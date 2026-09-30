"""UBAG enforcement in front of the deliberately broken cancel endpoint.

The gym reproduces the Melbourne incident of 10 August 2026: a booking API whose
cancel route performs no ownership check, so any caller who can reach it can
cancel anyone's booking. `gym.py` says the bug is on purpose and must not be
fixed, and this module does not fix it. The handler stays exactly as broken as
the real one was. What changes is that an authorization decision happens before
the handler is reached, which is the claim UBAG actually makes: not that your
code is correct, but that a wrong action does not execute.

WHY THE HANDLER IS LEFT BROKEN

Fixing `cancel_booking` would demonstrate nothing. Every reader already believes
an ownership check works; the question is what protects the endpoints where
somebody forgot one, which is all of them until an incident proves otherwise.
Leaving it broken and refusing the request upstream is the only arrangement that
shows the gateway carrying the load on its own.

THE TOGGLE IS PART OF THE EXHIBIT, NOT A CONVENIENCE

`gym.py` calls the bug "the thing being demonstrated". A gate that is always on
retires the exhibit: the site becomes a working booking system and the incident
becomes a story rather than something a visitor watches happen. So enforcement
is per session and defaults to OFF. The demo is: run the attack, watch it
succeed, turn UBAG on, run the identical attack, watch it refused.

DEGRADES TO TODAY'S BEHAVIOUR

`ubag_core`, `ubag_mcp` and `ubagweb.enforce` are the commercial engine and are
not vendored into this public image by default. When they are absent this module
imports cleanly, reports itself unavailable, and the gym serves exactly what it
serves now. That ordering matters: a missing private dependency must never be
able to take the public exhibit down, and the toggle cannot be switched on into
a half-built gate.
"""
from __future__ import annotations

import os
import threading
from contextvars import ContextVar
from typing import Callable, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from gym import ACTING_MEMBER, REGISTRY

# ---------------------------------------------------------------------------
# Optional private engine
# ---------------------------------------------------------------------------
try:
    from ubag import generate_issuer_keypair
    from ubag._credential import issue_credential, validate_credential
    from ubag._keys import issuer_public_from_private
    from ubag.provenance import agent_ref as derive_agent_ref
    from ubag.provenance import credential_hash
    from ubag_mcp.provenance import (CredentialRegistration,
                                     IdentityRegistration, TenantBinding)
    from ubagweb.enforce import CANCEL, CREATE, READ, EnforceGate, SitePolicy, tier
    from ubagweb.enforce.asgi import ActionGate, ActionRoute
    from ubagweb.enforce.policy import VERBS
    GATE_AVAILABLE = True
    GATE_IMPORT_ERROR = ""
except Exception as exc:                                   # noqa: BLE001
    GATE_AVAILABLE = False
    GATE_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
    ActionGate = object                                    # type: ignore[assignment]

TENANT = "southbank-fitness"
CREDENTIAL_HEADER = "X-UBAG-Credential"
ORIGIN = os.getenv("GYM_ORIGIN", "https://dixitalgorizmi.online")

# One issuer value, used to mint, to validate, and to name the trusted tier.
#
# It is spelled out here because getting it wrong is silent. `validate_credential`
# checks the `iss` claim against the protocol default, so a credential minted
# under any other name simply fails to validate and the caller lands in the
# anonymous tier. The gate then refuses, correctly and for the wrong reason, and
# the demo looks like "UBAG blocks everything" rather than "that credential was
# never valid". Three constants that must agree, so there is one.
ISSUER = os.getenv("UBAG_DEMO_ISSUER", "https://ubagprotocol.com")

# The session whose gym an ownership question is being asked about.
#
# EnforceGate takes one `owner_lookup(resource_ref)` for its lifetime, but this
# service holds a separate Gym per session, so "who owns booking 4471" has no
# answer without knowing which gym is being asked. A ContextVar carries it from
# the middleware to the lookup across the await boundary, which is the only
# mechanism here that is correct under concurrency: a module-level global would
# be read by whichever request happened to be resumed next.
_SESSION: ContextVar[str] = ContextVar("gym_session", default="public")

_ENABLED: dict[str, bool] = {}
_LOCK = threading.Lock()

# What this site enforces when nobody has configured it.
#
# The console's tier editor can replace this per session, which is the whole
# reason it exists: a panel headed "before agents arrive at your site" that does
# not change what the site does is worse than no panel, because it looks like
# the gate ignored the policy. This is the starting position, not a fixed one.
DEFAULT_POLICY: dict = {
    "require_ownership": True,
    "anonymous": {"verbs": ["read"]},
    "tiers": [{"name": "member-agent", "verbs": ["read", "create", "cancel"]}],
}

# Policy and gate per session, so one visitor editing tiers cannot silently
# rewrite what another visitor is watching. The public session is shared by
# design; these are keyed the same way everything else here is.
_POLICIES: dict = {}
_GATES: dict = {}

# The gate authorizing the request currently being handled. EnforceGate is built
# once per policy, but ActionGate holds one for its lifetime, so this carries the
# session's gate from the middleware into the base class without a global.
_ACTIVE = ContextVar("gym_gate_active", default=None)

router = APIRouter()


def enforcement_enabled(session: str) -> bool:
    """Off unless a visitor turned it on for their own session."""
    if not GATE_AVAILABLE:
        return False
    with _LOCK:
        return _ENABLED.get(session, False)


def _set_enabled(session: str, value: bool) -> bool:
    with _LOCK:
        _ENABLED[session] = bool(value)
        return _ENABLED[session]


def policy_for(session: str) -> dict:
    with _LOCK:
        return dict(_POLICIES.get(session) or DEFAULT_POLICY)


def set_policy(session: str, spec: dict) -> dict:
    """Replace what this site enforces for one session.

    Rebuilding the gate here rather than lazily means a spec the engine refuses
    fails on the request that set it, with the operator watching, instead of on
    the next agent action where it would read as the gate misbehaving.
    """
    gate = _gate_from(spec)
    with _LOCK:
        _POLICIES[session] = spec
        _GATES[session] = gate
    return policy_for(session)


def gate_for(session: str):
    with _LOCK:
        gate = _GATES.get(session)
        if gate is None:
            gate = _GATES[session] = _gate_from(_POLICIES.get(session) or DEFAULT_POLICY)
        return gate


def disarm(session: str) -> None:
    """Put this session back to undefended, which is what reset has to mean.

    The default gym is shared by every visitor, deliberately, so that "the agent
    acted on dixitalgorizmi.online" refers to the thing a person sees there. The
    toggle follows the same session, which means one visitor arming UBAG arms it
    for the next arrival too.

    Resetting the bookings without resetting this leaves the worst possible
    state: a fresh gym that quietly refuses the attack, with nothing on screen
    explaining why, so the exhibit reads as broken rather than as defended.
    Reset returns the whole exhibit to the incident, and the incident is the
    endpoint with nothing in front of it.
    """
    with _LOCK:
        _ENABLED.pop(session, None)
        # Reset means back to the incident, and that includes the policy. A
        # visitor who narrowed the tiers and walked away must not leave the next
        # arrival wondering why the site behaves unlike the panel in front of
        # them.
        _POLICIES.pop(session, None)
        _GATES.pop(session, None)


# ---------------------------------------------------------------------------
# Identity, minted here because the exhibit has to be self-contained
# ---------------------------------------------------------------------------
_ISSUER_PRIVATE = ""
_ISSUER_PUBLIC = ""
_AGENT_REF = ""
_IDENTITIES: dict = {}
_CREDENTIALS: dict = {}


class _SiteRegistry:
    """What this site has recorded about agents it issued credentials to."""

    def resolve_identity(self, tenant_id, ref):
        return _IDENTITIES.get((tenant_id, ref))

    def resolve_credential(self, tenant_id, ref, credential_ref):
        return _CREDENTIALS.get((tenant_id, ref, credential_ref))


def _owner_lookup(resource_ref: str) -> Optional[str]:
    """Who holds this booking, in the gym this request belongs to.

    Returning None means "this site cannot answer", which is different from
    "nobody owns it". The gate's ownership floor refuses an irreversible verb it
    cannot resolve an owner for, so a cancel aimed at a booking that does not
    exist is refused rather than passed through to produce a 404. That is the
    conservative reading and the right one: the gate is not a router.
    """
    if not resource_ref.startswith("booking:"):
        return None
    booking_id = resource_ref.split(":", 1)[1]
    gym = REGISTRY.get(_SESSION.get())
    booking = gym.bookings.get(booking_id)
    return booking.member if booking else None


def _identify(request) -> dict:
    """Only what this site verified itself.

    Never derived from unverified request content. An unsigned or absent
    credential is unattested, which lands the caller in the anonymous tier, and
    the anonymous tier holds `read` and nothing else.
    """
    token = request.headers.get(CREDENTIAL_HEADER, "")
    claims = validate_credential(token, _ISSUER_PUBLIC, issuer=ISSUER) if token else None
    if not claims:
        return {"attested": False}
    return {"agent_ref": _AGENT_REF,
            "credential_ref": credential_hash(token),
            "issuer": str(claims.get("iss") or ""),
            "agent_class": str(claims.get("agent_class") or ""),
            "attested": True}


def _build_gate():
    """The policy this site publishes, and the gate that enforces it."""
    global _ISSUER_PRIVATE, _ISSUER_PUBLIC, _AGENT_REF

    _ISSUER_PRIVATE, _ = generate_issuer_keypair()
    _ISSUER_PUBLIC = issuer_public_from_private(_ISSUER_PRIVATE)

    # One agent identity for the exhibit, registered as acting for Andrew. A
    # real deployment resolves this from its own records after a handshake; the
    # shape is identical, only the enrolment is short-circuited.
    from ubag import AgentCredential
    agent = AgentCredential.generate(owner="andrew@example.com")
    _AGENT_REF = derive_agent_ref(agent.public_key)
    _IDENTITIES[(TENANT, _AGENT_REF)] = IdentityRegistration(
        principal_id=ACTING_MEMBER, account_id="acct-southbank-1")

    return _gate_from(DEFAULT_POLICY)


def _policy_from(spec: dict) -> "SitePolicy":
    """Build the site's policy from a spec an operator posted.

    Deliberately permissive about shape and strict about vocabulary: an unknown
    verb is dropped rather than raising, because this arrives over HTTP from a
    console and a typo must not take the exhibit down. What it cannot do is
    invent a verb the engine does not enforce.
    """
    spec = spec or {}
    tiers = []
    for raw in spec.get("tiers") or ():
        name = str((raw or {}).get("name") or "").strip()
        if not name:
            continue
        verbs = [v for v in (str(x).strip().lower() for x in (raw.get("verbs") or ()))
                 if v in VERBS]
        issuers = [str(i).strip() for i in (raw.get("issuers") or ()) if str(i).strip()]
        tiers.append(tier(name, *verbs,
                          issuers=issuers or [ISSUER],
                          require_ownership=bool(spec.get("require_ownership", True))))
    anon_verbs = [v for v in (str(x).strip().lower()
                              for x in ((spec.get("anonymous") or {}).get("verbs") or ()))
                  if v in VERBS]
    anonymous = tier("anonymous", *anon_verbs, require_ownership=False)
    return SitePolicy(tenant=TENANT, tiers=tiers, anonymous=anonymous)


def _gate_from(spec: dict):
    """One gate for one policy spec.

    `cancel` is in IRREVERSIBLE_VERBS, so require_ownership binds it to the
    principal. Granting cancel is NOT granting cancel-anything: it is the
    difference between "may cancel" and "may cancel their own", and it is the
    exact distinction the real endpoint failed to make.
    """
    return EnforceGate(
        {ORIGIN: TenantBinding(tenant_id=TENANT, public_origin=ORIGIN)},
        _policy_from(spec),
        ["booking"], registry=_SiteRegistry(),
        owner_lookup=_owner_lookup)


# ---------------------------------------------------------------------------
# The routes this site declares as actions
# ---------------------------------------------------------------------------
def _action_routes():
    """Reads are deliberately absent.

    ActionGate claims only what is listed, so GET /api/bookings and
    GET /api/classes pass straight through untouched. A gate that intercepts
    reads is a proxy, and a proxy is a thing site owners rip out.
    """
    return [
        ActionRoute("DELETE", r"/api/bookings/(?P<ref>[^/]+)", "booking", "cancel"),
        ActionRoute("POST", r"/api/bookings", "booking", "create"),
    ]


def install(app, session_of: Callable[[Request, Optional[str]], str],
            always_headers: Optional[dict] = None) -> bool:
    """Mount the gate. Returns whether enforcement is available at all.

    `session_of` is injected rather than imported so this module does not import
    the service that imports it.

    `always_headers` exists because of middleware ordering. Starlette runs the
    most recently added middleware outermost, and this is installed after the
    disclosure middleware, so a response the gate generates itself returns
    without ever passing through it. The gym's rule is that every single
    response says what this site is, including to a scanner, and a 403 from the
    gate is exactly the kind of response a scanner collects. So the gate stamps
    them itself rather than quietly becoming the one exception.
    """
    if not GATE_AVAILABLE:
        return False

    gate = _build_gate()
    routes = _action_routes()
    stamp = dict(always_headers or {})

    class DemoActionGate(ActionGate):
        """ActionGate plus the four things this exhibit needs.

        The session has to be published before authorization runs, because the
        ownership lookup needs it. The gate itself is per session, because the
        console can rewrite this site's policy and the request has to be judged
        by the policy in force for that visitor rather than the one built at
        startup. When a visitor has not switched enforcement on, the gate must
        not merely allow: it must not run, so the broken handler is reached by
        exactly the path it is reached by today. And every response it produces
        carries the disclosure.
        """

        @property
        def gate(self):
            # ActionGate reads self.gate once per request. Resolving it from a
            # ContextVar keeps a per-session gate correct under concurrency,
            # where mutating an attribute on the shared middleware instance
            # would hand one visitor another visitor's policy.
            return _ACTIVE.get() or self._startup_gate

        @gate.setter
        def gate(self, value):
            self._startup_gate = value

        async def dispatch(self, request, call_next):
            session = session_of(request, request.headers.get("x-demo-session"))
            token = _SESSION.set(session)
            active = _ACTIVE.set(gate_for(session))
            try:
                if not enforcement_enabled(session):
                    return await call_next(request)
                response = await super().dispatch(request, call_next)
                for key, value in stamp.items():
                    response.headers.setdefault(key, value)
                return response
            finally:
                _ACTIVE.reset(active)
                _SESSION.reset(token)

    app.add_middleware(DemoActionGate, gate=gate, origin=ORIGIN,
                       identify=_identify, routes=routes)
    return True


# ---------------------------------------------------------------------------
# The surface the console and a curious visitor drive
# ---------------------------------------------------------------------------
@router.get("/api/ubag")
def ubag_state(request: Request):
    """What is configured and whether it is switched on for this visitor."""
    session = (request.headers.get("x-demo-session")
               or request.query_params.get("session") or "public")[:64]
    # Read back from the policy actually in force for this session, never from a
    # literal written here. A published policy that is a hand-maintained copy of
    # the enforced one is a lie waiting for someone to edit one and not the
    # other, and this endpoint is what the console draws its panel from.
    spec = policy_for(session) if GATE_AVAILABLE else {}
    tiers = [{"name": "anonymous", "always_on": True,
              "verbs": list((spec.get("anonymous") or {}).get("verbs") or []),
              "description": "Unattested automation and any issuer you do not trust."}]
    for raw in spec.get("tiers") or ():
        tiers.append({"name": raw.get("name"), "always_on": False,
                      "verbs": list(raw.get("verbs") or []),
                      "require_ownership": bool(spec.get("require_ownership", True)),
                      "description": "An agent holding a credential from an issuer "
                                     "this site trusts."})
    body = {
        "available": GATE_AVAILABLE,
        "enabled": enforcement_enabled(session),
        "tenant": TENANT,
        "origin": ORIGIN,
        "policy": spec,
        "tiers": tiers,
        "irreversible_verbs": ["cancel", "execute"],
        "actions": [{"method": r.method, "pattern": r.pattern,
                     "resource": r.resource, "verb": r.verb}
                    for r in (_action_routes() if GATE_AVAILABLE else [])],
    }
    if not GATE_AVAILABLE:
        body["unavailable_reason"] = GATE_IMPORT_ERROR
    return body


@router.post("/api/ubag/policy")
async def set_ubag_policy(request: Request):
    """Replace what this site enforces, for this visitor's session.

    This is what makes the console's tier panel real. Before it existed the
    panel configured a gate inside the console while this site enforced its own
    hardcoded policy, so switching a verb off changed nothing here and the gate
    looked like it had ignored the operator.
    """
    if not GATE_AVAILABLE:
        return JSONResponse({"ok": False, "reason": GATE_IMPORT_ERROR}, status_code=503)
    try:
        spec = await request.json()
    except Exception:                                      # noqa: BLE001
        spec = {}
    session = (request.headers.get("x-demo-session")
               or request.query_params.get("session") or "public")[:64]
    try:
        applied = set_policy(session, spec if isinstance(spec, dict) else {})
    except Exception as exc:                               # noqa: BLE001
        return JSONResponse({"ok": False, "reason": f"{type(exc).__name__}: {exc}"},
                            status_code=400)
    return {"ok": True, "policy": applied}


@router.post("/api/ubag")
async def set_ubag(request: Request):
    """Turn enforcement on or off for this visitor's gym."""
    if not GATE_AVAILABLE:
        return JSONResponse(
            {"ok": False, "available": False, "reason": GATE_IMPORT_ERROR},
            status_code=503)
    try:
        body = await request.json()
    except Exception:                                      # noqa: BLE001
        body = {}
    session = (request.headers.get("x-demo-session")
               or request.query_params.get("session") or "public")[:64]
    return {"ok": True, "enabled": _set_enabled(session, bool(body.get("enabled")))}


@router.post("/api/ubag/credential")
def mint_credential():
    """A credential for the exhibit's agent, standing in for the handshake.

    A real site issues this only after an agent proves possession of its key
    through the challenge flow. Short-circuiting enrolment is the one thing
    simulated here, and it is simulated in the direction that makes the demo
    harder rather than easier: the agent arrives already trusted, so a refusal
    can never be mistaken for "it just was not logged in".
    """
    if not GATE_AVAILABLE:
        return JSONResponse({"ok": False, "reason": GATE_IMPORT_ERROR},
                            status_code=503)
    token = issue_credential(
        subject=_AGENT_REF,
        issuer_private_pem=_ISSUER_PRIVATE,
        agent_class="authorized_agent",
        issuer=ISSUER,
        ttl=900)
    ref = credential_hash(token)
    _CREDENTIALS[(TENANT, _AGENT_REF, ref)] = CredentialRegistration(credential_id=ref)
    return {"ok": True, "header": CREDENTIAL_HEADER, "credential": token,
            "expires_in": 900}
