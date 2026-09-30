"""
UBAG authorization console - a real gateway behind a configuration screen.

Nothing here decides anything. The console builds a Registry, a StateProvider and
a CompositionPolicy out of whatever the operator switched on, hands them to the
real ubag_core.GatewayEngine, and renders the verdicts it returns. Every ALLOW /
REVIEW / BLOCK on screen came out of the engine.

Authorization is per destination, not global. The operator names a site, then
grants the specific verbs that site may be used for. Granting `create` on one
domain grants nothing on another, and a verb left unticked is denied there even
if it is granted somewhere else.

Run:  python server.py           then open http://127.0.0.1:8765

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

# Resolve the sibling ubag-core checkout the same way the demos do.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (os.path.join(_HERE, "..", "ubag-core"),):
    if os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, os.path.abspath(_candidate))

from ubag_core import (ALLOW, BLOCK, REVIEW, CircuitBreaker, CompositionPolicy,
                       GatewayEngine, InMemoryAudit, PlanProposal, Registry,
                       SecurityContext, StateProvider, ToolRule)

for _p in (os.path.join(_HERE, "..", "ubag-mcp"),):
    if os.path.isdir(_p) and os.path.abspath(_p) not in sys.path:
        sys.path.insert(0, os.path.abspath(_p))
from ubag_mcp.shadow import render_shadow_report, summarize_shadow
from ubag_mcp.recommend import propose_policy, render_policy_proposal

import scenarios
# The web-layer tab needs `ubagweb.enforce` (UBAG Edge), which this release does
# not include. Without it the tab is hidden and its routes say so, and every
# other tab works unchanged.
try:
    import web_console
    WEB_LAYER_ERROR = ""
except ImportError as _exc:
    web_console = None
    WEB_LAYER_ERROR = f"web layer not installed ({_exc.name or _exc})"
import egress_console
import route_console

# ── Credential isolation ──────────────────────────────────────────────────────
# The gateway holds these; the agent never sees one. A proposal carries no
# credential field at all, and only an ALLOW that actually executes causes the
# held credential to be injected into the outbound call.
#
# DEMO NOTE: these are placeholder references, not secrets. What the console can
# honestly prove is the SHAPE: the proposal has no credential field, and the
# audit record carries a reference id rather than a value.
CREDENTIAL_FOR = {
    "payments.transfer": "treasury-key-1",
    "http.request": "egress-key-1",
    "booking.read": "egress-key-1",
    "booking.create": "egress-key-1",
    "booking.cancel": "egress-key-1",
    "repo.write": "vcs-token-1",
    "data.read": "warehouse-ro-1",
    "data.write": "warehouse-rw-1",
    "secrets.read": "vault-token-1",
    "code.execute": "runner-key-1",
}

SHADOW, ENFORCE = "SHADOW", "ENFORCE"

# A trusted context of the shape a real surface derives from authenticated
# transport. `credential_id` is a REFERENCE the gateway holds, never a secret.
CONSOLE_CONTEXT = SecurityContext(
    tenant_id="demo-tenant", principal_id="operator-1", agent_id="console-agent",
    account_id="demo-account", credential_id="gateway-held-1", integration_id="console")


def key_state(decision: str, mode: str) -> dict:
    """What happened to the credential for one decision.

    This is the axis the whole surface turns on. Shadow mode is not a separate
    code path: it is enforcement with the key withheld, so an ALLOW that would
    have executed still moves nothing.

    The console has no downstream system, so ENFORCE means "the gateway releases
    the key and the call goes out", not that this page called anything. The
    engine records `executed=False` throughout, which is the honest reading.
    """
    # Shadow never releases the gateway's credential, but it also never stands
    # in the agent's way: the agent still holds its own and its action still
    # happens. So "withheld" here means UBAG moved nothing, NOT that nothing
    # occurred. Conflating those two tells a prospect that a shadow pilot breaks
    # their agents, which is the opposite of what a shadow pilot is.
    if mode == SHADOW:
        return {"released": False,
                "label": ("withheld (would have released)" if decision == ALLOW
                          else "withheld (would have blocked this)"),
                "note": "shadow: the verdict is real and the agent was not "
                        "interrupted, so this action still happened"}
    if decision != ALLOW:
        return {"released": False, "label": "withheld",
                "note": "no credential resolved, so nothing could side-effect"}
    return {"released": True, "label": "released",
            "note": "credential injected into the outbound call, never into the proposal"}

PORT = int(os.environ.get("UBAG_CONSOLE_PORT", "8765"))

# ── Verb model ────────────────────────────────────────────────────────────────
# A verb is what the agent wants to DO. The operator grants verbs per site, so
# `create` on one domain never implies `create` on another.

NETWORK_VERBS = ["read", "create", "cancel", "execute"]
DATA_VERBS = ["read", "write"]

# verb -> the tool names that verb makes grantable at all
NETWORK_VERB_TOOLS = {
    "read":    ["http.request", "booking.read"],
    "create":  ["booking.create", "repo.write"],
    "cancel":  ["booking.cancel"],
    "execute": ["code.execute"],
}
DATA_VERB_TOOLS = {
    "read":  ["data.read", "secrets.read"],
    "write": ["data.write"],
}

# tool -> the verb it exercises, used to check the grant on the exact destination
TOOL_VERB = {}
for _v, _tools in NETWORK_VERB_TOOLS.items():
    for _t in _tools:
        TOOL_VERB[_t] = _v
for _v, _tools in DATA_VERB_TOOLS.items():
    for _t in _tools:
        TOOL_VERB.setdefault(_t, _v)
TOOL_VERB["payments.transfer"] = "send"

IRREVERSIBLE = {"payments.transfer", "booking.cancel", "repo.write", "code.execute"}


def _sites(raw) -> dict[str, set]:
    """[{name, verbs:[...]}] -> {name: {verbs}}. Tolerates bare strings."""
    out: dict[str, set] = {}
    for entry in raw or ():
        if isinstance(entry, str):
            name, verbs = entry, ()
        elif isinstance(entry, dict):
            name, verbs = entry.get("name") or entry.get("domain") or "", entry.get("verbs") or ()
        else:
            continue
        name = str(name).strip().lower()
        if name:
            out[name] = {str(v).strip().lower() for v in verbs if str(v).strip()}
    return out


class ConsoleState(StateProvider):
    """Per-destination verb grants.

    `is_destination_allowed` answers for the verb currently being proposed, which
    the console pins with `for_tool()` immediately before each decision. One
    engine, one state object, one step at a time, so there is no shared mutation.

    None means "not configured, I cannot answer" and the engine skips the check.
    An empty allow-list is a real, empty allow-list and denies everything.
    """

    def __init__(self, wallets, net_sites, data_sites, balance: Optional[float],
                 owner_lookup=None):
        self._wallets = None if wallets is None else {w.strip().lower() for w in wallets if w.strip()}
        self._net = net_sites          # None or {domain: {verbs}}
        self._data = data_sites        # None or {source: {verbs}}
        self._balance = balance
        self._verb = None
        # (tool_name, arguments) -> True (target owned by the acting agent),
        # False (owned by someone else), or None (cannot resolve). Injected by the
        # caller that has the live resource state (e.g. the gym), so ownership is
        # answered against ground truth rather than guessed here.
        self._owner_lookup = owner_lookup

    def for_tool(self, tool_name: str) -> "ConsoleState":
        self._verb = TOOL_VERB.get(tool_name)
        return self

    @property
    def _configured(self) -> bool:
        return any(a is not None for a in (self._wallets, self._net, self._data))

    def is_destination_allowed(self, destination: str) -> Optional[bool]:
        d = (destination or "").strip().lower()
        # Once anything is configured, a destination outside every namespace the
        # operator wrote is outside their policy. Answering None would let an
        # agent escape an allow-list just by prefixing its target differently.
        deny_or_unknown = False if self._configured else None

        if d.startswith("wallet:"):
            if self._wallets is None:
                return deny_or_unknown
            return d[len("wallet:"):] in self._wallets

        for prefix, sites in (("net:", self._net), ("data:", self._data)):
            if d.startswith(prefix):
                if sites is None:
                    return deny_or_unknown
                grants = sites.get(d[len(prefix):])
                if grants is None:
                    return False            # site was never named
                if self._verb is None:
                    return False            # unknown verb on a named site
                return self._verb in grants  # the verb must be granted HERE

        return deny_or_unknown

    def available_balance(self) -> Optional[float]:
        return self._balance

    def owns_resource(self, principal_id, tool_name, arguments) -> Optional[bool]:
        """Answer ownership from the live resource state, via the injected lookup.

        The lookup already knows who the acting agent is in the resource's own
        world (e.g. the gym's member), so it returns True/False/None directly and
        `principal_id` is not needed to compare. Returning None leaves the engine's
        ownership check inert, which is what every non-resource verb wants.
        """
        if self._owner_lookup is None:
            return None
        try:
            return self._owner_lookup(tool_name, dict(arguments or {}))
        except Exception:                                  # noqa: BLE001
            return None                                    # unresolved -> engine skips the ownership check


def _num(value, default=None) -> Optional[float]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if f == f and f not in (float("inf"), float("-inf")) else default


def granted_tools(config: dict) -> list[str]:
    """Tools this configuration makes grantable anywhere. The destination check
    then binds each one to the specific sites that granted its verb."""
    granted: list[str] = []
    if (config.get("money") or {}).get("enabled"):
        granted.append("payments.transfer")

    network = config.get("network") or {}
    if network.get("enabled"):
        verbs = set().union(*_sites(network.get("sites")).values()) if _sites(network.get("sites")) else set()
        for verb in verbs:
            granted.extend(NETWORK_VERB_TOOLS.get(verb, ()))

    data = config.get("data") or {}
    if data.get("enabled"):
        verbs = set().union(*_sites(data.get("sites")).values()) if _sites(data.get("sites")) else set()
        for verb in verbs:
            granted.extend(DATA_VERB_TOOLS.get(verb, ()))

    return sorted(dict.fromkeys(granted))


def build_engine(config: dict, owner_lookup=None) -> tuple[GatewayEngine, ConsoleState, CompositionPolicy]:
    """Translate the operator's grants into a real engine. Default-deny throughout.

    `owner_lookup(tool_name, arguments) -> Optional[bool]` lets the caller answer
    resource ownership from live state (the gym), so the engine can bind an
    irreversible verb to the resources the acting agent owns. Left None, ownership
    is simply not checked and verbs behave as before.
    """
    money = config.get("money") or {}
    network = config.get("network") or {}
    data = config.get("data") or {}

    registry = Registry(default_allow=False)   # unknown verb -> BLOCK, always
    for tool in granted_tools(config):
        rule = ToolRule(reversible=tool not in IRREVERSIBLE)
        if tool == "payments.transfer":
            rule.value_arg = "amount"
            rule.block_value = _num(money.get("max_per_action"))
            rule.review_value = _num(money.get("review_above"))
        registry.register(tool, rule)

    state = ConsoleState(
        wallets=money.get("destinations") if money.get("enabled") else None,
        net_sites=_sites(network.get("sites")) if network.get("enabled") else None,
        data_sites=_sites(data.get("sites")) if data.get("enabled") else None,
        balance=_num(money.get("balance"), 25_000.0) if money.get("enabled") else None,
        owner_lookup=owner_lookup,
    )

    approved = frozenset(
        f"wallet:{w.strip().lower()}" for w in (money.get("destinations") or []) if w.strip()
    )
    composition = CompositionPolicy(
        approved_destinations=approved,
        session_ceiling=_num(money.get("max_per_day"), 400.0) or 400.0,
        staged_moves=int(_num(money.get("staged_moves"), 3) or 3),
    )

    engine = GatewayEngine(
        registry,
        breaker=CircuitBreaker(),           # fresh per request: no cross-session bleed
        audit=InMemoryAudit(),
        state=state,
        composition_policy=composition,
    )
    return engine, state, composition


def naive_verdict(step: dict, config: dict) -> dict:
    """What a conventional per-order control sees.

    A push-notification-per-order prompt knows the size of the order in front of
    it and nothing else. It cannot see the sequence, the destination history, or
    what the other nine orders add up to. Modelled here honestly: amount vs limit.
    """
    money = config.get("money") or {}
    limit = _num(money.get("max_per_action"))
    amount = _num((step.get("arguments") or {}).get("amount"))
    if amount is None:
        return {"decision": "APPROVED", "reason": "no monetary value to check"}
    if limit is not None and amount > limit:
        return {"decision": "DECLINED", "reason": f"{amount:,.0f} over the {limit:,.0f} limit"}
    return {"decision": "APPROVED", "reason": f"{amount:,.0f} is within the per-order limit"}


def decide_step(engine, state, identity, step) -> dict:
    """One proposal, with the state port pinned to the verb being proposed."""
    state.for_tool(step["tool"])
    d = engine.decide(identity, step["tool"], dict(step.get("arguments") or {}),
                      reason=step.get("reason", ""))
    return {"decision": d.decision, "reason": d.reason, "score": round(d.score, 3),
            "checks": [f.get("check") for f in d.flags if f.get("check")]}


def audit_records(sink) -> list:
    """`InMemoryAudit.records` is a list; `JsonlAudit.records()` is a method."""
    got = getattr(sink, "records", [])
    return list(got() if callable(got) else got)


def injection_view(step: dict, decision: str, mode: str, record) -> dict:
    """The three boxes that make safe injection checkable rather than claimed.

    What the agent proposed, what the gateway actually sent, and what the audit
    kept. The credential appears in exactly one of them, and it is never the one
    that gets stored.
    """
    tool = step["tool"]
    credential = CREDENTIAL_FOR.get(tool, "held-credential")
    released = decision == ALLOW and mode == ENFORCE
    return {
        "tool": tool,
        "credential_ref": credential,
        "proposed": step.get("arguments") or {},          # no credential field exists
        "sent": ({**(step.get("arguments") or {}),
                  "Authorization": "Bearer " + "•" * 12}
                 if released else None),
        "audit": ({"tool": record.tool, "decision": record.decision,
                   "executed": record.executed,
                   "credential_id": record.credential_id or credential,
                   "signature": (record.signature or "")[:16]}
                  if record is not None else None),
    }


def evaluate(config: dict, scenario_id: str) -> dict:
    scenario = scenarios.by_id(scenario_id)
    if scenario is None:
        raise KeyError(scenario_id)

    mode = ENFORCE if str(config.get("mode", "")).upper() == ENFORCE else SHADOW
    engine, state, composition = build_engine(config)
    identity = CONSOLE_CONTEXT

    per_step, injection = [], None
    for step in scenario["steps"]:
        verdict = decide_step(engine, state, identity, step)
        records = audit_records(engine.audit)
        per_step.append({
            "tool": step["tool"],
            "verb": TOOL_VERB.get(step["tool"], ""),
            "arguments": step.get("arguments") or {},
            "reason": step.get("reason", ""),
            "ubag": verdict,
            "key": key_state(verdict["decision"], mode),
            "naive": naive_verdict(step, config),
        })
        # Expand the first ALLOW: that is the only step where a key would move.
        if injection is None and verdict["decision"] == ALLOW:
            injection = injection_view(step, verdict["decision"], mode,
                                       records[-1] if records else None)

    plan_engine, plan_state, _c2 = build_engine(config)
    # The plan gate runs the full engine per step internally; pin the verb of the
    # dominant step so destination grants resolve the same way they do above.
    plan_state.for_tool(scenario["steps"][0]["tool"] if scenario["steps"] else "")
    plan = plan_engine.decide_plan(
        identity,
        [PlanProposal(tool=s["tool"], arguments=dict(s.get("arguments") or {}),
                      reason=s.get("reason", "")) for s in scenario["steps"]],
        plan_id=scenario_id,
    )

    blocked = sum(1 for s in per_step if s["ubag"]["decision"] == BLOCK)
    review = sum(1 for s in per_step if s["ubag"]["decision"] == REVIEW)
    allowed = sum(1 for s in per_step if s["ubag"]["decision"] == ALLOW)
    naive_through = sum(1 for s in per_step if s["naive"]["decision"] == "APPROVED")

    keys_released = sum(1 for s in per_step if s["key"]["released"])
    return {
        "scenario": {k: scenario[k] for k in
                     ("id", "kind", "title", "dated", "source", "brief", "the_point")},
        "steps": per_step,
        "totals": {"allowed": allowed, "review": review, "blocked": blocked,
                   "total": len(per_step), "naive_through": naive_through,
                   "keys_released": keys_released},
        "operating_mode": mode,
        "injection": injection,
        "plan": {"decision": plan.decision, "mode": plan.mode, "reasons": plan.reasons},
        "granted": granted_tools(config),
        "verbs": {"network": NETWORK_VERBS, "data": DATA_VERBS},
        "composition": {"session_ceiling": composition.session_ceiling,
                        "staged_moves": composition.staged_moves,
                        "approved_destinations": sorted(composition.approved_destinations)},
    }


def live_agent():
    """The live demo module, imported lazily.

    `demo/live/agent.py` imports THIS module for its engine construction, so
    importing it here at module level would be a cycle. Deferring it also keeps
    the console usable when the demo package is absent.
    """
    for candidate in (os.path.join(_HERE, "..", "live"),):
        if os.path.isdir(candidate) and os.path.abspath(candidate) not in sys.path:
            sys.path.insert(0, os.path.abspath(candidate))
    import agent                                        # noqa: PLC0415
    return agent


def shadow_report(config: dict) -> dict:
    """Run every scenario through ONE engine and render the real pilot report.

    This is the trial deliverable, not a mock: `render_shadow_report` is the same
    function `python -m ubag_mcp.shadow` writes for a customer, fed by the audit
    sink the engine wrote during these runs.
    """
    engine, state, _c = build_engine(config)
    identity = CONSOLE_CONTEXT
    for scenario in scenarios.SCENARIOS:
        for step in scenario["steps"]:
            decide_step(engine, state, identity, step)

    records = audit_records(engine.audit)
    return {
        "summary": summarize_shadow(records),
        "markdown": render_shadow_report(records,
                                         title="UBAG Shadow Pilot Report (console)"),
        "records": len(records),
    }


def policy_proposal(config: dict) -> dict:
    """Draft the authorization checklist the shadow window implies.

    Same engine, same audit, same scenarios as `shadow_report`. The difference is
    the question: shadow says what would have happened, this says what the
    operator should consider switching on, and refuses to say it for anything
    that was refused on an ownership, injection or breaker ground.

    `propose_policy` is the same function `python -m ubag_mcp.recommend` runs
    against a customer's audit log. Not a mock.
    """
    engine, state, _c = build_engine(config)
    for scenario in scenarios.SCENARIOS:
        for step in scenario["steps"]:
            decide_step(engine, state, CONSOLE_CONTEXT, step)

    records = audit_records(engine.audit)
    known = configured_destinations(config)
    draft = propose_policy(records, granted=granted_tools(config),
                           known_destinations=known)
    for item in draft["proposals"] + draft["irreversible_proposals"]:
        item["switch"] = switch_for(item)
    return {
        "draft": draft,
        "markdown": render_policy_proposal(records, granted=granted_tools(config),
                                           known_destinations=known,
                                           title="UBAG Proposed Policy (console)"),
        "records": len(records),
        "known_destinations": sorted(known),
    }


def configured_destinations(config: dict) -> set:
    """Every destination the operator has already named, namespaced.

    A site that appears here has been accepted by a person, so a verb missing on
    it is a gap in their configuration. A site that does not appear here is
    somewhere the agent went on its own, which is a different question entirely.
    """
    money = config.get("money") or {}
    out = {f"wallet:{str(w).strip().lower()}"
           for w in (money.get("destinations") or ()) if str(w).strip()}
    for section, prefix in (("network", "net:"), ("data", "data:")):
        block = config.get(section) or {}
        if block.get("enabled"):
            out |= {prefix + name for name in _sites(block.get("sites"))}
    return out


def switch_for(item: dict) -> Optional[dict]:
    """Map one proposal onto the console switch a tick would flip.

    Returns None when the proposal cannot be expressed as a scoped switch, which
    is the honest answer for an unscoped grant: there is no site to tick it on,
    so the UI must not offer a checkbox that quietly means "everywhere".
    """
    destination, verb = item.get("destination") or "", TOOL_VERB.get(item.get("tool", ""))
    if not destination or not verb:
        return None
    for prefix, section in (("net:", "network"), ("data:", "data"),
                            ("wallet:", "money")):
        if destination.startswith(prefix):
            return {"section": section, "site": destination[len(prefix):], "verb": verb}
    return None


def apply_proposals(config: dict, grants) -> dict:
    """Return a NEW config with the accepted grants added. Never mutates.

    Applied server-side on an explicit request carrying an explicit list, so
    "the operator ticked it" is a real event with a real payload rather than a
    front-end state change. Anything not named here stays exactly as it was.
    """
    accepted = {str(g) for g in (grants or ()) if str(g).strip()}
    if not accepted:
        return json.loads(json.dumps(config))

    engine_draft = policy_proposal(config)["draft"]
    by_grant = {i["grant"]: i for i in
                engine_draft["proposals"] + engine_draft["irreversible_proposals"]}

    updated = json.loads(json.dumps(config))          # deep copy, no shared state
    applied, rejected = [], []
    for grant in sorted(accepted):
        item = by_grant.get(grant)
        switch = switch_for(item) if item else None
        if switch is None:
            # Not a proposal this draft made. A grant the operator never saw
            # proposed must not be applied just because it arrived in the list.
            rejected.append(grant)
            continue
        section = updated.setdefault(switch["section"], {})
        section["enabled"] = True
        sites = section.setdefault("sites", [])
        for entry in sites:
            if isinstance(entry, dict) and str(entry.get("name", "")).lower() == switch["site"]:
                verbs = entry.setdefault("verbs", [])
                if switch["verb"] not in verbs:
                    verbs.append(switch["verb"])
                break
        else:
            sites.append({"name": switch["site"], "verbs": [switch["verb"]]})
        applied.append(grant)

    return {"config": updated, "applied": applied, "rejected": rejected,
            "granted": granted_tools(updated)}


# ── Routing ───────────────────────────────────────────────────────────────────
# One dispatch, two transports. The stdlib server below is for local development
# with no dependencies; `asgi.py` is the deployed surface. Both call these, so a
# route can never exist on one and not the other.

GET_ROUTES = ("/api/scenarios", "/api/web/scenarios", "/api/live/describe",
              "/api/web/live/describe", "/api/egress/describe", "/api/route/describe")
POST_ROUTES = ("/api/evaluate", "/api/web/evaluate", "/api/shadow-report",
               "/api/policy-proposal", "/api/policy-apply",
               "/api/live/step", "/api/live/reset", "/api/web/live",
               "/api/web/live/step", "/api/web/live/reset", "/api/web/live/arm",
               "/api/egress/step", "/api/route", "/api/route/run")

# Routes that reach a language model, and so cost money per call. Held apart
# from the rest because the rate limits that matter are the ones on these.
MODEL_ROUTES = ("/api/live/step", "/api/web/live/step", "/api/egress/step",
                "/api/route/run")


def dispatch_get(path: str) -> dict:
    """Handle a read-only route. Raises KeyError for anything unrouted."""
    if web_console is None and path.startswith("/api/web/"):
        return {"unavailable": WEB_LAYER_ERROR, "error": WEB_LAYER_ERROR}
    if path == "/api/scenarios":
        return {"scenarios": scenarios.public_catalog(),
                "verbs": {"network": NETWORK_VERBS, "data": DATA_VERBS}}
    if path == "/api/web/scenarios":
        return web_console.catalog()
    if path == "/api/live/describe":
        try:
            return live_agent().describe()
        except Exception as exc:                              # noqa: BLE001
            return {"error": f"live demo unavailable: {exc}"}
    if path == "/api/web/live/describe":
        try:
            return web_console.live_describe()
        except Exception as exc:                              # noqa: BLE001
            return {"error": f"live demo unavailable: {exc}"}
    if path == "/api/egress/describe":
        try:
            return egress_console.describe()
        except Exception as exc:                              # noqa: BLE001
            return {"error": f"egress demo unavailable: {exc}"}
    if path == "/api/route/describe":
        try:
            return route_console.describe()
        except Exception as exc:                              # noqa: BLE001
            return {"error": f"routing demo unavailable: {exc}"}
    raise KeyError(path)


def dispatch_post(path: str, payload: dict) -> dict:
    """Handle one action route. Raises KeyError for anything unrouted."""
    config = payload.get("config") or {}
    session = str(payload.get("session") or "anonymous")[:64]
    if web_console is None and path.startswith("/api/web/"):
        return {"unavailable": WEB_LAYER_ERROR, "error": WEB_LAYER_ERROR}

    if path == "/api/live/step":
        return live_agent().run_step(
            session=session, config=config,
            provider_id=str(payload.get("provider") or ""),
            task=str(payload.get("task") or "")[:400],
            step_index=max(0, min(int(payload.get("step") or 0), 32)))
    if path == "/api/live/reset":
        return live_agent().reset(session)
    if path == "/api/shadow-report":
        return shadow_report(config)
    if path == "/api/policy-proposal":
        return policy_proposal(config)
    if path == "/api/policy-apply":
        return apply_proposals(config, payload.get("grants") or [])
    if path in ("/api/evaluate", "/api/web/evaluate"):
        runner = evaluate if path == "/api/evaluate" else web_console.evaluate
        return runner(config, str(payload.get("scenario") or ""))
    # /api/web/live/step now DOES take the tier config, and pushes it to the
    # site before acting. It previously did not, on the reasoning that a console
    # should not reconfigure a service it does not control. That was correct
    # about the boundary and wrong about the product: the site accepts a policy
    # from its operator, and the operator is the person at this screen. Without
    # it, switching a verb off changed nothing and the gate looked broken.
    if path == "/api/web/live":
        mode = str(payload.get("mode") or "both")
        return web_console.live_run(mode if mode in ("both", "undefended", "gated") else "both")
    if path == "/api/web/live/step":
        return web_console.live_step(
            provider_id=str(payload.get("provider") or ""),
            task=str(payload.get("task") or "")[:400],
            step_index=max(0, min(int(payload.get("step") or 0), 32)),
            config=config or None)
    if path == "/api/web/live/reset":
        return web_console.live_reset()
    if path == "/api/web/live/arm":
        return web_console.live_arm(bool(payload.get("enabled")))
    if path == "/api/egress/step":
        return egress_console.step(
            str(payload.get("task") or payload.get("message") or "")[:400],
            payload.get("allowed"),
            key_host=str(payload.get("key_host") or "")[:253] or None)
    if path == "/api/route":
        return route_console.route(payload)
    if path == "/api/route/run":
        try:
            return route_console.run(payload)
        except Exception as exc:                              # noqa: BLE001
            print(f"route run unavailable: {type(exc).__name__}: {exc}",
                  file=sys.stderr, flush=True)
            return {"error": "the brokered run is unavailable right now"}
    raise KeyError(path)


def console_html() -> bytes:
    with open(os.path.join(_HERE, "console.html"), "rb") as handle:
        return handle.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "ubag-console"

    def _send(self, code: int, payload: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._send(200, console_html(), "text/html; charset=utf-8")
        try:
            result = dispatch_get(path)
        except KeyError:
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        self._send(200, json.dumps(result).encode(), "application/json")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in POST_ROUTES:
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 256_000:
                raise ValueError("bad content length")
            result = dispatch_post(path, json.loads(self.rfile.read(length) or b"{}"))
        except KeyError as exc:
            return self._send(404, json.dumps({"error": f"unknown scenario {exc}"}).encode(),
                              "application/json")
        except Exception as exc:                                  # noqa: BLE001
            return self._send(400, json.dumps({"error": str(exc)}).encode(), "application/json")
        self._send(200, json.dumps(result).encode(), "application/json")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"UBAG console  ->  http://127.0.0.1:{PORT}")
    print("Verdicts are produced by ubag_core.GatewayEngine. Nothing is hardcoded.\n")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
