"""
Capability grants — cryptographic proof-of-entitlement (deterministic, no LLM).

Where the behavioral layer JUDGES a fuzzy action, this VERIFIES a pre-authorization.
For actions a backend can decide by hard business rules (a refund, a payout, a
withdrawal), the backend issues a short-lived Ed25519-signed grant authorizing ONE
specific action bound to specific argument constraints. The gateway holds only the
PUBLIC key: it cannot mint grants, only verify them.

A prompt-injected agent that tries to move $10,000 has no valid grant for that
action, so the gateway drops it on a MATHEMATICAL failure, not a judgment call.

Fail CLOSED on every path. Requires the `cryptography` package (Ed25519).
Generalized from the deployment layer: the public key is passed in directly, so
this module has no environment or transport coupling.
"""
from __future__ import annotations

import base64
import json
import math
import time
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class GrantResult:
    ok: bool
    reason: str
    jti: str = ""
    claims: dict = field(default_factory=dict)


class ReplayStore:
    """Atomic single-use grant replay port for a shared production store."""
    def seen_or_record(self, jti: str, exp: float, now: float) -> bool:  # pragma: no cover
        raise NotImplementedError


class InMemoryReplayStore(ReplayStore):
    def __init__(self):
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def seen_or_record(self, jti: str, exp: float, now: float) -> bool:
        with self._lock:
            if len(self._seen) > 4096:
                for key, expiry in list(self._seen.items()):
                    if expiry < now:
                        self._seen.pop(key, None)
            if jti in self._seen and self._seen[jti] >= now:
                return True
            self._seen[jti] = exp
            return False


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_NOT_ACTION_PARAMETERS = frozenset({"reason", "_cost"})


def _check_bind(bind: dict, arguments: dict) -> Optional[str]:
    if not isinstance(bind, dict):
        return "grant has no binding"
    args = arguments or {}
    for key, rule in bind.items():
        actual = args.get(key)
        if actual is None:
            return f"bound arg '{key}' missing from action"
        if isinstance(rule, dict):
            if "eq" in rule and str(actual) != str(rule["eq"]):
                return f"'{key}' must equal {rule['eq']}, got {actual}"
            if "lte" in rule:
                try:
                    actual_number, limit = float(actual), float(rule["lte"])
                    if not math.isfinite(actual_number) or not math.isfinite(limit):
                        return f"'{key}' has a non-finite lte value"
                    if actual_number > limit:
                        return f"'{key}'={actual} exceeds authorized max {rule['lte']}"
                except (TypeError, ValueError):
                    return f"'{key}' not numeric for lte check"
            if "gte" in rule:
                try:
                    actual_number, limit = float(actual), float(rule["gte"])
                    if not math.isfinite(actual_number) or not math.isfinite(limit):
                        return f"'{key}' has a non-finite gte value"
                    if actual_number < limit:
                        return f"'{key}'={actual} below authorized min {rule['gte']}"
                except (TypeError, ValueError):
                    return f"'{key}' not numeric for gte check"
            if "in" in rule and str(actual) not in [str(x) for x in rule["in"]]:
                return f"'{key}'={actual} not in authorized set"
        elif str(actual) != str(rule):
            return f"'{key}' must equal {rule}, got {actual}"
    return None


def verify_grant(public_key_pem: str, tool_name: str, arguments: Optional[dict],
                 token: Optional[str], *, leeway_s: float = 5.0, max_ttl_s: float = 300.0,
                 tenant_id: Optional[str] = None,
                 replay_store: Optional[ReplayStore] = None,
                 consume: bool = False) -> GrantResult:
    """Verify that a grant authorizes this action, optionally consuming it.

    Policy evaluation must use ``consume=False`` because REVIEW/HOLD/BLOCK paths
    do not execute.  An execution surface calls this again with ``consume=True``
    immediately before releasing the credential.  Consumption requires an
    explicit replay store so a deployment cannot silently fall back to
    process-local protection.
    """
    if not token:
        return GrantResult(False, "no capability grant presented")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return GrantResult(False, "cryptography package not available")

    try:
        pub = load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            return GrantResult(False, "public key is not Ed25519")
    except Exception:
        return GrantResult(False, "invalid public key")

    try:
        h_b64, p_b64, s_b64 = token.split(".")
        signing_input = (h_b64 + "." + p_b64).encode("ascii")
        header = json.loads(_b64url_decode(h_b64))
        claims = json.loads(_b64url_decode(p_b64))
        sig = _b64url_decode(s_b64)
    except Exception:
        return GrantResult(False, "malformed grant token")
    # A well-formed token whose header/claims decode to a non-object (e.g. a JSON
    # array) must fail closed here, not crash on `.get` further down.
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return GrantResult(False, "malformed grant token: header/claims must be objects")

    if header.get("alg") != "EdDSA":
        return GrantResult(False, f"unsupported alg {header.get('alg')!r} (require EdDSA)")
    try:
        pub.verify(sig, signing_input)
    except InvalidSignature:
        return GrantResult(False, "signature verification failed")
    except Exception:
        return GrantResult(False, "signature check error")

    now = time.time()
    try:
        iat = float(claims.get("iat", 0))
        exp = float(claims.get("exp", 0))
    except (TypeError, ValueError):
        return GrantResult(False, "bad iat/exp")
    if not math.isfinite(iat) or not math.isfinite(exp):
        return GrantResult(False, "bad iat/exp: values must be finite")
    if exp <= 0 or now > exp + leeway_s:
        return GrantResult(False, "grant expired")
    if iat and now + leeway_s < iat:
        return GrantResult(False, "grant not yet valid (iat in future)")
    if exp - iat > max_ttl_s:
        return GrantResult(False, f"grant lifetime exceeds max {max_ttl_s:.0f}s")
    if claims.get("tool") != tool_name:
        return GrantResult(False, f"grant authorizes {claims.get('tool')!r}, not {tool_name!r}")
    # Tenant scoping fails CLOSED: when the caller enforces a tenant, the grant
    # must carry a MATCHING tenant. A grant with no tenant claim is rejected, not
    # accepted for everyone (the cross-tenant hole).
    if tenant_id is not None and str(claims.get("tenant")) != str(tenant_id):
        return GrantResult(False, "grant is not scoped to this tenant")

    # A grant must constrain its arguments. An empty / absent `bind` would authorize
    # ARBITRARY arguments for the tool (unlimited amount, any destination). Require
    # an explicit `bind`, unless the signer deliberately opts out with bind_any=true
    # (only sane for a tool that takes no sensitive arguments).
    bind = claims.get("bind")
    if not (isinstance(bind, dict) and bind):
        if claims.get("bind_any") is True:
            bind = None
        else:
            return GrantResult(False, "grant has no argument binding "
                               "(add a bind, or bind_any=true to authorize any arguments)")
    if bind is not None:
        bind_err = _check_bind(bind, arguments or {})
        if bind_err:
            return GrantResult(False, "action does not match grant: " + bind_err)
        # A grant covers the WHOLE call, not only the fields it names. Without
        # this, a grant bound to {"amount": {"lte": 100}} also authorized
        # {"amount": 50, "admin_override": true}. Arguments the signer did not
        # bind are refused unless the grant says otherwise with `allow_extra`
        # (a list of names, or true). `reason` (the agent's free text) and
        # `_cost` (the gateway's own metering) are not action parameters.
        extra_ok = claims.get("allow_extra")
        if extra_ok is not True:
            covered = set(bind) | _NOT_ACTION_PARAMETERS
            if isinstance(extra_ok, (list, tuple)):
                covered |= {str(k) for k in extra_ok}
            unbound = sorted(str(k) for k in (arguments or {}) if str(k) not in covered)
            if unbound:
                return GrantResult(False, "action carries arguments the grant does not "
                                   f"cover: {', '.join(unbound)}")

    jti = str(claims.get("jti", ""))
    if not jti:
        return GrantResult(False, "grant missing jti (not single-use)")
    if consume:
        if replay_store is None:
            return GrantResult(False, "an explicit replay store is required to consume a grant")
        if replay_store.seen_or_record(jti, exp, time.time()):
            return GrantResult(False, "grant already used (replay)")

    return GrantResult(True, "grant consumed" if consume else "grant verified",
                       jti=jti, claims=claims)
