"""
Result verifier — the ground-truth port for OUTCOMES (Pile B, causal layer).

State verification asks "is this true before I act." Result verification asks "what
actually happened after." The agent never gets to invent success: if it claims the
order filled and the system of record says it errored, the gateway returns the
TRUTH, not the claim. Same universal-plug pattern: core defines the question, the
deployment answers it against the broker / ledger / API.

`action_status(reference)` returns the authoritative status of a prior action, or
None if unknown. Best-effort keys: {"success": bool, "filled_qty": float,
"price": float, "error": str}.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

CONFIRMED, CONTRADICTED, UNVERIFIED = "CONFIRMED", "CONTRADICTED", "UNVERIFIED"


class ResultVerifier:
    def action_status(self, reference: str) -> Optional[dict]:
        """Authoritative status of a prior action from the system of record."""
        return None


class StaticResultVerifier(ResultVerifier):
    """Reference / test implementation: reference id -> status dict."""
    def __init__(self, statuses: Optional[dict] = None):
        self._statuses = statuses or {}

    def action_status(self, reference: str) -> Optional[dict]:
        return self._statuses.get(reference)


@dataclass
class ResultCheck:
    verdict: str                    # CONFIRMED | CONTRADICTED | UNVERIFIED
    reason: str
    truth: dict = field(default_factory=dict)   # authoritative status to feed back to the agent


def _num(v):
    """Coerce to a FINITE float, or None (NaN/inf rejected so a claimed price of
    NaN can never slip past the tolerance comparison)."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def verify_result(verifier: Optional[ResultVerifier], reference: str,
                  claim: Optional[dict] = None, *, price_tolerance: float = 0.0) -> ResultCheck:
    """Compare the agent's claimed outcome against the system of record.

    With no claim, report the authoritative truth. With a claim, CONTRADICT it if it
    disagrees with reality on success, or on price beyond `price_tolerance`."""
    if verifier is None or not reference:
        return ResultCheck(UNVERIFIED, "no verifier or reference", {})
    truth = verifier.action_status(reference)
    if truth is None:
        return ResultCheck(UNVERIFIED, "status unknown from system of record", {})

    real_success = bool(truth.get("success"))
    if claim is None:
        return ResultCheck(CONFIRMED if real_success else CONTRADICTED,
                           "succeeded" if real_success else
                           f"did NOT succeed: {truth.get('error', 'unknown error')}", truth)

    if isinstance(claim, dict):
        has_success = "success" in claim or "status" in claim
        status = str(claim.get("status", "")).strip().lower()
        claimed_success = (bool(claim.get("success")) if "success" in claim
                           else status in {"ok", "success", "succeeded", "filled",
                                           "complete", "completed"})
    else:
        has_success, claimed_success = True, bool(claim)
    if has_success:
        if claimed_success and not real_success:
            return ResultCheck(CONTRADICTED, "agent claimed success but system of record shows "
                               f"failure: {truth.get('error', 'unknown error')}", truth)
        if (not claimed_success) and real_success:
            return ResultCheck(CONTRADICTED, "agent claimed failure but it actually succeeded", truth)

    # Compare fill price when both sides report one.
    claim_map = claim if isinstance(claim, dict) else {}
    cp, tp = _num(claim_map.get("price")), _num(truth.get("price"))
    if isinstance(claim, dict) and "price" in claim and tp is None:
        return ResultCheck(UNVERIFIED, "claimed price is absent from the system of record", truth)
    if cp is not None and tp is not None and abs(cp - tp) > price_tolerance:
        return ResultCheck(CONTRADICTED, f"agent claimed price {cp:,.2f} but real fill was "
                           f"{tp:,.2f}", truth)

    # Reconcile every additional claimed field. Previously, arbitrary fields such
    # as executed_amount were silently ignored and a mismatched claim was marked
    # CONFIRMED as long as success/price happened to match.
    if isinstance(claim, dict):
        for key, wanted in claim.items():
            if key in {"success", "status", "price"}:
                continue
            if key not in truth:
                return ResultCheck(UNVERIFIED,
                                   f"claimed field '{key}' is absent from the system of record",
                                   truth)
            actual = truth[key]
            wn, an = _num(wanted), _num(actual)
            matches = (wn == an) if wn is not None and an is not None else wanted == actual
            if not matches:
                return ResultCheck(CONTRADICTED,
                                   f"agent claimed {key}={wanted!r} but system of record has "
                                   f"{actual!r}", truth)

    return ResultCheck(CONFIRMED, "claim matches the system of record", truth)
