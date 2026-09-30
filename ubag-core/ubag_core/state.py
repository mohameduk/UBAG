"""
State provider — the ground-truth port (Pile B, layer 2: state verification).

The gate must never trust what the model CLAIMS about the world. It asks the
deployment. `StateProvider` is the universal plug: core defines the questions, the
deployment answers them against its real systems (broker, ledger, database). A
Kraken adapter, a bank adapter, and a brokerage adapter all satisfy the same port,
and core never changes.

Every method returns Optional: return None for "I can't answer that" and the gate
skips that check (so a deployment implements only what it can verify). A definite
False is a hard ground-truth failure.
"""
from __future__ import annotations

import math
from typing import Optional

from .policy import BLOCK, REVIEW, PolicyDecision, canonical_signature


class StateProvider:
    """Implement the questions your deployment can answer against real systems."""

    def is_destination_allowed(self, destination: str) -> Optional[bool]:
        """Is this destination on the real allow-list? None = unknown."""
        return None

    def account_exists(self, ref: str) -> Optional[bool]:
        """Does this account / order / entity actually exist? (e.g. refund TX123.)"""
        return None

    def available_balance(self) -> Optional[float]:
        """Real spendable balance. None = unknown."""
        return None

    def current_exposure(self, agent_id: str) -> Optional[float]:
        """Value this agent has already committed this session. None = unknown."""
        return None

    def owns_resource(self, principal_id: str, tool_name: str,
                      arguments: dict) -> Optional[bool]:
        """Does `principal_id` own the resource this action targets? None = can't say.

        Consulted by the engine only for IRREVERSIBLE verbs. Granting an
        irreversible verb is not granting it on every resource: "may cancel" is
        not "may cancel anything". A definite False refuses the action even when
        the verb is allowed; None means the deployment cannot resolve an owner and
        the gate does not invent one (it is not a router). This is the exact
        distinction the Melbourne cancel endpoint failed to make, moved to the
        point of authorization instead of the handler."""
        return None


class StaticStateProvider(StateProvider):
    """Reference / test implementation backed by fixed values."""

    def __init__(self, *, allowed_destinations=None, balance: Optional[float] = None,
                 exposure: Optional[float] = None, accounts=None):
        # None = "not configured, I can't answer" (returns None -> check skipped).
        # A list (INCLUDING an empty one) = "this is the allow-list" -> an empty
        # list denies everything. Conflating the two would fail open.
        self._allowed = None if allowed_destinations is None \
            else {d.lower() for d in allowed_destinations}
        self._balance = balance
        self._exposure = exposure
        self._accounts = {a.lower() for a in (accounts or [])} if accounts is not None else None

    def is_destination_allowed(self, destination: str) -> Optional[bool]:
        if self._allowed is None:
            return None
        return (destination or "").lower() in self._allowed

    def account_exists(self, ref: str) -> Optional[bool]:
        if self._accounts is None:
            return None
        return (ref or "").lower() in self._accounts

    def available_balance(self) -> Optional[float]:
        return self._balance

    def current_exposure(self, agent_id: str) -> Optional[float]:
        return self._exposure


def verify_state(provider: Optional[StateProvider], agent_id: str, arguments: dict, *,
                 exposure_ceiling: float = 0.0) -> Optional[PolicyDecision]:
    """Run the ground-truth checks. Returns a BLOCK/REVIEW decision on a failure, or
    None if everything the provider could answer checks out."""
    if provider is None or not arguments:
        return None
    sig = canonical_signature("state", arguments)
    dest = arguments.get("destination")
    amount = _num(arguments.get("amount"))

    if "amount" in arguments and amount is None:
        return PolicyDecision(BLOCK, "amount is not a finite number", score=0.9, signature=sig,
                              flags=[{"check": "State: amount", "severity": "HIGH"}])
    if amount is not None and amount < 0:
        return PolicyDecision(BLOCK, "amount cannot be negative", score=0.9, signature=sig,
                              flags=[{"check": "State: amount", "severity": "HIGH"}])

    if dest:
        allowed = provider.is_destination_allowed(dest)
        if allowed is False:
            return PolicyDecision(BLOCK, f"destination '{dest}' is not on the allow-list",
                                  score=0.9, signature=sig,
                                  flags=[{"check": "State: destination", "severity": "CRITICAL"}])

    if amount is not None:
        bal = provider.available_balance()
        if bal is not None and amount > bal:
            return PolicyDecision(BLOCK, f"amount {amount:,.2f} exceeds real balance {bal:,.2f}",
                                  score=0.9, signature=sig,
                                  flags=[{"check": "State: balance", "severity": "HIGH"}])
        if exposure_ceiling > 0:
            exp = provider.current_exposure(agent_id)
            if exp is not None and (exp + amount) > exposure_ceiling:
                return PolicyDecision(REVIEW, f"exposure {exp:,.2f}+{amount:,.2f} would exceed "
                                      f"ceiling {exposure_ceiling:,.2f}", score=0.5, signature=sig,
                                      flags=[{"check": "State: exposure", "severity": "MEDIUM"}])
    return None


def count_confirmations(provider: Optional[StateProvider], agent_id: str,
                        arguments: Optional[dict]) -> int:
    """How many ground-truth questions the provider POSITIVELY confirmed for this
    action.  Balance sufficiency is deliberately excluded: it proves only that an
    account can afford an action, not that a high-value action is authorized.
    Used by the engine's verification floor: "verified" means an affirmative
    policy premise such as an allow-listed destination, not merely solvency."""
    if provider is None or not arguments:
        return 0
    n = 0
    dest = arguments.get("destination")
    if dest and provider.is_destination_allowed(dest) is True:
        n += 1
    return n


def _num(val) -> Optional[float]:
    """Coerce to a FINITE float, or None. NaN/inf are rejected so they can never
    slip past a balance or exposure comparison (nan > x is always False)."""
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        f = float(val)
    elif isinstance(val, str):
        try:
            f = float(val.replace(",", "").strip())
        except ValueError:
            return None
    else:
        return None
    return f if math.isfinite(f) else None
