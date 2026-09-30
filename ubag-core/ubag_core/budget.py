"""
Spend budget — spend is authority.

A permission says WHERE an agent may act; a budget says HOW MUCH it may spend
getting there. Both are authority the operator delegates, and both have to be
enforced by the infrastructure rather than trusted to the prompt. Every action an
agent takes burns tokens, compute, and paid API calls, and at scale that spend is
the fastest way an autonomous loop turns a small mistake into a large invoice.

This is NOT the circuit breaker. The breaker is a rolling-window safety net: it
trips on runaway VELOCITY (too much cost too fast, or the same call looping) and
its window slides, so a slow burn eventually clears. A budget is a fixed ALLOWANCE
delegated for a task: it only ever decrements, and once it is spent the next action
is refused whether it arrived in one second or one week. One guards against losing
control; the other enforces a limit that was granted on purpose.

  spent + this action's cost > allowance   -> BLOCK   (the grant is exhausted)
  spent + this action's cost >= review_at  -> REVIEW  (soft warning, optional)
  otherwise                                -> ALLOW

Deterministic, in-memory, per-scope. It can only ever ADD a stop, never green-light.
Like the breaker it PROJECTS at decision time and CHARGES after a real execution, so
a refused or held proposal never draws down the allowance. Back the store with a
shared adapter for multi-instance; the threshold logic (`evaluate`) is identical.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Optional

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"


class BudgetStore:
    """Shared-state port for the spent-so-far ledger. Adapters must be atomic."""
    def spent(self, scope: str) -> float:                 # pragma: no cover
        raise NotImplementedError

    def charge(self, scope: str, cost: float) -> float:   # pragma: no cover
        raise NotImplementedError

    def reset(self, scope: Optional[str] = None):         # pragma: no cover
        raise NotImplementedError


class InMemoryBudgetStore(BudgetStore):
    def __init__(self):
        self._spent: dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def spent(self, scope: str) -> float:
        with self._lock:
            return self._spent.get(scope, 0.0)

    def charge(self, scope: str, cost: float) -> float:
        with self._lock:
            self._spent[scope] += float(cost)
            return self._spent[scope]

    def reset(self, scope: Optional[str] = None):
        with self._lock:
            if scope is None:
                self._spent.clear()
            else:
                self._spent.pop(scope, None)


def _verdict(decision: str, reason: str, spent: float, cost: float,
             allowance: float) -> dict:
    return {"decision": decision, "reason": reason,
            "spent": round(spent, 4), "cost": round(float(cost), 4),
            "allowance": round(allowance, 4),
            "remaining": round(max(0.0, allowance - spent), 4)}


def evaluate(spent: float, cost: float, *, allowance: float,
             review_at: Optional[float]) -> dict:
    """Pure threshold logic. The allowance is a hard stop; review_at is a soft one.

    `spent` is what the scope has already drawn; `cost` is this action's projected
    draw. An allowance of 0 (or less) means "no budget declared" and never stops.
    """
    projected = spent + max(0.0, float(cost))
    if allowance <= 0:
        return _verdict(ALLOW, "no budget declared", projected, cost, allowance)
    if projected > allowance:
        return _verdict(
            BLOCK,
            f"spend {projected:,.2f} would exceed the {allowance:,.2f} allowance "
            f"(remaining {max(0.0, allowance - spent):,.2f}) — the grant is spent",
            projected, cost, allowance)
    if review_at is not None and projected >= review_at:
        return _verdict(
            REVIEW,
            f"spend {projected:,.2f} at/above the {review_at:,.2f} review threshold "
            f"of a {allowance:,.2f} allowance",
            projected, cost, allowance)
    return _verdict(ALLOW, f"within budget ({allowance - projected:,.2f} of "
                    f"{allowance:,.2f} left)", projected, cost, allowance)


class SpendBudget:
    """A declared spend allowance, delegated per scope, enforced as a hard limit.

    `review_at` is optional; when None it is derived from `review_fraction` of the
    allowance (default 0.8), so a budget warns before it stops. Pass
    `review_fraction=1.0` for a pure hard cap with no soft band.
    """

    def __init__(self, allowance: float = 0.0, *, review_at: Optional[float] = None,
                 review_fraction: float = 0.8, store: Optional[BudgetStore] = None):
        self.allowance = float(allowance)
        if review_at is not None:
            self.review_at: Optional[float] = float(review_at)
        elif 0.0 < review_fraction < 1.0 and self.allowance > 0:
            self.review_at = self.allowance * review_fraction
        else:
            self.review_at = None
        self.store = store or InMemoryBudgetStore()

    def check(self, scope: str, cost: float = 0.0, *, charge: bool = False) -> dict:
        """Project this action's cost against the allowance -> ALLOW | REVIEW | BLOCK.

        `charge=False` (the default, and what the decision path uses) only projects,
        so a proposal the gate then refuses or holds never draws down the budget.
        The execution surface calls :meth:`charge` after a side effect actually runs.
        """
        spent = self.store.spent(scope)
        verdict = evaluate(spent, cost, allowance=self.allowance, review_at=self.review_at)
        if charge and verdict["decision"] != BLOCK:
            self.store.charge(scope, max(0.0, float(cost)))
        return verdict

    def charge(self, scope: str, cost: float) -> float:
        """Draw the real cost after an action executed. Returns the new spent total."""
        if not cost:
            return self.store.spent(scope)
        return self.store.charge(scope, max(0.0, float(cost)))

    def remaining(self, scope: str) -> float:
        if self.allowance <= 0:
            return float("inf")
        return max(0.0, self.allowance - self.store.spent(scope))

    def reset(self, scope: Optional[str] = None) -> None:
        self.store.reset(scope)
