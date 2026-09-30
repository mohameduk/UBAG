"""
Circuit breaker — deterministic runaway / loop / budget guard.

The guard for the Cursor-class failure: an agent stuck in a loop burning cost with
no cap (1.3B tokens, $1,382, 90 minutes, to tag 87 tasks). That is a structural
state-machine failure, not a speed violation. The breaker trips on STRUCTURE:

  LOOP   — the same call repeated >= loop_repeats within loop_window_s   -> BLOCK
  BUDGET — cumulative cost in the rolling window crosses soft/hard caps   -> THROTTLE / BLOCK

Deterministic, in-memory, per-agent. It can only ever ADD a stop, never green-light.
Inject `now` for reproducible tests. For multi-instance, back the window with a
shared store; the threshold logic (`evaluate`) is identical either way.
"""
from __future__ import annotations

import time
import threading
import uuid
from collections import defaultdict, deque
from typing import Optional

ALLOW, THROTTLE, BLOCK = "ALLOW", "THROTTLE", "BLOCK"


class BreakerStore:
    """Shared-state port. Production adapters must make updates atomic."""
    def record(self, scope: str, *, now: float, window_s: float,
               loop_window_s: float, signature: str, cost: float):  # pragma: no cover
        raise NotImplementedError

    def reset(self, scope: Optional[str] = None):         # pragma: no cover
        raise NotImplementedError


class InMemoryBreakerStore(BreakerStore):
    def __init__(self):
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def record(self, scope: str, *, now: float, window_s: float,
               loop_window_s: float, signature: str, cost: float):
        with self._lock:
            dq = self._events[scope]
            cutoff = now - window_s
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            dq.append((now, signature, float(cost)))
            total = sum(event_cost for _, _, event_cost in dq)
            loop_cutoff = now - loop_window_s
            repeats = sum(1 for ts, sig, _ in dq
                          if sig == signature and ts >= loop_cutoff)
            return total, repeats

    def reset(self, scope: Optional[str] = None):
        with self._lock:
            if scope is None:
                self._events.clear()
            else:
                self._events.pop(scope, None)


def _verdict(decision: str, reason: str, total_cost: float, repeats: int) -> dict:
    return {"decision": decision, "reason": reason,
            "cumulative_cost": round(total_cost, 4), "repeats": repeats}


def evaluate(total_cost: float, repeats: int, *, soft_budget: float, hard_budget: float,
             loop_repeats: int, loop_window_s: float) -> dict:
    """Pure threshold logic. Hard budget and loop are hard stops; soft budget throttles."""
    if total_cost >= hard_budget:
        return _verdict(BLOCK, f"cumulative ${total_cost:,.2f} >= hard budget "
                        f"${hard_budget:,.2f} — runaway burn", total_cost, repeats)
    if repeats >= loop_repeats:
        return _verdict(BLOCK, f"identical call x{repeats} in {loop_window_s:.0f}s — "
                        f"state-machine stall (loop)", total_cost, repeats)
    if total_cost >= soft_budget:
        return _verdict(THROTTLE, f"cumulative ${total_cost:,.2f} >= soft budget "
                        f"${soft_budget:,.2f} — flag for review", total_cost, repeats)
    return _verdict(ALLOW, "within budget", total_cost, repeats)


class CircuitBreaker:
    def __init__(self, *, window_s: float = 120.0, soft_budget: float = 5.0,
                 hard_budget: float = 12.0, loop_repeats: int = 25, loop_window_s: float = 60.0,
                 store: Optional[BreakerStore] = None):
        self.window_s = window_s
        self.soft_budget = soft_budget
        self.hard_budget = hard_budget
        self.loop_repeats = loop_repeats
        self.loop_window_s = loop_window_s
        self.store = store or InMemoryBreakerStore()

    def check(self, agent_id: str, signature: str, cost: float = 0.0,
              now: Optional[float] = None, *, charge_cost: bool = True) -> dict:
        """Record a proposal and return ALLOW | THROTTLE | BLOCK.

        ``charge_cost=False`` records the proposal for loop detection but only
        projects its cost into this verdict.  The execution surface calls
        :meth:`charge` after a real execution, so rejected proposals cannot burn
        the caller's execution budget.
        """
        # Wall-clock timestamps are comparable across processes/hosts. A shared
        # breaker store cannot use process-local monotonic clock origins.
        now = time.time() if now is None else now
        total_cost, repeats = self.store.record(
            agent_id, now=now, window_s=self.window_s,
            loop_window_s=self.loop_window_s, signature=signature,
            cost=cost if charge_cost else 0.0)
        projected_cost = total_cost if charge_cost else total_cost + float(cost)
        return evaluate(projected_cost, repeats, soft_budget=self.soft_budget,
                        hard_budget=self.hard_budget, loop_repeats=self.loop_repeats,
                        loop_window_s=self.loop_window_s)

    def charge(self, agent_id: str, cost: float, now: Optional[float] = None) -> None:
        """Record cost after a side effect actually executed."""
        if not cost:
            return
        now = time.time() if now is None else now
        self.store.record(
            agent_id, now=now, window_s=self.window_s,
            loop_window_s=self.loop_window_s,
            signature=f"__executed_cost__:{uuid.uuid4().hex}", cost=cost)

    def reset(self, agent_id: Optional[str] = None) -> None:
        self.store.reset(agent_id)
