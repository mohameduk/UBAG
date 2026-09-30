"""
Transactional plan-session — the UBAG core's answer to the n+1 problem.

A per-action gate can only ever decide the current action (n+1). By the time it
sees a malicious step, the earlier side-effecting steps already happened, and you
may not be able to roll them back.

The plan-session moves the decision earlier: the agent submits its WHOLE plan, the
gateway HOLDS every step (nothing executes), scores the trajectory, and commits the
batch atomically only if the entire plan is clean. Because the gateway holds the
credentials, "hold" is real: no step reaches the outside world until COMMIT. For
stageable actions, this reaches n.

Two layers:
  - per-step: deterministic text signal (catches one loud action)
  - cumulative: reads the structured trajectory and catches the COMPOSITION —
    a drip spread across individually-benign steps — which no per-action gate sees.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from .policy import ALLOW, BLOCK, REVIEW, band
from .signals import text_signals

# Cumulative policy knobs (deterministic).
APPROVED_DESTINATIONS = {"house", "primary", "clearing", "core", "treasury-internal"}
SESSION_CEILING = 400.0     # max total value to NOVEL destinations across the plan
STAGED_MOVES = 3            # >= this many moves to one novel destination = staged drip


@dataclass(frozen=True)
class CompositionPolicy:
    """Deployment-owned plan composition thresholds."""
    approved_destinations: frozenset[str] = field(
        default_factory=lambda: frozenset(APPROVED_DESTINATIONS))
    session_ceiling: float = SESSION_CEILING
    staged_moves: int = STAGED_MOVES


@dataclass
class Action:
    step: int
    tool: str
    destination: str        # structured destination id (account / address)
    amount: float
    reason: str             # the agent's own free-text justification
    arguments: dict = field(default_factory=dict)  # exact structured step args, when available


@dataclass
class PlanResult:
    decision: str                 # COMMIT | HOLD | DISCARD
    steps: list                   # [(Action, band, score, detail)]
    cumulative_flags: list
    naive_executed: list          # what an n+1 per-step gate would already have RUN
    naive_caught: bool            # did the n+1 gate catch the bad action at all?


def per_step(a: Action) -> tuple[str, float, str]:
    sig = text_signals(a.reason)
    score = max(0.0, sum(sig.values()))
    detail = "clean" if not sig else ", ".join(f"{k}={v:+.2f}" for k, v in sig.items())
    return band(score), score, detail


def _is_novel(destination: str, state, policy: CompositionPolicy) -> bool:
    """A destination is 'novel' (suspect for accumulation) if the deployment's real
    allow-list says it is not allowed, or, with no provider, if it is not in the
    static baseline set. Ground truth wins when available."""
    d = (destination or "").lower()
    if state is not None:
        allowed = state.is_destination_allowed(destination)
        if allowed is not None:
            return not allowed
    return d not in policy.approved_destinations


def cumulative(actions: list[Action], state=None,
               policy: Optional[CompositionPolicy] = None) -> tuple[str, list[str]]:
    policy = policy or CompositionPolicy()
    flags: list[str] = []
    by_dest: dict[str, list[float]] = {}
    seen_terminal_refs: set[tuple[str, str]] = set()
    plan_total = 0.0
    if not actions:
        flags.append("empty plan has nothing to authorize")
    for a in actions:
        if isinstance(a.amount, bool) or not isinstance(a.amount, (int, float)) \
                or not math.isfinite(float(a.amount)) or float(a.amount) < 0:
            flags.append(f"step {a.step} has an invalid amount")
            continue
        plan_total += float(a.amount)
        # Terminal operations are not meaningfully repeatable. Canceling the same
        # order twice indicates a reordered/duplicated dependency and must discard
        # the whole held plan before either step reaches the executor.
        if a.tool == "cancel_order":
            ref = str((a.arguments or {}).get("order_id", "")).strip().lower()
            if ref:
                key = (a.tool, ref)
                if key in seen_terminal_refs:
                    flags.append(f"duplicate terminal action: {a.tool} for '{ref}' appears more than once")
                seen_terminal_refs.add(key)
        if _is_novel(a.destination, state, policy):
            by_dest.setdefault((a.destination or "").lower(), []).append(float(a.amount))
    for dest, amts in by_dest.items():
        total = sum(amts)
        if len(amts) >= policy.staged_moves:
            flags.append(f"staged drip: {len(amts)} moves to novel destination '{dest}' "
                         f"(each small, together ${total:,.0f}); the sequence is the attack")
        if total > policy.session_ceiling:
            flags.append(f"cumulative exfil: ${total:,.0f} to novel destination '{dest}' "
                          f"exceeds session ceiling ${policy.session_ceiling:,.0f}")
    if state is not None:
        balance = state.available_balance()
        if balance is not None and plan_total > balance:
            flags.append(f"plan total ${plan_total:,.0f} exceeds real balance ${balance:,.0f}")
    return (BLOCK if flags else ALLOW), flags


def evaluate_plan(actions: list[Action], state=None,
                  policy: Optional[CompositionPolicy] = None) -> PlanResult:
    """Hold the plan, score both layers, decide: DISCARD on any BLOCK, HOLD on any
    REVIEW, COMMIT only if every step and the whole trajectory are clean. When a
    StateProvider is passed, novelty is judged against the real allow-list."""
    steps, naive_executed, naive_caught = [], [], False
    for a in actions:
        b, score, detail = per_step(a)
        steps.append((a, b, score, detail))
        if not naive_caught:
            if b == BLOCK:
                naive_caught = True
            else:
                naive_executed.append(a)
    cum_decision, cum_flags = cumulative(actions, state, policy)
    bands = {s[1] for s in steps}
    if BLOCK in bands or cum_decision == BLOCK:
        decision = "DISCARD"
    elif REVIEW in bands:
        decision = "HOLD"
    else:
        decision = "COMMIT"
    return PlanResult(decision, steps, cum_flags, naive_executed, naive_caught)
