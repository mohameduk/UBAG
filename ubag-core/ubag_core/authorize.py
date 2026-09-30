"""
Plan authorization — the irreversibility layer (closes the n problem).

The transactional plan-session (plan.evaluate_plan) reaches n for STAGEABLE actions:
hold everything provisionally, commit atomically, discard freely. That safety net
only exists when the action can be escrowed.

Some actions cannot. An on-chain send, a cleared wire, a hard delete, a sent email
commits the instant it touches the world. There is no provisional state to hold and
no rollback. For those, the decision must be made BEFORE anything runs, and it must
be stricter, because there is no undo:

  - REVERSIBLE-only plan  -> transactional: COMMIT / HOLD / DISCARD (hold is safe)
  - plan with IRREVERSIBLE actions -> plan-authorization: AUTHORIZE / HOLD / REFUSE
      * AUTHORIZE only if the WHOLE plan is clean (no BLOCK, no REVIEW, no composition
        flag) — there is no "hold for review" once a step is real
      * HOLD sends the plan to a human before anything runs
      * any block/review/drip -> REFUSE, nothing executes

Even after AUTHORIZE, each irreversible step is re-verified against CURRENT ground
truth right before it fires (`precheck_irreversible`), because state may have drifted
since authorization. That is the last defensible line; an irreversible step that has
already fired cannot be pulled back, and the honest boundary is that the gate reduces
that window, it does not erase it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .plan import Action, CompositionPolicy, cumulative, per_step
from .policy import ALLOW, BLOCK, REVIEW
from .registry import Registry
from .state import verify_state

# transactional outcomes
COMMIT, HOLD, DISCARD = "COMMIT", "HOLD", "DISCARD"
# plan-authorization outcomes
AUTHORIZE, REFUSE = "AUTHORIZE", "REFUSE"


@dataclass
class AuthResult:
    decision: str                       # COMMIT/HOLD/DISCARD or AUTHORIZE/HOLD/REFUSE
    mode: str                           # "transactional" | "plan-authorization"
    reasons: list = field(default_factory=list)
    irreversible_steps: list = field(default_factory=list)   # steps needing pre-fire recheck
    steps: list = field(default_factory=list)                # [(Action, band, score, detail)]
    engine_decisions: list = field(default_factory=list)     # [(Action, PolicyDecision)]


def _reversible(registry: Optional[Registry], tool_name: str) -> bool:
    rule = registry.tools.get(tool_name) if registry else None
    return getattr(rule, "reversible", True) if rule else True


def authorize_plan(actions: list[Action], registry: Optional[Registry] = None,
                   state=None, composition_policy: Optional[CompositionPolicy] = None) -> AuthResult:
    """Composition-only compatibility primitive.

    This function does not run the full per-step engine (ACL, grounding, grants,
    deny memory, argument scanning, breaker, or verification floor). Deployment
    surfaces must call ``GatewayEngine.decide_plan``. It is retained for callers
    that intentionally need only trajectory/reversibility classification.
    """
    steps = [(a, *per_step(a)) for a in actions]
    cum_decision, cum_flags = cumulative(actions, state, composition_policy)
    irreversible = [a.step for a in actions if not _reversible(registry, a.tool)]
    bands = {s[1] for s in steps}
    has_block = (BLOCK in bands) or (cum_decision == BLOCK)
    has_review = REVIEW in bands
    reasons = list(cum_flags)

    if irreversible:
        # No rollback safety net. Only a fully clean plan may be authorized.
        if has_block:
            dec = REFUSE
            reasons.append("plan contains a blocked step and irreversible actions — refused")
        elif has_review or cum_flags:
            dec = HOLD
            reasons.append("irreversible plan needs human sign-off before any step runs")
        else:
            dec = AUTHORIZE
            reasons.append(f"whole plan clean; {len(irreversible)} irreversible step(s) "
                           f"will be re-verified at fire time")
        return AuthResult(dec, "plan-authorization", reasons, irreversible, steps)

    # All reversible -> transactional (holding is safe).
    if has_block:
        dec = DISCARD
    elif has_review:
        dec = HOLD
    else:
        dec = COMMIT
    return AuthResult(dec, "transactional", reasons, [], steps)


def precheck_irreversible(action: Action, state, *, agent_id: str = "plan",
                          exposure_ceiling: float = 0.0,
                          principal_id: Optional[str] = None):
    """Re-verify one irreversible action against CURRENT ground truth, immediately
    before it fires. Returns (ok, reason). A False here HALTS the plan; earlier
    irreversible steps that already fired cannot be undone.

    For an irreversible action there is NO rollback net, so BOTH a BLOCK and a
    REVIEW halt it: a "hold for review" verdict cannot be honored once the step
    would fire, so it must stop, not proceed. (A reversible plan can hold; this
    path cannot.) The exposure ceiling is honored so a fire-time exposure overrun
    halts too — it must be passed by the caller."""
    d = verify_state(state, agent_id, {"destination": action.destination, "amount": action.amount},
                     exposure_ceiling=exposure_ceiling)
    if d is not None and d.decision in (BLOCK, REVIEW):
        return False, d.reason
    # Ownership can change between authorization and fire time (a resource is
    # transferred, a booking reassigned). The plan was authorized on ownership, so
    # it is re-asked here: a definite "not owned" halts the step. None (the
    # deployment cannot say) does not invent an owner, as in the engine.
    owns = getattr(state, "owns_resource", None) if state is not None else None
    if callable(owns):
        try:
            owned = owns(principal_id or agent_id, action.tool, dict(action.arguments or {}))
        except Exception:                                  # noqa: BLE001
            return False, "resource ownership could not be re-verified at fire time"
        if owned is False:
            return False, ("resource ownership: the acting principal no longer owns the "
                           "target resource at fire time")
    return True, "ground truth still valid at fire time"
