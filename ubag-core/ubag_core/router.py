"""
Execution router - route each task to the cheapest compliant agent.

The reasoning is not ours to control. A customer brings their strongest model to
decide WHAT a task is; this routes WHO executes it. The split is the whole point:
we never try to predict which model is "best" (that needs quality prediction, which
is not deterministic), so we never claim to. We pick, deterministically, the
cheapest agent that is COMPLIANT for the task's data, has the required capability,
and meets the latency budget. Given the same candidates, telemetry and task, the
same agent is chosen every time. No model sits in this decision.

The differentiator is the first filter. A pure cost router (Martian, NotDiamond,
OpenRouter) cannot route on SECURITY, because it does not own the trust boundary.
UBAG does, so a task carrying regulated data can be refused every third-party agent
and pinned to the on-prem one, as policy, before cost is even considered.

  0. Custody     - when a vault is attached, drop any agent whose credential UBAG
                   does not hold. An agent carrying its own key cannot be governed,
                   so it is never a routing option, however cheap it is.
  1. Compliance  - drop any agent not permitted for this task's data class. Deny by
                   default: an agent that does not explicitly allow the class is out.
  2. Capability  - drop any agent missing a capability the task requires.
  3. Budget/SLO  - drop any agent whose projected cost exceeds the remaining budget
                   or whose live latency exceeds the task's SLO.
  4. Optimize    - among the survivors, pick by the objective (cost / latency /
                   balanced), with a stable tie-break so the choice is reproducible.

If nothing survives the filters the router REFUSES rather than falling back to a
non-compliant agent, exactly like the gate refuses an unauthorized action.

CREDENTIAL-BOUND ROUTING. Each candidate names the vault reference of the key that
reaches it. The agent holds none of them. Routing to an agent and releasing that
agent's key are therefore one decision: the decision records the single reference
released and every reference withheld, and `release()` resolves only the chosen
one. A regulated task pinned to the on-prem model means the cloud providers' keys
never leave the vault, so the data cannot reach them. The router never reads a
secret value itself; only `release()` does, and only for a routed decision.

Deterministic, in-memory. Telemetry (live latency, observed cost) is updated after a
real execution so routing tracks current conditions; the DECISION FUNCTION stays
deterministic on each snapshot.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


class CredentialVault:
    """Port to wherever production keys live (Secret Manager, Vault, KMS, HSM).

    The router asks only `has(ref)`, a custody question. `resolve(ref)` returns
    the secret and is called by `Router.release()` for a routed decision only.
    """
    def has(self, ref: str) -> bool:                   # pragma: no cover
        raise NotImplementedError

    def resolve(self, ref: str) -> str:                # pragma: no cover
        raise NotImplementedError


class StaticVault(CredentialVault):
    """In-memory vault for tests and demos. Never put real keys in one."""
    def __init__(self, secrets=None):
        self._secrets = dict(secrets or {})

    def has(self, ref: str) -> bool:
        return bool(ref) and ref in self._secrets

    def resolve(self, ref: str) -> str:
        if not self.has(ref):
            raise KeyError(f"no credential held for {ref!r}")
        return self._secrets[ref]


@dataclass
class RouteCandidate:
    """One executor UBAG may route to.

    `allowed_data_classes` is the security contract: the set of data classes this
    agent may handle. Empty means it may handle nothing (deny by default). `cost` is
    a relative cost per unit of work (tokens, calls, dollars, the operator's unit);
    `latency_ms` is the live figure, updated by `Router.record`. `credential_ref`
    names the vault entry holding the key that reaches this agent; empty means
    UBAG holds no key for it.
    """
    id: str
    cost: float                                    # relative cost per unit of work
    latency_ms: float = 0.0                         # live, updated by record()
    allowed_data_classes: frozenset = frozenset()  # security: what data it may touch
    capabilities: frozenset = frozenset()          # what it can do
    local: bool = False                            # on-prem / owned (informational)
    credential_ref: str = ""                       # vault reference, never the secret


@dataclass
class RouteTask:
    """What the planner handed down, described in routable terms (not its reasoning).

    `data_class` drives the compliance filter; it defaults to "public" so an
    unclassified task can only reach agents that explicitly allow public data.
    """
    data_class: str = "public"
    required_capabilities: frozenset = frozenset()
    max_latency_ms: Optional[float] = None         # SLO; None = no latency limit
    est_units: float = 1.0                          # scales each candidate's cost
    budget_remaining: Optional[float] = None        # projected cost must not exceed this


@dataclass
class RouteDecision:
    chosen: Optional[str]                            # candidate id, or None if refused
    reason: str
    projected_cost: float = 0.0
    latency_ms: float = 0.0
    considered: list = field(default_factory=list)   # [(id, ok: bool, why: str)]
    credential_ref: str = ""                         # the ONE key this decision releases
    withheld: list = field(default_factory=list)     # every other key, never released

    @property
    def routed(self) -> bool:
        return self.chosen is not None


def _score(cand: RouteCandidate, cost: float, objective: str,
           weights: tuple[float, float]) -> tuple:
    """Sort key, lower is better. Every key ends with the id for a stable tie-break,
    so the same snapshot always resolves to the same agent."""
    lat = max(cand.latency_ms, 0.0)
    if objective == "latency":
        return (lat, cost, cand.id)
    if objective == "balanced":
        w_cost, w_lat = weights
        return (w_cost * cost + w_lat * (lat / 1000.0), cand.id)
    return (cost, lat, cand.id)                      # default: cost


class Router:
    """Deterministic execution router over a fixed set of candidate agents."""

    def __init__(self, candidates=None, *, ewma_alpha: float = 0.3,
                 vault: Optional[CredentialVault] = None):
        self._by_id: dict[str, RouteCandidate] = {}
        self._alpha = ewma_alpha
        self._lock = threading.Lock()
        # With a vault attached, routing is credential-bound: only agents whose key
        # UBAG holds are routable. Without one, custody is not checked (back-compat).
        self._vault = vault
        for c in candidates or ():
            self.register(c)

    @property
    def credential_bound(self) -> bool:
        """True when a vault is attached, so routing checks custody and can release."""
        return self._vault is not None

    def register(self, candidate: RouteCandidate) -> None:
        self._by_id[candidate.id] = candidate

    def route(self, task: RouteTask, *, objective: str = "cost",
              weights: tuple[float, float] = (1.0, 1.0)) -> RouteDecision:
        considered: list = []
        survivors: list[tuple[RouteCandidate, float]] = []

        for cand in self._by_id.values():
            # 0. Custody - no key in the vault, no route. An agent holding its own
            # credential sits outside the boundary and cannot be governed.
            if self._vault is not None and not self._vault.has(cand.credential_ref):
                considered.append((cand.id, False,
                                   "no credential held in the vault for this agent"))
                continue
            # 1. Compliance - the hard gate. Deny by default.
            if task.data_class not in cand.allowed_data_classes:
                considered.append((cand.id, False,
                                   f"not permitted for data class '{task.data_class}'"))
                continue
            # 2. Capability.
            missing = task.required_capabilities - cand.capabilities
            if missing:
                considered.append((cand.id, False,
                                   f"missing capability {sorted(missing)}"))
                continue
            # 3. Budget / SLO.
            projected = cand.cost * max(0.0, task.est_units)
            if task.budget_remaining is not None and projected > task.budget_remaining:
                considered.append((cand.id, False,
                                   f"cost {projected:.4g} exceeds remaining budget "
                                   f"{task.budget_remaining:.4g}"))
                continue
            if task.max_latency_ms is not None and cand.latency_ms > task.max_latency_ms:
                considered.append((cand.id, False,
                                   f"latency {cand.latency_ms:.0f}ms over SLO "
                                   f"{task.max_latency_ms:.0f}ms"))
                continue
            considered.append((cand.id, True, "eligible"))
            survivors.append((cand, projected))

        all_refs = sorted({c.credential_ref for c in self._by_id.values()
                           if c.credential_ref})
        if not survivors:
            # Refuse, do not fall back to a non-compliant or over-budget agent. No
            # key is released, so every credential stays in the vault.
            return RouteDecision(
                None,
                f"no eligible agent for data class '{task.data_class}'"
                + (f" with {sorted(task.required_capabilities)}"
                   if task.required_capabilities else ""),
                considered=considered, withheld=all_refs)

        best, cost = min(survivors,
                         key=lambda sc: _score(sc[0], sc[1], objective, weights))
        return RouteDecision(
            best.id,
            f"cheapest eligible agent ({objective}); {len(survivors)} candidate(s) passed",
            projected_cost=cost, latency_ms=best.latency_ms, considered=considered,
            credential_ref=best.credential_ref,
            withheld=[r for r in all_refs if r != best.credential_ref])

    def release(self, decision: RouteDecision) -> Optional[str]:
        """Resolve the ONE credential a routed decision names, for injection into the
        outbound call. Refused decisions release nothing. The secret is returned to
        the caller (the gateway's executor) and is never stored on the decision."""
        if self._vault is None or not decision.routed or not decision.credential_ref:
            return None
        return self._vault.resolve(decision.credential_ref)

    def record(self, candidate_id: str, *, latency_ms: Optional[float] = None,
               cost: Optional[float] = None) -> None:
        """Fold a real execution's measured latency/cost into the live figures, so
        the next routing decision reflects current conditions (a slow or rate-limited
        agent is deprioritized). EWMA, so one slow call does not swing it wholesale."""
        cand = self._by_id.get(candidate_id)
        if cand is None:
            return
        a = self._alpha
        with self._lock:
            if latency_ms is not None:
                cand.latency_ms = (a * float(latency_ms) + (1 - a) * cand.latency_ms
                                   if cand.latency_ms else float(latency_ms))
            if cost is not None:
                cand.cost = a * float(cost) + (1 - a) * cand.cost

    def candidates(self) -> list:
        return list(self._by_id.values())
