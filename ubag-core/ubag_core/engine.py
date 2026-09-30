"""
Gateway engine — composes every deterministic layer into one decision.

For each proposed action it runs, in order, taking the stricter verdict at each step
(a layer can only ADD suspicion, never clear it):

  1.  Tool ACL + value ceiling  (registry)      — unknown/denied/oversized -> BLOCK
  1b. State verification        (state)         — destination/balance/exposure vs ground truth
  1c. Grounding verification    (grounding)     — the premises the action stands on: fabricated
                                                  references and facts the world contradicts -> BLOCK
  2.  Capability grant          (capability)    — required tools need a valid signed grant
  3.  Behavioral reason signals (signals)       — injection/exfil/control in the justification
  3b. Attack memory             (denylist)      — confirmed-attack fingerprints (and their
                                                  recase/reorder/de-leet variants) -> BLOCK
  4.  Argument injection scan   (registry+signals)
  5.  Circuit breaker           (breaker)       — velocity / cost / loop across the session
  5b. Spend budget              (budget)        — a declared allowance the operator delegates;
                                                  spend is authority, exhausted -> BLOCK / REVIEW
  6.  Verification floor        (engine)        — at/above verify_floor, an ALLOW needs at
                                                  least one POSITIVE authorization signal
                                                  (allow-list, grounding, or a valid grant) -> REVIEW

Every decision is written to the audit sink. Deterministic throughout: no LLM.
The transactional plan-session (plan.evaluate_plan) sits alongside this for the
multi-step / composition case.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .audit import AuditRecord, AuditSink, InMemoryAudit, make_record
from .breaker import CircuitBreaker
from .budget import SpendBudget
from .capability import ReplayStore, verify_grant
from .denylist import DenyMemory, scan_denied
from .grounding import (Claim, FactProvider, GroundingRule, decision_from_checks,
                        ground_claims)
from .policy import ALLOW, BLOCK, REVIEW, PolicyDecision, band, canonical_signature, merge
from .registry import Registry, _coerce_float, _iter_strings, check_tool, scan_arguments
from .result import CONFIRMED, ResultVerifier, ResultCheck, verify_result
from .signals import hard_injection_hits, injection_hits, text_signals
from .state import StateProvider, count_confirmations, verify_state
from .plan import Action, CompositionPolicy
from .authorize import (AuthResult, AUTHORIZE, COMMIT, DISCARD, HOLD, REFUSE,
                        authorize_plan)
from .identity import SecurityContext, coerce_context


@dataclass
class PlanProposal:
    """One immutable-intent input to the engine-owned whole-plan gate."""
    tool: str
    arguments: dict = field(default_factory=dict)
    reason: str = ""
    grant: Optional[str] = None
    claims: list[Claim] = field(default_factory=list)


class GatewayEngine:
    def __init__(self, registry: Registry, *, breaker: Optional[CircuitBreaker] = None,
                 budget: Optional[SpendBudget] = None,
                 audit: Optional[AuditSink] = None, grant_required: Optional[set] = None,
                 public_key_pem: str = "", detector: Optional[Callable[[str], list]] = None,
                 state: Optional[StateProvider] = None, exposure_ceiling: float = 0.0,
                 result_verifier: Optional[ResultVerifier] = None,
                 facts: Optional[FactProvider] = None,
                 grounding: Optional[dict[str, GroundingRule]] = None,
                 deny_memory: Optional[DenyMemory] = None,
                 verify_floor: float = 0.0,
                 grant_replay_store: Optional[ReplayStore] = None,
                 composition_policy: Optional[CompositionPolicy] = None,
                 composition_policy_provider: Optional[
                     Callable[[SecurityContext], CompositionPolicy]] = None):
        self.registry = registry
        self.breaker = breaker or CircuitBreaker()
        self.budget = budget                     # declared spend allowance (optional)
        self.audit = audit or InMemoryAudit()
        self.grant_required = set(grant_required or [])
        self.public_key_pem = public_key_pem
        # Argument scanner default: hard-block families only. encoded-payload is
        # excluded here (as it already is for reasons) so a bare IBAN/account id in
        # an argument does not hard-block a legitimate transfer.
        self.detector = detector or hard_injection_hits
        self.state = state                       # ground-truth port, before (optional)
        self.exposure_ceiling = exposure_ceiling
        self.result_verifier = result_verifier   # ground-truth port, after (optional)
        self.facts = facts                       # ground-truth port, premises (optional)
        self.grounding = grounding or {}         # tool name -> GroundingRule
        self.deny_memory = deny_memory           # confirmed-attack fingerprints (optional)
        self.verify_floor = verify_floor         # USD at/above which ALLOW needs a confirmation
        self.grant_replay_store = grant_replay_store
        self.composition_policy = composition_policy or CompositionPolicy()
        self.composition_policy_provider = composition_policy_provider

    def decide_plan(self, identity: SecurityContext, proposals, *, now=None,
                    plan_id: str = "") -> AuthResult:
        """Run the complete engine over every held step, then composition policy.

        This is the safe public plan entry point. It owns per-step enforcement,
        trajectory checks, reversibility routing, and aggregate value/exposure
        checks so surfaces cannot accidentally implement a weaker plan gate.
        """
        context = coerce_context(identity)
        actions, decisions = [], []
        for index, raw in enumerate(proposals or (), 1):
            if isinstance(raw, PlanProposal):
                p = raw
            elif isinstance(raw, dict):
                p = PlanProposal(tool=raw.get("tool", ""),
                                 arguments=raw.get("arguments", {}),
                                 reason=raw.get("reason", ""),
                                 grant=raw.get("grant"),
                                 claims=raw.get("claims") or [])
            else:
                p = PlanProposal(tool="", arguments={"_invalid_plan_step": raw})
            args = p.arguments if isinstance(p.arguments, dict) else p.arguments
            fields = args if isinstance(args, dict) else {}
            rule = self.registry.tools.get(str(p.tool or ""))
            value_arg = (rule.value_arg if rule and rule.value_arg else
                         ("amount" if "amount" in fields else None))
            value = _coerce_float(fields.get(value_arg, 0) if value_arg else 0)
            action = Action(index, str(p.tool or ""),
                            str(fields.get("destination", "") or ""),
                            value if value is not None else 0.0,
                            str(p.reason or ""), arguments=dict(fields))
            d = self.decide(context, p.tool, args, reason=p.reason,
                            grant=p.grant, claims=p.claims, now=now,
                            correlation_id=f"{plan_id}:{index}" if plan_id else "",
                            plan_id=plan_id, step_id=str(index))
            actions.append(action)
            decisions.append((action, d))

        composition_policy = (self.composition_policy_provider(context)
                              if self.composition_policy_provider else
                              self.composition_policy)
        if not isinstance(composition_policy, CompositionPolicy):
            raise TypeError("composition_policy_provider must return CompositionPolicy")
        res = authorize_plan(actions, self.registry, self.state, composition_policy)
        res.engine_decisions = decisions

        hard = next(((a, d) for a, d in decisions if d.decision == BLOCK), None)
        held = next(((a, d) for a, d in decisions if d.decision == REVIEW), None)
        if hard:
            res.decision = REFUSE if res.mode == "plan-authorization" else DISCARD
            res.reasons.append(f"step {hard[0].step} failed the engine gate: {hard[1].reason}")
        elif held and res.decision in (COMMIT, AUTHORIZE):
            res.decision = HOLD
            res.reasons.append(f"step {held[0].step} needs review: {held[1].reason}")

        # Aggregate the actual configured value fields. Per-call thresholds must
        # not be evadable by splitting one value across many individually-small
        # calls of the same tool.
        totals: dict[str, float] = {}
        for action in actions:
            rule = self.registry.tools.get(action.tool)
            value_arg = rule.value_arg if rule and rule.value_arg else None
            if value_arg:
                val = _coerce_float(action.arguments.get(value_arg))
                if val is not None:
                    totals[action.tool] = totals.get(action.tool, 0.0) + abs(val)

        aggregate_hard = None
        aggregate_hold = None
        for tool, total in totals.items():
            rule = self.registry.tools.get(tool)
            if rule and rule.block_value is not None and total > rule.block_value:
                aggregate_hard = (f"aggregate {tool} value {total:,.2f} exceeds block "
                                  f"ceiling {rule.block_value:,.2f}")
                break
            if rule and rule.review_value is not None and total > rule.review_value:
                aggregate_hold = (f"aggregate {tool} value {total:,.2f} exceeds review "
                                  f"threshold {rule.review_value:,.2f}")

        # Balance/exposure is plan-wide across every conventional monetary
        # action, including tools that intentionally have no per-tool ceiling.
        total_value = sum(abs(a.amount) for a in actions
                          if isinstance(a.amount, (int, float)) and math.isfinite(a.amount))
        if self.state is not None and total_value > 0:
            balance = self.state.available_balance()
            if balance is not None and total_value > balance:
                aggregate_hard = (f"plan total {total_value:,.2f} exceeds real balance "
                                  f"{balance:,.2f}")
            if self.exposure_ceiling > 0:
                exposure = self.state.current_exposure(context.account_key) or 0.0
                if exposure + total_value > self.exposure_ceiling:
                    aggregate_hold = (f"plan exposure {exposure:,.2f}+{total_value:,.2f} "
                                      f"would exceed ceiling {self.exposure_ceiling:,.2f}")

        if aggregate_hard:
            res.decision = REFUSE if res.mode == "plan-authorization" else DISCARD
            res.reasons.append("plan accumulation: " + aggregate_hard)
        elif aggregate_hold and res.decision in (COMMIT, AUTHORIZE):
            res.decision = HOLD
            res.reasons.append("plan accumulation: " + aggregate_hold)
        return res

    def decide(self, identity: SecurityContext, tool_name: str,
               arguments: Optional[dict] = None, *,
               reason: str = "", grant: Optional[str] = None,
               claims: Optional[list[Claim]] = None, now=None,
               correlation_id: str = "", plan_id: str = "", step_id: str = "") -> PolicyDecision:
        context = coerce_context(identity)
        args_valid = arguments is None or isinstance(arguments, dict)
        args = arguments if isinstance(arguments, dict) else {}
        sig = canonical_signature(tool_name, arguments)
        confirmed = 0        # positive ground-truth confirmations (verification floor)

        # Revocation is an authoritative resolution result, not customer policy.
        # Preserve the attributed context for evidence, but block before any
        # tenant-configurable registry, state, grant, or behavioral rule runs.
        if context.revoked or context.credential_blocked:
            status = ("identity is revoked"
                      if context.attribution_status.value == "REVOKED"
                      else f"credential is {context.credential_status.value.lower()}")
            d = PolicyDecision(
                BLOCK, f"authoritative {status}",
                score=1.0, signature=sig,
                flags=[{"check": "Identity revocation", "severity": "CRITICAL"}],
            )
            self.audit.record(make_record(context, tool_name, d, executed=False,
                                          correlation_id=correlation_id,
                                          plan_id=plan_id, step_id=step_id,
                                          destination=args.get("destination", "")))
            return d

        # 1. Tool ACL + value ceiling
        d = check_tool(self.registry, tool_name, args)
        if not args_valid:
            d = merge(d, PolicyDecision(BLOCK, "arguments must be an object", score=0.9,
                                        signature=sig,
                                        flags=[{"check": "Argument schema", "severity": "HIGH"}]))

        # 1b. Ground-truth state verification (never trust the model's claims)
        sv = verify_state(self.state, context.account_key, args,
                          exposure_ceiling=self.exposure_ceiling)
        if sv is not None:
            d = merge(d, sv)
        confirmed += count_confirmations(self.state, context.account_key, args)

        # 1b-ii. Ownership binding for irreversible verbs. Granting an irreversible
        # verb ("cancel", "delete", a transfer) is NOT granting it on every
        # resource: "may cancel" is not "may cancel anything". The state port
        # answers whether the acting principal owns the target resource; a definite
        # False refuses the action even when the verb is allowed, and None means the
        # deployment cannot resolve an owner so the gate does not invent one. This is
        # the exact check the Melbourne cancel endpoint lacked, applied at
        # authorization time rather than left to the handler.
        own_rule = self.registry.tools.get(tool_name)
        if own_rule is not None and own_rule.reversible is False and self.state is not None:
            owns = getattr(self.state, "owns_resource", None)
            owned = owns(context.principal_id, tool_name, args) if callable(owns) else None
            if owned is False:
                d = merge(d, PolicyDecision(
                    BLOCK, "resource ownership: the acting principal does not own the "
                           "target resource", score=0.9, signature=sig,
                    flags=[{"check": "Resource ownership", "severity": "HIGH"}]))
            elif owned is True:
                confirmed += 1        # ownership of the target is a positive authorization

        # 1c. Grounding verification — every premise the action stands on, checked
        # against the fact port. A fabricated reference or a contradicted fact is a
        # hallucination -> BLOCK; a critical premise nobody can verify -> REVIEW.
        g_rule = self.grounding.get(tool_name)
        if g_rule is not None or claims:
            checks = ground_claims(self.facts, g_rule, args, claims or (), now=now)
            gd = decision_from_checks(checks, args)
            if gd is not None:
                d = merge(d, gd)
            confirmed += sum(1 for c in checks if c.verdict == CONFIRMED)

        # 2. Capability grant (only for grant-required tools) — fail closed
        if tool_name in self.grant_required:
            g = verify_grant(self.public_key_pem, tool_name, args, grant,
                             tenant_id=context.tenant_id,
                             replay_store=self.grant_replay_store,
                             consume=False)
            if not g.ok:
                d = merge(d, PolicyDecision(BLOCK, f"capability: {g.reason}", signature=sig))
            else:
                confirmed += 1        # a valid signed grant is a positive verification

        # 3. Behavioral reason signals
        if reason:
            hard_hits = hard_injection_hits(reason)
            if hard_hits:
                d = merge(d, PolicyDecision(
                    BLOCK, f"unsafe reason payload: {', '.join(hard_hits[:3])}",
                    score=0.9, signature=sig,
                    flags=[{"check": "Reason injection", "severity": "CRITICAL"}]))
            delta = max(0.0, sum(text_signals(reason).values()))
            if delta > 0:
                d = merge(d, PolicyDecision(band(delta), "behavioral reason signals",
                                            score=delta, signature=sig))

        # 3b. Attack memory - permanent deterministic blocklist. A confirmed attack
        # (caught once by a semantic judge or a human, outside this core) stays
        # blocked forever, along with its recase/reorder/de-leet variants. Deny-only.
        if self.deny_memory is not None:
            candidates = ([reason] if reason else []) + list(_iter_strings(args))
            fp = scan_denied(self.deny_memory, candidates)
            if fp:
                d = merge(d, PolicyDecision(
                    BLOCK, f"attack memory: matches confirmed attack fingerprint {fp[:12]}",
                    score=0.95, signature=sig,
                    flags=[{"check": "Attack memory", "severity": "CRITICAL"}]))

        # 4. Argument injection scan
        hits = scan_arguments(self.registry, tool_name, args, self.detector)
        if hits:
            d = merge(d, PolicyDecision(BLOCK, f"argument injection: {', '.join(hits[:3])}",
                                        signature=sig))

        # 5. Circuit breaker (velocity / cost / loop)
        rule = self.registry.tools.get(tool_name)
        cost = rule.cost if rule else 0.0
        b = self.breaker.check(context.breaker_key, sig, cost=cost, now=now,
                               charge_cost=False)
        if b["decision"] == "BLOCK":
            d = merge(d, PolicyDecision(BLOCK, f"circuit breaker: {b['reason']}", signature=sig))
        elif b["decision"] == "THROTTLE":
            d = merge(d, PolicyDecision(REVIEW, f"circuit breaker: {b['reason']}", signature=sig))

        # 5b. Spend budget - the operator delegates an allowance and it is enforced
        # here, not by the prompt. This action's cost is the explicit `_cost`
        # argument when the caller meters real token/compute/API spend, otherwise
        # the tool's declared unit cost. PROJECTED only (charge=False): a proposal
        # the gate refuses or holds must not draw down the allowance, so the surface
        # calls budget.charge() after a real execution, exactly like the breaker.
        if self.budget is not None:
            spend = _coerce_float(args.get("_cost"))
            if spend is None:
                spend = rule.cost if rule else 0.0
            bud = self.budget.check(context.breaker_key, spend, charge=False)
            if bud["decision"] == "BLOCK":
                d = merge(d, PolicyDecision(BLOCK, f"spend budget: {bud['reason']}", signature=sig))
            elif bud["decision"] == "REVIEW":
                d = merge(d, PolicyDecision(REVIEW, f"spend budget: {bud['reason']}", signature=sig))

        # 6. High-value verification floor - fail closed on unverified large value.
        # "No objection" is not "verified": at/above the floor, an ALLOW must carry
        # at least one POSITIVE ground-truth confirmation (state, grounding, or a
        # valid signed grant). Closes the fail-open where every ceiling passes but
        # nothing real ever vouched for the action.
        if self.verify_floor > 0 and d.decision == ALLOW:
            value_arg = (rule.value_arg if rule and rule.value_arg else "amount")
            val = _coerce_float(args.get(value_arg))
            if val is not None and abs(val) >= self.verify_floor and confirmed == 0:
                d = merge(d, PolicyDecision(
                    REVIEW, f"unverified high value: {abs(val):,.2f} at/above floor "
                            f"{self.verify_floor:,.2f} with no positive ground-truth confirmation",
                    score=0.5, signature=sig,
                    flags=[{"check": "Verification floor", "severity": "HIGH"}]))

        # This is a DECISION event, not an execution. decide() never runs the tool,
        # so it must never claim executed=True — the surface records the actual
        # execution separately (see ubag_mcp.Gateway). A prior version wrote
        # executed=d.allowed here, which fabricated "executed" rows for allowed
        # steps that a plan then discarded, and for calls whose executor later failed.
        self.audit.record(make_record(context, tool_name, d, executed=False,
                                      correlation_id=correlation_id,
                                      plan_id=plan_id, step_id=step_id,
                                      destination=args.get("destination", "")))
        return d

    def confirm_result(self, identity: SecurityContext, tool_name: str, reference: str,
                       claim: Optional[dict] = None, *, price_tolerance: float = 0.0,
                       correlation_id: str = "") -> ResultCheck:
        """Post-execution: verify what ACTUALLY happened against the system of record,
        so the agent cannot report a success (or a price) that did not occur. The
        returned `truth` is the authoritative status to feed back into the agent's
        context in place of its claim."""
        context = coerce_context(identity)
        rc = verify_result(self.result_verifier, reference, claim, price_tolerance=price_tolerance)
        self.audit.record(AuditRecord(
            ts=time.time(), agent_id=context.agent_id, tool=tool_name,
            decision=rc.verdict, reason=rc.reason, executed=False,
            signature=canonical_signature(tool_name, {"reference": reference}),
            tenant_id=context.tenant_id, principal_id=context.principal_id,
            account_id=context.account_id, credential_id=context.credential_id,
            integration_id=context.integration_id, correlation_id=correlation_id))
        return rc
