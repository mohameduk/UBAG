"""
UBAG MCP gateway - credential isolation around the FULL deterministic core.

One brain, many plugs: ubag-core is the verdict engine; this package is the MCP
surface. The agent never holds the keys. It PROPOSES a tool call; the gateway
holds the credentials and DISPOSES. On ALLOW the gateway injects the held
credential and executes; on anything else the credential is never released, so
nothing side-effects.

Every proposal runs through ubag_core.GatewayEngine, so this surface gets every
core layer - tool ACL + value ceilings, state verification, grounding
(anti-hallucination), capability grants, reason signals, attack memory, argument
injection scan, circuit breaker, high-value verification floor - and every future
core layer, with no changes here.

Three modes:
  propose(tool, args)              single call, gated immediately (n+1)
  begin_plan()/stage()/commit()    hold a whole plan; reversible plans commit with
                                   best-effort compensation, irreversible plans are
                                   authorized up front and re-verified at fire time
  confirm(tool, reference, claim)  post-execution result verification - the agent
                                   cannot invent success
  delegate(task, payload)          brokered model call: route to the cheapest
                                   compliant agent, gate it, release ONLY its vault
                                   key, execute, meter spend and latency

Audit is the core's pluggable sink, shared with the engine. decide() writes a
DECISION row (executed=False); the gateway writes a separate EXECUTION row for
each step that actually ran, so the trail never claims an execution that did not
happen.

Honest boundary on "atomic": external executors touch real systems, so a plan is
not transactional in the database sense. For REVERSIBLE tools that supply a
`compensator`, a mid-plan failure triggers best-effort rollback of the steps that
already ran. For IRREVERSIBLE tools there is no rollback: a step that has fired
cannot be pulled back, which is exactly why irreversible plans are authorized
up front and re-checked at fire time, and why a failure there aborts the rest.
"""
from __future__ import annotations

import copy
import dataclasses
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Callable, Optional, Union

from ubag_core import (Router, RouteTask, RouteDecision)
from ubag_core import (ALLOW, REVIEW, AUTHORIZE, COMMIT, HOLD, DISCARD, REFUSE,
                       AuditRecord, AuditSink, BLOCK, Claim, CircuitBreaker, SpendBudget,
                       DenyMemory, FactProvider, GatewayEngine, GroundingRule,
                       InMemoryAudit, Registry, ResultVerifier, StateProvider,
                       ToolRule, Action, PlanProposal, SecurityContext,
                       ReplayStore, CompositionPolicy, verify_grant,
                       precheck_irreversible)
from .gateway_state import GatewayStateStore, InMemoryGatewayStateStore
from .credentials import HttpArgs, judge as _judge_credentials, swap as _swap_credentials
from ubag_core import SafeInjector

ABORTED = "ABORTED"


class GatewaySecurityError(RuntimeError):
    """Fail-closed rejection for unknown or cross-context gateway handles."""


def _coerce_cost(value) -> Optional[float]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if f == f and f >= 0 else None           # reject NaN and negatives


def _redact(value, secret: Optional[str]):
    """Strip a released key from anything handed back to the agent. A provider
    that echoes the credential (an error message, a debug field) must not leak it.
    Delegates to ubag_core's redaction: dict keys, sets and escaped forms too."""
    if not secret:
        return value
    from ubag_core.injection import redact
    return redact(value, [secret], mask="[REDACTED]")


@dataclass
class Tool:
    """One executable capability. The credential lives HERE, never with the agent.
    `rule` is the full per-tool core policy (value ceilings, cost, reversibility);
    `grounding` binds its arguments to ground-truth premises; `grant_required`
    demands a signed Ed25519 capability grant on every proposal; `compensator`
    (reversible tools only) undoes a completed step for best-effort plan rollback.
    A trusted adapter that needs the authenticated identity can set
    `uses_security_context`; its executor then receives the exact context used by
    authorization and audit as a second positional argument."""
    name: str
    executor: Callable[..., object]      # the real side effect (only called after ALLOW)
    credential: Union[str, Callable[[SecurityContext], str]] = ""
    rule: Optional[ToolRule] = None
    grounding: Optional[GroundingRule] = None
    grant_required: bool = False
    compensator: Optional[Callable[[dict], object]] = None
    uses_security_context: bool = False
    allow_shared_credential: bool = False
    # HTTP-shaped tool: the agent builds the request, so a credential PLACEHOLDER
    # may ride in `http.headers` (swapped for the real key at execution, bound
    # host only). On every other tool a placeholder anywhere is a tripwire.
    http: Optional[HttpArgs] = None


AGENT_PREFIX = "agent:"


@dataclass
class ModelAgent:
    """One executor agent UBAG brokers calls to (a provider model or a local one).

    `candidate` is its routing contract (cost, latency, data classes, capabilities,
    and the vault reference of its key). `executor` makes the real model call; it
    receives the task payload plus `_credential`, the ONE key the routing decision
    released. It may return a dict carrying `_cost` (metered usage) to replace the
    projected cost when the budget and router telemetry are charged."""
    candidate: object                     # ubag_core.RouteCandidate
    executor: Callable[[dict], object]
    rule: Optional[ToolRule] = None


class Gateway:
    """The MCP enforcement point: registry + engine + credentials + plan buffers.

    Ground-truth ports and hardening knobs are passed straight through to the
    core engine; a deployment plugs its own StateProvider / FactProvider /
    DenyMemory / ResultVerifier and the surface never changes.
    """

    def __init__(self, *, state: Optional[StateProvider] = None,
                 facts: Optional[FactProvider] = None,
                 deny_memory: Optional[DenyMemory] = None,
                 result_verifier: Optional[ResultVerifier] = None,
                 verify_floor: float = 0.0, exposure_ceiling: float = 0.0,
                 public_key_pem: str = "", breaker: Optional[CircuitBreaker] = None,
                 budget: Optional[SpendBudget] = None,
                 audit: Optional[AuditSink] = None, detector=None,
                 context_provider: Optional[Callable[[], SecurityContext]] = None,
                 grant_replay_store: Optional[ReplayStore] = None,
                 composition_policy: Optional[CompositionPolicy] = None,
                 composition_policy_provider: Optional[
                     Callable[[SecurityContext], CompositionPolicy]] = None,
                 gateway_state_store: Optional[GatewayStateStore] = None,
                 router: Optional[Router] = None,
                 injector: Optional[SafeInjector] = None):
        if context_provider is None:
            raise ValueError("Gateway requires a trusted context_provider; caller-supplied "
                             "agent identifiers are not a security boundary")
        self._context_provider = context_provider
        self.registry = Registry(default_allow=False)   # unknown tools are denied
        self._tools: dict[str, Tool] = {}
        self.state = state
        self.exposure_ceiling = exposure_ceiling
        self.grant_replay_store = grant_replay_store
        self.audit = audit or InMemoryAudit()
        self.engine = GatewayEngine(
            self.registry, breaker=breaker, budget=budget, audit=self.audit,
            public_key_pem=public_key_pem, detector=detector,
            state=state, exposure_ceiling=exposure_ceiling,
            result_verifier=result_verifier, facts=facts,
            deny_memory=deny_memory, verify_floor=verify_floor,
            grant_replay_store=grant_replay_store,
            composition_policy=composition_policy,
            composition_policy_provider=composition_policy_provider)
        self.gateway_state_store = gateway_state_store or InMemoryGatewayStateStore()
        self._static_credential_tenants: dict[str, str] = {}
        # Brokered model calls. A router without a vault cannot release keys, so it
        # could only route to agents holding their own - refuse that configuration.
        if router is not None and not router.credential_bound:
            raise ValueError("Gateway router must be credential-bound (Router(vault=...)); "
                             "an agent holding its own key cannot be brokered")
        self.router = router
        self._agents: dict[str, ModelAgent] = {}
        # Credential placeholders (safe injection). With an injector attached every
        # proposal is scanned for placeholders before the engine runs.
        self.injector = injector

    def _context(self) -> SecurityContext:
        context = self._context_provider()
        if not isinstance(context, SecurityContext):
            raise TypeError("context_provider must return SecurityContext")
        return context

    @staticmethod
    def _context_key(context: SecurityContext) -> str:
        return "\x1f".join((
            context.tenant_id, context.principal_id, context.agent_id,
            context.account_id, context.credential_id, context.integration_id,
            context.attribution_status.value, context.credential_status.value,
        ))

    def _remember_execution(self, correlation_id: str, context: SecurityContext,
                            tool_name: str) -> None:
        self.gateway_state_store.remember_execution(
            correlation_id, self._context_key(context), tool_name, time.time())

    def register(self, tool: Tool) -> None:
        if tool.grant_required and self.grant_replay_store is None:
            raise ValueError(
                f"tool '{tool.name}' requires an explicit ReplayStore; use "
                "InMemoryReplayStore only for a single-process development deployment")
        self._tools[tool.name] = tool
        self.registry.register(tool.name, tool.rule or ToolRule())
        if tool.grounding is not None:
            self.engine.grounding[tool.name] = tool.grounding
        if tool.grant_required:
            self.engine.grant_required.add(tool.name)

    def _record_exec(self, context: SecurityContext, tool_name: str, event: str, note: str,
                     signature: str = "", correlation_id: str = "", plan_id: str = "",
                     step_id: str = "", executed: bool = False) -> None:
        self.audit.record(AuditRecord(
            ts=time.time(), agent_id=context.agent_id, tool=tool_name,
            decision=event, reason=note, executed=executed, signature=signature,
            tenant_id=context.tenant_id, principal_id=context.principal_id,
            account_id=context.account_id, credential_id=context.credential_id,
            integration_id=context.integration_id, correlation_id=correlation_id,
            plan_id=plan_id, step_id=step_id))

    def _credential_for(self, tool: Tool, context: SecurityContext) -> str:
        try:
            if callable(tool.credential):
                credential = tool.credential(context)
            else:
                credential = tool.credential
                # An empty credential means the trusted adapter authenticates through
                # another channel (for example a context-aware data client).  Only an
                # actual static secret is tenant-bound here.
                if credential:
                    first_tenant = self._static_credential_tenants.setdefault(
                        tool.name, context.tenant_id)
                    if (first_tenant != context.tenant_id and
                            not tool.allow_shared_credential):
                        raise GatewaySecurityError(
                            f"tool '{tool.name}' has a static credential already bound to "
                            f"tenant '{first_tenant}'; configure a context credential resolver")
        except GatewaySecurityError:
            raise
        except Exception as exc:
            raise GatewaySecurityError(
                f"credential resolver failed for tool '{tool.name}': "
                f"{type(exc).__name__}: {exc}") from exc
        if not isinstance(credential, str):
            raise GatewaySecurityError("credential resolver must return a string")
        return credential

    def _consume_grant(self, tool: Tool, args: dict, grant: Optional[str],
                       context: SecurityContext):
        if not tool.grant_required:
            return None
        consumed = verify_grant(
            self.engine.public_key_pem, tool.name, args, grant,
            tenant_id=context.tenant_id, replay_store=self.grant_replay_store,
            consume=True)
        if not consumed.ok:
            raise GatewaySecurityError("capability consumption failed: " + consumed.reason)
        return consumed

    def _charge_execution(self, tool_name: str, context: SecurityContext, now=None,
                          args: Optional[dict] = None) -> None:
        rule = self.registry.tools.get(tool_name)
        self.engine.breaker.charge(context.breaker_key, rule.cost if rule else 0.0,
                                   now=now)
        # Spend is authority: draw the real cost against the declared allowance,
        # matching what step 5b projected (the explicit `_cost` the caller metered,
        # else the tool's unit cost). Only after a real execution, so a refused or
        # held proposal never spends the budget.
        if self.engine.budget is not None:
            try:
                spend = float((args or {}).get("_cost"))
            except (TypeError, ValueError):
                spend = None
            if spend is None or spend != spend:      # missing or NaN
                spend = rule.cost if rule else 0.0
            self.engine.budget.charge(context.breaker_key, spend)

    @staticmethod
    def _run_executor(tool: Tool, payload: dict, context: SecurityContext):
        """Execute with the already-authorized context when the adapter requests it.

        The context is passed out-of-band from agent arguments, so it cannot be
        replaced by a proposal.  Resolving it once also prevents identity drift
        between authorization, execution, and the execution audit record.
        """
        if tool.uses_security_context:
            return tool.executor(payload, context)
        return tool.executor(payload)

    def _tripwire(self, context, tool_name: str, args, reason: str, correlation_id: str):
        """Credential tripwire, before the engine: a placeholder where it may not be
        refuses the call and never touches the vault. Returns (verdict, refusal)."""
        tool = self._tools.get(tool_name)
        cv = _judge_credentials(self.injector, tool_name, args, reason,
                                tool.http if tool is not None else None)
        if cv.ok:
            return cv, None
        self._record_exec(context, tool_name, "CREDENTIAL_TRIPWIRE", cv.reason,
                          correlation_id=correlation_id)
        return cv, {"decision": BLOCK, "executed": False, "reason": cv.reason,
                    "result": None, "error": None, "signature": "",
                    "flags": [{"check": "Credential tripwire", "severity": "HIGH"}],
                    "correlation_id": correlation_id, "execution_status": "NOT_ATTEMPTED",
                    "tripwire": True}

    # ── single call (n+1) ──────────────────────────────────────────────────────
    def propose(self, tool_name: str, args: Optional[dict] = None, *,
                claims: Optional[list[Claim]] = None,
                grant: Optional[str] = None, now=None) -> dict:
        """Gate one proposed tool call through EVERY core layer. Execute only on
        ALLOW; the credential is injected by the gateway, the agent never sees it.
        The exact arguments that were gated are the ones executed (a private copy),
        so nothing can be swapped between the verdict and the side effect."""
        args = copy.deepcopy({} if args is None else args)  # gate/execute same snapshot
        reason = str(args.get("reason", "") or "") if isinstance(args, dict) else ""
        context = self._context()
        correlation_id = uuid.uuid4().hex
        cv, refusal = self._tripwire(context, tool_name, args, reason, correlation_id)
        if refusal is not None:
            return refusal
        d = self.engine.decide(context, tool_name, args,
                               reason=reason,
                               grant=grant, claims=claims, now=now,
                               correlation_id=correlation_id)

        executed, result, error = False, None, None
        execution_status = "NOT_ATTEMPTED"
        tool = self._tools.get(tool_name)
        if d.decision == ALLOW and tool is not None:
            try:
                self._consume_grant(tool, args, grant, context)
                credential = self._credential_for(tool, context)
                exec_args, injected = args, None
                if cv.carries_credential and tool.http is not None:
                    injected, exec_args = _swap_credentials(self.injector, args, tool.http)
                    if not injected.ok:
                        raise GatewaySecurityError(injected.reason)
                result = self._run_executor(
                    tool, {**exec_args, "_credential": credential}, context
                )
                if injected is not None:
                    result = injected.redact(result)   # an echoed key never returns
                executed = True
                execution_status = "EXECUTED"
                self._remember_execution(correlation_id, context, tool_name)
                self._charge_execution(tool_name, context, now=now, args=args)
                self._record_exec(context, tool_name, "EXECUTED", "propose executed",
                                  d.signature, correlation_id, executed=True)
            except GatewaySecurityError as e:
                error = str(e)
                execution_status = "REFUSED"
                self._record_exec(context, tool_name, "EXECUTION_REFUSED", error,
                                  d.signature, correlation_id)
            except Exception as e:                     # executor failed AFTER authorization
                error = f"{type(e).__name__}: {e}"
                execution_status = "INDETERMINATE"
                self._record_exec(context, tool_name, "EXECUTION_INDETERMINATE",
                                  f"executor raised: {error}", d.signature, correlation_id)
        return {"decision": d.decision, "executed": executed, "reason": d.reason,
                "result": result, "error": error, "flags": d.flags, "signature": d.signature,
                "correlation_id": correlation_id, "execution_status": execution_status}

    def observe(self, tool_name: str, args: Optional[dict] = None, *,
                claims: Optional[list[Claim]] = None,
                grant: Optional[str] = None, now=None) -> dict:
        """Evaluate and durably record a proposal without enforcing the verdict.

        The returned ``decision`` is always the honest counterfactual UBAG
        decision.  ``production_action_interrupted`` is always false: the caller's
        existing production path remains authoritative in shadow mode.
        """
        args = copy.deepcopy({} if args is None else args)
        reason = str(args.get("reason", "") or "") if isinstance(args, dict) else ""
        context = self._context()
        correlation_id = uuid.uuid4().hex
        _cv, refusal = self._tripwire(context, tool_name, args, reason, correlation_id)
        if refusal is not None:
            return {"decision": BLOCK, "would_execute": False, "executed": False,
                    "execution_status": "SHADOW_NOT_ENFORCED", "operating_mode": "SHADOW",
                    "production_action_interrupted": False, "reason": refusal["reason"],
                    "flags": refusal["flags"], "signature": "",
                    "correlation_id": correlation_id, "tripwire": True}
        decision = self.engine.decide(
            context, tool_name, args, reason=reason, grant=grant, claims=claims,
            now=now, correlation_id=correlation_id)
        return {
            "decision": decision.decision,
            "would_execute": decision.decision == ALLOW and tool_name in self._tools,
            "executed": False,
            "execution_status": "SHADOW_NOT_ENFORCED",
            "operating_mode": "SHADOW",
            "production_action_interrupted": False,
            "reason": decision.reason,
            "flags": decision.flags,
            "signature": decision.signature,
            "correlation_id": correlation_id,
        }

    # ── brokered model calls (credential-bound routing) ────────────────────────
    def register_agent(self, agent: ModelAgent) -> None:
        """Make an executor agent routable AND governed. It enters the router as a
        candidate and the registry as the tool `agent:<id>`, so every call to it runs
        the full engine like any other tool. Its key stays in the router's vault."""
        if self.router is None:
            raise ValueError("register_agent needs a Gateway(router=Router(vault=...))")
        cand = agent.candidate
        if not cand.credential_ref:
            raise ValueError(f"agent '{cand.id}' names no vault credential_ref; "
                             "UBAG cannot broker an agent whose key it does not hold")
        self.router.register(cand)
        self._agents[cand.id] = agent
        self.registry.register(AGENT_PREFIX + cand.id, agent.rule or ToolRule())

    def delegate(self, task: RouteTask, payload: Optional[dict] = None, *,
                 objective: str = "cost", now=None) -> dict:
        """Route a task the planner decided to the cheapest compliant agent, then
        broker the call. The planner's reasoning is not ours; the doing is.

        1. Route: custody, compliance, capability, remaining budget / SLO, optimize.
           The remaining spend budget is filled in from the engine when attached.
        2. Gate: the call to `agent:<chosen>` runs the full engine (ACL, arg scan on
           the prompt, breaker, spend budget with the projected cost, ...).
        3. Release: only on ALLOW, the vault resolves the ONE chosen key and it is
           injected as `_credential`. Every other key stays in the vault.
        4. Meter: measured latency and cost (metered `_cost` if the executor
           returns one, else projected) feed router telemetry and the budget.
        The key is redacted from anything handed back, and never appears in audit."""
        if self.router is None:
            raise GatewaySecurityError("no router configured on this gateway")
        payload = copy.deepcopy({} if payload is None else payload)
        context = self._context()
        correlation_id = uuid.uuid4().hex
        if self.engine.budget is not None and task.budget_remaining is None:
            task = dataclasses.replace(
                task, budget_remaining=self.engine.budget.remaining(context.breaker_key))

        route = self.router.route(task, objective=objective)
        route_info = {"chosen": route.chosen, "reason": route.reason,
                      "credential_ref": route.credential_ref,
                      "withheld": list(route.withheld),
                      "projected_cost": route.projected_cost,
                      "considered": [{"id": i, "ok": ok, "why": why}
                                     for i, ok, why in route.considered]}
        base = {"executed": False, "result": None, "error": None, "route": route_info,
                "correlation_id": correlation_id, "released": None}
        if not route.routed or route.chosen not in self._agents:
            self._record_exec(context, AGENT_PREFIX + "*", "ROUTE_REFUSED", route.reason,
                              correlation_id=correlation_id)
            return {**base, "decision": BLOCK, "reason": route.reason, "flags": [],
                    "signature": "", "execution_status": "NOT_ROUTED"}

        tool_name = AGENT_PREFIX + route.chosen
        args = {**payload, "_cost": route.projected_cost}
        reason = str(payload.get("reason", "") or "")
        _cv, refusal = self._tripwire(context, tool_name, payload, reason, correlation_id)
        if refusal is not None:
            return {**base, **refusal}
        d = self.engine.decide(context, tool_name, args, reason=reason, now=now,
                               correlation_id=correlation_id)
        out = {**base, "decision": d.decision, "reason": d.reason, "flags": d.flags,
               "signature": d.signature, "execution_status": "NOT_ATTEMPTED"}
        if d.decision != ALLOW:
            return out                                   # no key leaves the vault

        agent = self._agents[route.chosen]
        key = None
        try:
            try:
                key = self.router.release(route)
            except Exception as exc:
                raise GatewaySecurityError(
                    f"vault could not release {route.credential_ref}: "
                    f"{type(exc).__name__}") from exc
            if not key:
                raise GatewaySecurityError(f"vault released no credential for "
                                           f"{route.credential_ref}")
            self._record_exec(context, tool_name, "ROUTED",
                              f"released {route.credential_ref}; withheld "
                              f"{', '.join(route.withheld) or 'none'}",
                              d.signature, correlation_id)
            t0 = time.monotonic()
            result = agent.executor({**args, "_credential": key})
            elapsed_ms = (time.monotonic() - t0) * 1000.0
        except GatewaySecurityError as e:
            self._record_exec(context, tool_name, "EXECUTION_REFUSED", str(e),
                              d.signature, correlation_id)
            return {**out, "error": str(e), "execution_status": "REFUSED"}
        except Exception as e:
            error = _redact(f"{type(e).__name__}: {e}", key)
            self._record_exec(context, tool_name, "EXECUTION_INDETERMINATE",
                              f"executor raised: {error}", d.signature, correlation_id)
            return {**out, "error": error, "execution_status": "INDETERMINATE",
                    "released": route.credential_ref}

        metered = _coerce_cost(result.get("_cost")) if isinstance(result, dict) else None
        spent = metered if metered is not None else route.projected_cost
        units = task.est_units if task.est_units and task.est_units > 0 else None
        self.router.record(route.chosen, latency_ms=elapsed_ms,
                           cost=(metered / units) if (metered is not None and units)
                           else None)
        self._remember_execution(correlation_id, context, tool_name)
        self._charge_execution(tool_name, context, now=now, args={"_cost": spent})
        self._record_exec(context, tool_name, "EXECUTED",
                          f"delegated to {route.chosen}; cost {spent:.4g}; "
                          f"{elapsed_ms:.0f}ms", d.signature, correlation_id,
                          executed=True)
        return {**out, "executed": True, "result": _redact(result, key),
                "execution_status": "EXECUTED", "released": route.credential_ref,
                "cost": spent, "latency_ms": elapsed_ms}

    # ── post-execution truth (the agent cannot invent success) ─────────────────
    def confirm(self, tool_name: str, reference: str, claim: Optional[dict] = None, *,
                correlation_id: str, price_tolerance: float = 0.0) -> dict:
        """Verify the agent's claimed outcome against the system of record and
        return the authoritative truth to feed back into its context."""
        context = self._context()
        owner = self.gateway_state_store.get_execution(correlation_id)
        if owner is None or owner[:2] != (self._context_key(context), tool_name):
            raise GatewaySecurityError("unknown or cross-context execution correlation")
        rc = self.engine.confirm_result(context, tool_name, reference, claim,
                                        price_tolerance=price_tolerance,
                                        correlation_id=correlation_id)
        return {"verdict": rc.verdict, "reason": rc.reason, "truth": rc.truth}

    # ── transactional / authorized plan (reaches n) ─────────────────────────────
    def begin_plan(self) -> str:
        """Open a plan buffer and return its session id. Pass that id to stage()
        and commit() so concurrent callers never touch each other's plan."""
        sid = uuid.uuid4().hex
        context = self._context()
        self.gateway_state_store.create_plan(
            sid, self._context_key(context), time.time())
        return sid

    def stage(self, session: str, tool_name: str, args: dict, *,
              grant: Optional[str] = None, claims: Optional[list[Claim]] = None) -> None:
        """Buffer a step. Nothing executes; the credential stays held. The args are
        DEEP-COPIED now, so mutating the caller's dict afterward cannot change what
        was validated or what will execute."""
        context = self._context()
        snap = copy.deepcopy({} if args is None else args)
        try:
            self.gateway_state_store.append_plan(
                session, self._context_key(context),
                {"tool": tool_name, "args": snap, "grant": grant,
                 "claims": [asdict(claim) for claim in (claims or [])]})
        except (KeyError, PermissionError) as exc:
            raise GatewaySecurityError(str(exc)) from exc

    def commit(self, session: str, *, now=None) -> dict:
        """Decide the WHOLE held plan, then execute.

        1. Every staged step is gated through the full engine (ACL, state,
           grounding, attack memory, floor, grant, ...); any non-ALLOW refuses it.
        2. Plan-wide accumulation (summed amounts vs real balance / exposure
           ceiling) is checked, which no per-step gate can see.
        3. authorize_plan routes by reversibility: reversible-only plans get
           COMMIT/HOLD/DISCARD; a plan with irreversible steps is authorized up
           front (AUTHORIZE/HOLD/REFUSE, stricter - no rollback net).
        4. On COMMIT/AUTHORIZE the steps run in order; each IRREVERSIBLE step is
           re-verified against current ground truth (incl. exposure) immediately
           before it fires. If an executor RAISES, reversible steps already run
           are compensated best-effort and the plan reports ABORTED.
        Credentials release only for steps that actually execute.
        """
        context = self._context()
        try:
            plan = self.gateway_state_store.pop_plan(
                session, self._context_key(context))
        except (KeyError, PermissionError) as exc:
            raise GatewaySecurityError(str(exc)) from exc
        proposals = [PlanProposal(
            item["tool"], item["args"],
            str(item["args"].get("reason", "") or "")
            if isinstance(item["args"], dict) else "",
            item.get("grant"),
            [Claim(**claim) for claim in item.get("claims", [])])
            for item in plan]
        # Credential tripwire across the whole plan, before anything is decided or
        # runs: one step leaking a placeholder refuses every step.
        plan_creds = []
        for i, item in enumerate(plan):
            cv, refusal = self._tripwire(context, item["tool"], item["args"],
                                         str(item["args"].get("reason", "") or "")
                                         if isinstance(item["args"], dict) else "",
                                         f"{session}:{i}")
            if refusal is not None:
                return {"decision": REFUSE, "mode": "credential", "steps": len(plan),
                        "executed": 0, "reasons": [f"step {i}: {refusal['reason']}"],
                        "executed_steps": [], "compensated_steps": [],
                        "uncompensated_steps": [], "compensation_failed_steps": [],
                        "indeterminate_steps": [], "irreversible_steps": [],
                        "halted_at": None, "halt_reason": "", "aborted": False,
                        "naive_would_have_run": 0, "tripwire": True}
            plan_creds.append(cv)
        # Core owns the complete plan gate. This surface only executes a core
        # decision, so new core layers cannot be omitted here by accident.
        res = self.engine.decide_plan(context, proposals, now=now, plan_id=session)
        decision, reasons = res.decision, list(res.reasons)
        irreversible = set(res.irreversible_steps)

        # naive n+1 comparison: how many steps a per-call gate would have run first
        naive = 0
        for _, band, _, _ in res.steps:
            if band == BLOCK:
                break
            naive += 1

        # 4. execute, with fire-time recheck on irreversible steps + compensation
        executed, halted_at, halt_reason, aborted = 0, None, "", False
        executed_steps: list[int] = []
        compensated_steps: list[int] = []
        compensation_failed_steps: list[int] = []
        indeterminate_steps: list[int] = []
        ran_reversible: list = []                 # (step, tool, args) for best-effort undo
        if decision in (COMMIT, AUTHORIZE):
            for index, item in enumerate(plan):
                # Use the Action constructed by the core.  It resolves each
                # tool's configured value_arg and is the exact representation
                # that was authorized.
                a = res.engine_decisions[index][0]
                tool_name, args = item["tool"], item["args"]
                if a.step in irreversible:
                    ok, why = precheck_irreversible(
                        a, self.state, agent_id=context.account_key,
                        exposure_ceiling=self.exposure_ceiling,
                        principal_id=context.principal_id)
                    if not ok:
                        aborted = True
                        halted_at, halt_reason = a.step, why
                        reasons.append(f"HALTED before step {a.step}: {why}")
                        compensated, failed = self._compensate(
                            ran_reversible, context, session)
                        compensated_steps.extend(compensated)
                        compensation_failed_steps.extend(failed)
                        if compensated:
                            reasons.append(
                                f"compensated {len(compensated)} prior reversible step(s)")
                        break
                tool = self._tools[tool_name]
                try:
                    self._consume_grant(tool, args, item.get("grant"), context)
                    exec_args = args
                    if plan_creds[index].carries_credential and tool.http is not None:
                        injected, exec_args = _swap_credentials(self.injector, args, tool.http)
                        if not injected.ok:
                            raise GatewaySecurityError(injected.reason)
                    payload = {**exec_args, "_credential": self._credential_for(tool, context)}
                except GatewaySecurityError as e:
                    aborted = True
                    halted_at = a.step
                    halt_reason = str(e)
                    reasons.append(f"REFUSED before step {a.step}: {halt_reason}")
                    self._record_exec(
                        context, tool_name, "EXECUTION_REFUSED", halt_reason,
                        correlation_id=f"{session}:{a.step}", plan_id=session,
                        step_id=str(a.step))
                    compensated, failed = self._compensate(
                        ran_reversible, context, session)
                    compensated_steps.extend(compensated)
                    compensation_failed_steps.extend(failed)
                    break
                try:
                    self._run_executor(tool, payload, context)
                except Exception as e:
                    aborted = True
                    halted_at = a.step
                    halt_reason = f"executor raised at step {a.step}: {type(e).__name__}: {e}"
                    reasons.append(halt_reason)
                    indeterminate_steps.append(a.step)
                    self._record_exec(context, tool_name, "EXECUTION_INDETERMINATE", halt_reason,
                                      correlation_id=f"{session}:{a.step}",
                                      plan_id=session, step_id=str(a.step))
                    # best-effort rollback of reversible steps already run
                    compensated, failed = self._compensate(
                        ran_reversible, context, session)
                    compensated_steps.extend(compensated)
                    compensation_failed_steps.extend(failed)
                    if compensated:
                        reasons.append(
                            f"compensated {len(compensated)} prior reversible step(s)")
                    break
                executed += 1
                executed_steps.append(a.step)
                self._remember_execution(f"{session}:{a.step}", context, tool_name)
                self._charge_execution(tool_name, context, now=now, args=a.arguments)
                self._record_exec(context, tool_name, "EXECUTED",
                                  f"plan step {a.step} executed",
                                  correlation_id=f"{session}:{a.step}",
                                  plan_id=session, step_id=str(a.step), executed=True)
                if a.step not in irreversible and tool.compensator is not None:
                    ran_reversible.append((a.step, tool, payload))

        final = ABORTED if aborted else decision
        uncompensated_steps = ([step for step in executed_steps
                                if step not in set(compensated_steps)] if aborted else [])
        return {"decision": final, "mode": res.mode, "steps": len(plan),
                "executed": executed, "reasons": reasons,
                "executed_steps": executed_steps,
                "compensated_steps": compensated_steps,
                "uncompensated_steps": uncompensated_steps,
                "compensation_failed_steps": compensation_failed_steps,
                "indeterminate_steps": indeterminate_steps,
                "irreversible_steps": res.irreversible_steps,
                "halted_at": halted_at, "halt_reason": halt_reason,
                "aborted": aborted, "naive_would_have_run": naive}

    def observe_plan(self, session: str, *, now=None) -> dict:
        """Evaluate a staged plan in shadow mode and close its session."""
        context = self._context()
        try:
            plan = self.gateway_state_store.pop_plan(
                session, self._context_key(context))
        except (KeyError, PermissionError) as exc:
            raise GatewaySecurityError(str(exc)) from exc
        proposals = [PlanProposal(
            item["tool"], item["args"],
            str(item["args"].get("reason", "") or "")
            if isinstance(item["args"], dict) else "",
            item.get("grant"),
            [Claim(**claim) for claim in item.get("claims", [])])
            for item in plan]
        result = self.engine.decide_plan(context, proposals, now=now, plan_id=session)
        return {
            "decision": result.decision,
            "would_execute": result.decision in (COMMIT, AUTHORIZE),
            "executed": 0,
            "execution_status": "SHADOW_NOT_ENFORCED",
            "operating_mode": "SHADOW",
            "production_action_interrupted": False,
            "steps": len(plan),
            "reasons": list(result.reasons),
            "step_decisions": [
                {"step": action.step, "tool": action.tool,
                 "decision": decision.decision, "reason": decision.reason,
                 "signature": decision.signature}
                for action, decision in result.engine_decisions
            ],
            "plan_id": session,
        }

    def _compensate(self, ran_reversible: list, context: SecurityContext,
                    plan_id: str) -> tuple[list[int], list[int]]:
        """Undo already-executed reversible steps in reverse order, best effort.
        Return the successfully compensated and compensation-failed step ids."""
        done: list[int] = []
        failed: list[int] = []
        for step, tool, payload in reversed(ran_reversible):
            try:
                tool.compensator(payload)
                done.append(step)
                self._record_exec(context, tool.name, "COMPENSATED",
                                  "compensated (rollback)", plan_id=plan_id,
                                  step_id=str(step))
            except Exception as e:
                failed.append(step)
                self._record_exec(context, tool.name, "COMPENSATION_FAILED",
                                  f"compensation failed: {type(e).__name__}: {e}",
                                  plan_id=plan_id, step_id=str(step))
        return done, failed
