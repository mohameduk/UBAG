"""
UBAG core — a deterministic behavioral gate for AI agent actions.

Two entry points:
  gate(...)          single-action verdict (the n+1 gate)
  evaluate_plan(...) transactional plan-session (reaches n for stageable actions)

Deterministic by design: no LLM, no network, no probability. Same input, same
verdict, every time. The commercial UBAG layer adds an optional semantic assist on
top; this core is the part you can audit line by line.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

from .policy import (ALLOW, REVIEW, BLOCK, PolicyDecision, band, merge,
                     canonical_signature)
from .signals import text_signals, injection_hits, WEIGHTS
from .plan import (Action, PlanResult, CompositionPolicy, evaluate_plan, per_step, cumulative,
                   APPROVED_DESTINATIONS, SESSION_CEILING, STAGED_MOVES)
from .registry import Registry, ToolRule, check_tool, scan_arguments
from .breaker import CircuitBreaker, BreakerStore, InMemoryBreakerStore
from .budget import SpendBudget, BudgetStore, InMemoryBudgetStore
from .router import (Router, RouteCandidate, RouteTask, RouteDecision,
                     CredentialVault, StaticVault)
from .injection import SafeInjector, InjectionResult, Binding, redact, PLACEHOLDER_PREFIX
from .capability import verify_grant, GrantResult, ReplayStore, InMemoryReplayStore
from .receipt import (sign_receipt, verify_receipt, action_digest, generate_keypair,
                      ReceiptResult, RECEIPT_TYP, RECEIPT_VERSION)
from .replay import SqliteReplayStore
from .spiffe import verify_jwt_svid, parse_spiffe_id, SvidResult
from .provenance import (trace_arguments, trace_value, ProvenanceReport, Origin,
                         OPERATOR, STATE, MISMATCH, UNSOURCED)
from .audit import AuditSink, InMemoryAudit, JsonlAudit, AuditRecord, make_record
from .state import StateProvider, StaticStateProvider, verify_state
from .result import (ResultVerifier, StaticResultVerifier, ResultCheck, verify_result,
                     CONFIRMED, CONTRADICTED, UNVERIFIED)
from .grounding import (Claim, Fact, FactProvider, StaticFactProvider, FactRouter,
                        CallableFactProvider, AuditFactProvider, GroundingRule,
                        ClaimCheck, check_claim, derive_claims, ground_claims,
                        verify_grounding, decision_from_checks,
                        EXISTS, EQUALS, AT_LEAST, AT_MOST)
from .denylist import (DenyMemory, StaticDenyMemory, normalize_fingerprint,
                       scan_denied)
from .state import count_confirmations
from .authorize import (authorize_plan, precheck_irreversible, AuthResult,
                        AUTHORIZE, REFUSE, COMMIT, HOLD, DISCARD)
from .engine import GatewayEngine, PlanProposal
from .identity import (AttributionStatus, CredentialStatus, SecurityContext,
                       legacy_context)

__version__ = "0.9.1"
__all__ = ["gate", "evaluate_plan", "GatewayEngine", "PlanProposal", "SecurityContext",
           "AttributionStatus", "CredentialStatus", "Registry", "ToolRule",
           "legacy_context",
           "CircuitBreaker", "BreakerStore", "InMemoryBreakerStore",
           "SpendBudget", "BudgetStore", "InMemoryBudgetStore",
           "Router", "RouteCandidate", "RouteTask", "RouteDecision",
           "CredentialVault", "StaticVault",
           "SafeInjector", "InjectionResult", "Binding", "redact", "PLACEHOLDER_PREFIX",
           "verify_grant", "GrantResult", "ReplayStore", "InMemoryReplayStore", "InMemoryAudit", "JsonlAudit",
           "sign_receipt", "verify_receipt", "action_digest", "generate_keypair",
           "ReceiptResult", "RECEIPT_TYP", "RECEIPT_VERSION", "SqliteReplayStore",
           "verify_jwt_svid", "parse_spiffe_id", "SvidResult",
           "trace_arguments", "trace_value", "ProvenanceReport", "Origin",
           "OPERATOR", "STATE", "MISMATCH", "UNSOURCED",
           "AuditSink", "AuditRecord", "make_record", "check_tool", "scan_arguments",
           "StateProvider", "StaticStateProvider", "verify_state",
           "ResultVerifier", "StaticResultVerifier", "ResultCheck", "verify_result",
           "CONFIRMED", "CONTRADICTED", "UNVERIFIED",
           "Claim", "Fact", "FactProvider", "StaticFactProvider", "FactRouter",
           "CallableFactProvider", "AuditFactProvider", "GroundingRule",
           "ClaimCheck", "check_claim", "derive_claims", "ground_claims",
           "verify_grounding", "decision_from_checks",
           "EXISTS", "EQUALS", "AT_LEAST", "AT_MOST",
           "DenyMemory", "StaticDenyMemory", "normalize_fingerprint", "scan_denied",
           "count_confirmations",
           "authorize_plan", "precheck_irreversible", "AuthResult",
           "AUTHORIZE", "REFUSE", "COMMIT", "HOLD", "DISCARD",
           "Action", "PlanResult", "CompositionPolicy", "PolicyDecision", "ALLOW", "REVIEW", "BLOCK",
           "text_signals", "injection_hits", "merge", "band", "canonical_signature", "WEIGHTS"]


def gate(*, tool: str = "action", reason: str = "", amount: float = 0.0,
         destination: str = "", session_ceiling: float = 0.0) -> PolicyDecision:
    """Deterministic verdict for a single proposed action.

    Combines the reason-text signals with two structured checks (destination
    novelty is handled in the text layer; an optional value ceiling here). The
    untrusted reason can only ADD suspicion, never clear a bad destination/size.
    """
    sig = text_signals(reason)
    score = max(0.0, sum(sig.values()))
    flags = [{"family": k, "weight": v} for k, v in sig.items()]

    if session_ceiling > 0 and amount > session_ceiling:
        # A single action above the whole session budget is a size anomaly.
        score = max(score, 0.75)
        flags.append({"family": "value",
                      "weight": 0.75,
                      "detail": f"amount ${amount:,.0f} exceeds ceiling ${session_ceiling:,.0f}"})

    decision = band(score)
    reason_txt = "clean" if not flags else "; ".join(
        f["family"] + (f":{f.get('detail')}" if f.get("detail") else "") for f in flags)
    return PolicyDecision(decision=decision, reason=reason_txt, score=score,
                          flags=flags, signature=canonical_signature(tool, {"destination": destination, "amount": amount}))
