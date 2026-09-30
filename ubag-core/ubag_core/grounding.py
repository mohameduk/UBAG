"""
Grounding verification - the premise layer (Pile B: is the action standing on facts?).

Every action an LLM proposes rests on premises: this order ID exists, this price is
what the market says, this balance covers it, this customer asked for a refund. A
hallucinated action is one whose premises fail against ground truth. This layer
decides GROUNDED / CONTRADICTED / UNVERIFIED for each premise - deterministically,
with no LLM in the path.

The trick that keeps it deterministic: the gate never parses the model's prose.
Premises come from exactly two places, both structured:

  1. DERIVED  - a per-tool `GroundingRule` binds arguments to facts mechanically:
                every reference argument (order_id, account, ticket) must EXIST in
                the system of record; every quoted value (a limit price) must match
                the live ground-truth value within a tolerance and a freshness window.
                A fabricated ID or an invented price fails here with zero NLP.
  2. DECLARED - the agent states its premises as typed `Claim`s alongside the action
                (propose/dispose: "I believe X"). Each is checked against the same
                port. An agent that declares a false belief is caught before the
                side effect; an agent that declares nothing is still covered by (1).

`FactProvider` is the universal plug, same pattern as StateProvider/ResultVerifier:
core defines the questions (`exists`, `value_of`), the deployment answers them
against its real systems, every method may return None for "I can't answer that."

Policy is fail-closed on what matters: a premise the world CONTRADICTS is a
hallucination -> BLOCK. A critical premise nobody can verify -> REVIEW. Only a
non-critical unverifiable premise is let through silently.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from .policy import BLOCK, REVIEW, PolicyDecision, canonical_signature
from .result import CONFIRMED, CONTRADICTED, UNVERIFIED

# Predicates a claim can assert about a subject. All are decidable by comparison.
EXISTS, EQUALS, AT_LEAST, AT_MOST = "EXISTS", "EQUALS", "AT_LEAST", "AT_MOST"


@dataclass
class Claim:
    """One typed factual premise: <subject> <predicate> <value>.

    subject    key the FactProvider can answer, e.g. "order:TX123", "price:BTC/USD"
    predicate  EXISTS | EQUALS | AT_LEAST | AT_MOST
    value      expected value (unused for EXISTS)
    tolerance  numeric slack for EQUALS
    max_age    seconds a fact may be old and still ground this claim (0 = no limit)
    critical   True -> UNVERIFIED escalates to REVIEW (fail closed)
    """
    subject: str
    predicate: str = EXISTS
    value: object = None
    tolerance: float = 0.0
    max_age: float = 0.0
    critical: bool = True


@dataclass
class _MissingPremise:
    """Engine-owned marker for a required argument that is absent.

    Callers may declare premises, but only the engine may synthesize a verdict
    without consulting an authoritative provider.
    """
    subject: str
    critical: bool
    reason: str
    predicate: str = EXISTS


@dataclass
class Fact:
    """A ground-truth answer: the value, and when it was true (epoch s, optional)."""
    value: object
    asof: Optional[float] = None


class FactProvider:
    """Implement the questions your deployment can answer against real systems.
    Return None for "I can't answer that" - the claim stays UNVERIFIED."""

    def exists(self, subject: str) -> Optional[bool]:
        """Does this entity exist in the system of record? None = unknown."""
        return None

    def value_of(self, subject: str) -> Optional[Fact]:
        """Current authoritative value of this subject. None = unknown."""
        return None


class StaticFactProvider(FactProvider):
    """Reference / test implementation backed by fixed entities and values."""

    def __init__(self, *, entities=None, values: Optional[dict] = None):
        self._entities = {e.lower() for e in entities} if entities is not None else None
        self._values = {}
        for k, v in (values or {}).items():
            self._values[k.lower()] = v if isinstance(v, Fact) else Fact(v)

    def exists(self, subject: str) -> Optional[bool]:
        if self._entities is None:
            return None
        return (subject or "").lower() in self._entities

    def value_of(self, subject: str) -> Optional[Fact]:
        return self._values.get((subject or "").lower())


class FactRouter(FactProvider):
    """Compose MANY systems of record into one fact source, by subject namespace.

    routes = {"order": broker_facts, "invoice": erp_facts, "price": market_facts}
    Subject "order:TX123" goes to the provider registered for "order"; the provider
    receives the full subject, so any provider works standalone or routed. A subject
    whose namespace has no provider stays unanswered (None -> UNVERIFIED). This is
    what makes grounding universal: one deployment = many unrelated systems, each
    answering only its own namespace, and core never changes.
    """

    def __init__(self, routes: Optional[dict] = None, default: Optional[FactProvider] = None):
        self.routes = {k.lower(): v for k, v in (routes or {}).items()}
        self.default = default

    def register(self, namespace: str, provider: FactProvider) -> None:
        self.routes[namespace.lower()] = provider

    def _provider_for(self, subject: str) -> Optional[FactProvider]:
        ns = (subject or "").split(":", 1)[0].strip().lower()
        return self.routes.get(ns, self.default)

    def exists(self, subject: str) -> Optional[bool]:
        p = self._provider_for(subject)
        return None if p is None else p.exists(subject)

    def value_of(self, subject: str) -> Optional[Fact]:
        p = self._provider_for(subject)
        return None if p is None else p.value_of(subject)


class CallableFactProvider(FactProvider):
    """The zero-boilerplate universal plug: wrap any two callables.

    Anything you can write as a function of the subject (a REST call, a SQL query,
    a ledger lookup, a file read) becomes a provider, no subclass needed:

        CallableFactProvider(exists_fn=lambda s: s.split(":")[1] in crm.ids(),
                             value_fn=lambda s: market.quote(s))

    `value_fn` may return None (unknown), a raw value, a (value, asof) tuple, or a
    Fact. Determinism is the deployment's contract: same subject, same answer,
    within the freshness window the GroundingRule enforces.
    """

    def __init__(self, exists_fn: Optional[Callable] = None,
                 value_fn: Optional[Callable] = None):
        self.exists_fn = exists_fn
        self.value_fn = value_fn

    def exists(self, subject: str) -> Optional[bool]:
        if self.exists_fn is None:
            return None
        v = self.exists_fn(subject)
        return None if v is None else bool(v)

    def value_of(self, subject: str) -> Optional[Fact]:
        if self.value_fn is None:
            return None
        v = self.value_fn(subject)
        if v is None:
            return None
        if isinstance(v, Fact):
            return v
        if isinstance(v, tuple) and len(v) == 2:
            return Fact(v[0], v[1])
        return Fact(v)


class AuditFactProvider(FactProvider):
    """Grounds premises about the gateway's OWN history. Universal by construction:
    every deployment has the audit trail, so no external system is needed.

    Subjects use the "audit" namespace and the canonical action signature:
        "audit:<tool>:<digest>"   (the `signature` on every PolicyDecision/record)

    exists   -> was an action with that signature ever recorded? A model claiming a
                prior step that the gateway never saw is fabricating history.
    value_of -> Fact(decision of the latest matching record, asof=its timestamp),
                so a claim like "step X was ALLOWED" is checked against what the
                gateway itself wrote, not what the model remembers.

    Works with any sink exposing a `records` list (InMemoryAudit does); a durable
    sink can duck-type the same attribute or be wrapped in a CallableFactProvider.
    """

    def __init__(self, audit):
        self.audit = audit

    def _matches(self, subject: str) -> Optional[list]:
        s = subject or ""
        if not s.lower().startswith("audit:"):
            return None                       # not our namespace: can't answer
        sig = s.split(":", 1)[1]
        recs = getattr(self.audit, "records", None) or []
        return [r for r in recs if r.signature == sig]

    def exists(self, subject: str) -> Optional[bool]:
        m = self._matches(subject)
        return None if m is None else bool(m)

    def value_of(self, subject: str) -> Optional[Fact]:
        m = self._matches(subject)
        if not m:
            return None
        last = m[-1]
        return Fact(last.decision, asof=last.ts)


@dataclass
class GroundingRule:
    """Mechanical argument->premise bindings for one tool (no NLP, no parsing).

    ref_args    {"order_id": "order"} -> the order_id argument must EXIST as
                "order:<value>" in the system of record (hallucinated-reference check)
    quote_args  {"limit_price": "price:BTC/USD"} -> the argument must EQUAL the live
                ground-truth value within `tolerance`, no older than `max_age`
                (hallucinated / stale-fact check)
    """
    ref_args: dict[str, str] = field(default_factory=dict)
    quote_args: dict[str, str] = field(default_factory=dict)
    tolerance: float = 0.0
    max_age: float = 0.0
    critical: bool = True
    # A bound argument that is absent (or blank / non-numeric) is a MISSING premise.
    # With require_args=True (default) that fails closed to UNVERIFIED instead of
    # silently emitting no claim — otherwise omitting order_id would skip the
    # existence check entirely (the "silently optional" hole).
    require_args: bool = True


@dataclass
class ClaimCheck:
    claim: Claim
    verdict: str        # CONFIRMED | CONTRADICTED | UNVERIFIED
    reason: str
    truth: object = None


def derive_claims(rule: Optional[GroundingRule], arguments: Optional[dict]) -> list[Claim]:
    """Turn a tool's argument bindings into typed claims. Purely mechanical.

    A binding whose argument is absent (or blank / non-numeric) does NOT vanish:
    with rule.require_args (default) it becomes a forced-UNVERIFIED claim so the
    missing premise fails closed instead of skipping the check."""
    if rule is None:
        return []
    args = arguments or {}
    claims: list[Claim] = []

    def _missing(arg: str, namespace_or_subject: str, kind: str) -> None:
        if rule.require_args:
            claims.append(_MissingPremise(
                f"{namespace_or_subject}", rule.critical,
                f"required {kind} argument '{arg}' is missing or blank; "
                "premise cannot be grounded"))

    for arg, namespace in rule.ref_args.items():
        v = args.get(arg)
        if v is not None and str(v).strip():
            claims.append(Claim(f"{namespace}:{str(v).strip()}", EXISTS,
                                critical=rule.critical))
        else:
            _missing(arg, f"{namespace}:<missing>", "reference")
    for arg, subject in rule.quote_args.items():
        n = _num(args.get(arg))
        if n is not None:
            claims.append(Claim(subject, EQUALS, n, tolerance=rule.tolerance,
                                max_age=rule.max_age, critical=rule.critical))
        else:
            _missing(arg, subject, "quote")
    return claims


def check_claim(provider: Optional[FactProvider], claim: Claim, *, now=None) -> ClaimCheck:
    """Decide one claim against ground truth. Deterministic comparison only."""
    if isinstance(claim, _MissingPremise):
        return ClaimCheck(claim, UNVERIFIED, claim.reason)
    if provider is None:
        return ClaimCheck(claim, UNVERIFIED, "no fact provider")

    if claim.predicate == EXISTS:
        known = provider.exists(claim.subject)
        if known is None:
            return ClaimCheck(claim, UNVERIFIED, f"'{claim.subject}': existence unknown")
        if not known:
            return ClaimCheck(claim, CONTRADICTED,
                              f"'{claim.subject}' does not exist in the system of record", False)
        return ClaimCheck(claim, CONFIRMED, f"'{claim.subject}' exists", True)

    fact = provider.value_of(claim.subject)
    if fact is None:
        return ClaimCheck(claim, UNVERIFIED, f"'{claim.subject}': no authoritative value")

    if claim.max_age > 0:
        ts = time.time() if now is None else now
        if fact.asof is None:
            return ClaimCheck(claim, UNVERIFIED,
                              f"'{claim.subject}': freshness required but fact has no timestamp",
                              fact.value)
        if ts - fact.asof > claim.max_age:
            return ClaimCheck(claim, UNVERIFIED,
                              f"'{claim.subject}': fact is {ts - fact.asof:,.0f}s old, "
                              f"max {claim.max_age:,.0f}s", fact.value)

    want, real = claim.value, fact.value
    wn, rn = _num(want), _num(real)
    if claim.predicate == EQUALS:
        if wn is not None and rn is not None:
            ok = abs(wn - rn) <= claim.tolerance
        else:
            ok = str(want).strip().lower() == str(real).strip().lower()
        if not ok:
            return ClaimCheck(claim, CONTRADICTED,
                              f"'{claim.subject}': claimed {want} but ground truth is {real}", real)
        return ClaimCheck(claim, CONFIRMED, f"'{claim.subject}' matches ground truth", real)

    if claim.predicate in (AT_LEAST, AT_MOST):
        if wn is None or rn is None:
            return ClaimCheck(claim, UNVERIFIED,
                              f"'{claim.subject}': {claim.predicate} needs numeric values")
        ok = rn >= wn if claim.predicate == AT_LEAST else rn <= wn
        if not ok:
            return ClaimCheck(claim, CONTRADICTED,
                              f"'{claim.subject}': claimed {claim.predicate} {want} but ground "
                              f"truth is {real}", real)
        return ClaimCheck(claim, CONFIRMED, f"'{claim.subject}' holds ({claim.predicate} {want})", real)

    return ClaimCheck(claim, UNVERIFIED, f"unknown predicate '{claim.predicate}'")


def ground_claims(provider: Optional[FactProvider], rule: Optional[GroundingRule],
                  arguments: Optional[dict], claims: Sequence[Claim] = (), *,
                  now=None) -> list[ClaimCheck]:
    """Full per-premise report: derived bindings first, then the agent's declarations."""
    todo = derive_claims(rule, arguments) + list(claims or [])
    return [check_claim(provider, c, now=now) for c in todo]


def verify_grounding(provider: Optional[FactProvider], arguments: Optional[dict],
                     rule: Optional[GroundingRule] = None, claims: Sequence[Claim] = (), *,
                     now=None) -> Optional[PolicyDecision]:
    """Policy verdict over every premise. Returns None when everything checkable is
    grounded; BLOCK on the first premise the world contradicts (a hallucination is
    not a judgement call); REVIEW when a critical premise cannot be verified."""
    return decision_from_checks(ground_claims(provider, rule, arguments, claims, now=now),
                                arguments)


def decision_from_checks(checks: Sequence[ClaimCheck],
                         arguments: Optional[dict] = None) -> Optional[PolicyDecision]:
    """Fold per-premise verdicts into one policy decision (see verify_grounding).
    Split out so a caller that needs the raw checks (e.g. to count CONFIRMED
    ground-truth answers) can run ground_claims itself and still get the verdict."""
    if not checks:
        return None
    sig = canonical_signature("grounding", arguments)
    flags = [{"check": f"Grounding: {c.claim.subject} {c.claim.predicate}",
              "verdict": c.verdict, "detail": c.reason} for c in checks]

    contradicted = [c for c in checks if c.verdict == CONTRADICTED]
    if contradicted:
        return PolicyDecision(BLOCK, f"hallucinated premise - {contradicted[0].reason}",
                              score=0.9, signature=sig, flags=flags)
    unverified = [c for c in checks if c.verdict == UNVERIFIED and c.claim.critical]
    if unverified:
        return PolicyDecision(REVIEW, f"critical premise unverifiable - {unverified[0].reason}",
                              score=0.5, signature=sig, flags=flags)
    return None


def _num(val) -> Optional[float]:
    """Coerce to a FINITE float, or None (NaN/inf rejected)."""
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
