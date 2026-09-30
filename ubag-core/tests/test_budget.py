"""Spend budget: the declared allowance is enforced as authority, projected at
decision time and charged only after a real execution."""
from ubag_core import GatewayEngine, Registry, SpendBudget, legacy_context
from ubag_core.budget import evaluate, ALLOW, REVIEW, BLOCK
from ubag_core.identity import coerce_context


def test_evaluate_thresholds():
    # allowance 10, soft at 8
    assert evaluate(0, 5, allowance=10, review_at=8)["decision"] == ALLOW
    assert evaluate(5, 4, allowance=10, review_at=8)["decision"] == REVIEW   # 9 >= 8
    assert evaluate(9, 5, allowance=10, review_at=8)["decision"] == BLOCK    # 14 > 10
    # exactly at the allowance is still allowed; over is blocked
    assert evaluate(6, 4, allowance=10, review_at=None)["decision"] == ALLOW  # 10 == 10
    assert evaluate(6, 4.01, allowance=10, review_at=None)["decision"] == BLOCK


def test_zero_allowance_never_stops():
    assert evaluate(1e9, 1e9, allowance=0, review_at=None)["decision"] == ALLOW


def test_review_fraction_default():
    b = SpendBudget(allowance=100)          # default review_fraction 0.8
    assert b.review_at == 80.0
    b2 = SpendBudget(allowance=100, review_fraction=1.0)  # pure hard cap
    assert b2.review_at is None


def test_project_does_not_charge():
    b = SpendBudget(allowance=10, review_fraction=1.0)
    b.check("agent", 5, charge=False)
    b.check("agent", 5, charge=False)
    assert b.store.spent("agent") == 0.0     # projection never draws down
    assert b.remaining("agent") == 10.0


def test_charge_draws_down_and_blocks_when_spent():
    b = SpendBudget(allowance=10, review_fraction=1.0)
    assert b.check("a", 6, charge=True)["decision"] == ALLOW
    assert b.remaining("a") == 4.0
    # the next action would exceed: blocked, and a blocked action is not charged
    v = b.check("a", 5, charge=True)
    assert v["decision"] == BLOCK
    assert b.remaining("a") == 4.0           # unchanged, the refusal cost nothing


def test_engine_allows_reviews_then_blocks():
    b = SpendBudget(allowance=10, review_fraction=0.8)   # review at 8
    eng = GatewayEngine(Registry(default_allow=True), budget=b)
    ctx = legacy_context("agent-1")
    scope = coerce_context(ctx).breaker_key

    d1 = eng.decide(ctx, "act", {"_cost": 5})
    assert d1.decision == ALLOW
    b.charge(scope, 5)

    d2 = eng.decide(ctx, "act", {"_cost": 4})            # projected 9 >= 8
    assert d2.decision == REVIEW
    assert "spend budget" in d2.reason
    b.charge(scope, 4)

    d3 = eng.decide(ctx, "act", {"_cost": 5})            # projected 14 > 10
    assert d3.decision == BLOCK
    assert "allowance" in d3.reason


def test_engine_without_budget_is_unaffected():
    eng = GatewayEngine(Registry(default_allow=True))    # no budget
    d = eng.decide(legacy_context("a"), "act", {"_cost": 10_000})
    assert d.decision == ALLOW


def test_cost_falls_back_to_tool_unit_cost():
    from ubag_core import ToolRule, CircuitBreaker
    reg = Registry(default_allow=True)
    reg.register("act", ToolRule(cost=6.0))
    b = SpendBudget(allowance=10, review_fraction=1.0)
    # A generous breaker so this test isolates the budget: the tool's unit cost of
    # 6 would otherwise trip the breaker's default soft budget (5) into REVIEW.
    eng = GatewayEngine(reg, budget=b,
                        breaker=CircuitBreaker(soft_budget=1e9, hard_budget=1e9))
    ctx = legacy_context("a"); scope = coerce_context(ctx).breaker_key
    # no _cost arg -> uses the tool's declared unit cost (6); 6 <= 10 allowed
    assert eng.decide(ctx, "act", {}).decision == ALLOW
    b.charge(scope, 6)
    # a second one would be 12 > 10 -> blocked
    assert eng.decide(ctx, "act", {}).decision == BLOCK
