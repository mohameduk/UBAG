"""
UBAG core - grounding verification demo (is the action standing on facts?).

    python demo_grounding.py

An LLM action rests on premises: this order exists, this price is what the market
says, my position count is under the limit. A hallucinated action is one whose
premises fail against ground truth. The gate never parses prose - premises are
derived mechanically from tool bindings, or declared by the agent as typed claims,
and every one is checked against the FactProvider port. Deterministic, no LLM.
"""
import time

from ubag_core import (GatewayEngine, Registry, ToolRule, StaticFactProvider,
                       legacy_context,
                       GroundingRule, Claim, Fact, AT_MOST, ground_claims,
                       FactRouter, CallableFactProvider, AuditFactProvider)


def line(): print("=" * 74)


now = time.time()

# The deployment's ground truth: which orders are real, the live BTC price (fresh),
# and how many positions are actually open.
facts = StaticFactProvider(
    entities=["order:TX123", "order:TX124"],
    values={"price:BTC/USD": Fact(43000.0, asof=now),
            "open_positions": 7},
)

reg = Registry(default_allow=False)
reg.register("cancel_order", ToolRule(cost=0.1))
reg.register("place_order", ToolRule(cost=1.0, value_arg="amount", block_value=10_000))

eng = GatewayEngine(reg, facts=facts, grounding={
    # every order_id must EXIST in the system of record
    "cancel_order": GroundingRule(ref_args={"order_id": "order"}),
    # every limit price must match the live quote within $75, no older than 60s
    "place_order": GroundingRule(quote_args={"limit_price": "price:BTC/USD"},
                                 tolerance=75, max_age=60),
})

line(); print("FABRICATED REFERENCE - the classic agent hallucination"); line()
for label, args in [("real order TX123", {"order_id": "TX123"}),
                    ("invented order TX999", {"order_id": "TX999"})]:
    d = eng.decide(legacy_context("agent-1"), "cancel_order", args, reason="cleanup stale order")
    print(f"  {label:24} -> {d.decision:6}  {d.reason[:48]}")

print()
line(); print("HALLUCINATED / STALE FACT - the price the action stands on"); line()
for label, args, t in [
        ("limit at live quote",   {"amount": 500, "limit_price": 43_020}, now),
        ("limit at invented px",  {"amount": 500, "limit_price": 51_000}, now),   # market says no
        ("live px, stale fact",   {"amount": 500, "limit_price": 43_020}, now + 600)]:
    d = eng.decide(legacy_context("agent-1"), "place_order", args, reason="scale in", now=t)
    print(f"  {label:24} -> {d.decision:6}  {d.reason[:48]}")

print()
line(); print("DECLARED CLAIMS - the agent states its beliefs, the gate checks them"); line()
false_belief = [Claim("open_positions", AT_MOST, 3)]    # reality: 7
true_belief = [Claim("open_positions", AT_MOST, 10)]
for label, claims in [("'I have <= 10 positions'", true_belief),
                      ("'I have <= 3 positions'", false_belief)]:
    d = eng.decide(legacy_context("agent-1"), "place_order", {"amount": 500, "limit_price": 43_010},
                   reason="add to winner", claims=claims, now=now)
    print(f"  {label:26} -> {d.decision:6}  {d.reason[:46]}")

print()
line(); print("PER-PREMISE REPORT - what the audit trail sees"); line()
checks = ground_claims(facts, GroundingRule(ref_args={"order_id": "order"}),
                       {"order_id": "TX999"}, false_belief, now=now)
for c in checks:
    print(f"  {c.verdict:12} {c.reason}")

# ------------------------------------------------------------------------------
# UNIVERSAL PLUG: one gateway, many unrelated systems of record. The router sends
# each subject namespace to its own provider; a provider is anything that answers
# a function, so a CRM, an ERP, a market feed, and the gateway's own audit log all
# plug in the same way. Kraken was one plug; this is the pattern.
# ------------------------------------------------------------------------------
print()
line(); print("UNIVERSAL PLUG - CRM + ERP + market feed + own audit, one router"); line()

def crm_lookup(subject):                       # stand-in for any REST/SQL call
    return subject.split(":", 1)[1] in {"CUST-7", "CUST-8"}

erp_invoices = StaticFactProvider(entities=["invoice:INV-2024-001"])
market_feed = CallableFactProvider(value_fn=lambda s: Fact(43000.0, asof=now))

ueng = GatewayEngine(Registry(default_allow=False,
                              tools={"refund": ToolRule(), "trade": ToolRule()}))
ueng.decide(legacy_context("agent-1"), "trade", {"amount": 50}, reason="scale in")  # goes into the log

router = FactRouter({
    "customer": CallableFactProvider(exists_fn=crm_lookup),
    "invoice":  erp_invoices,
    "price":    market_feed,
    "audit":    AuditFactProvider(ueng.audit),
})
ueng.facts = router
ueng.grounding = {"refund": GroundingRule(ref_args={"customer_id": "customer",
                                                    "invoice_id": "invoice"})}

for label, args in [
        ("real customer + invoice", {"customer_id": "CUST-7", "invoice_id": "INV-2024-001"}),
        ("invented customer",       {"customer_id": "CUST-99", "invoice_id": "INV-2024-001"}),
        ("invented invoice",        {"customer_id": "CUST-7", "invoice_id": "INV-9999"})]:
    d = ueng.decide(legacy_context("agent-1"), "refund", args, reason="customer requested refund")
    print(f"  {label:26} -> {d.decision:6}  {d.reason[:46]}")

# fabricated history: 'my earlier trade went through' when the gateway never saw it
prior = ueng.audit.records[0].signature
for label, subj in [("real prior action", f"audit:{prior}"),
                    ("fabricated prior action", "audit:trade:deadbeefdeadbeef")]:
    d = ueng.decide(legacy_context("agent-1"), "trade", {"amount": 60}, reason="follow-up",
                    claims=[Claim(subj)])
    print(f"  {label:26} -> {d.decision:6}  {d.reason[:46]}")
