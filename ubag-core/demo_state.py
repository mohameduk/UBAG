"""
UBAG core — state verification demo (ground truth beats a good story).

    python demo_state.py

The reason text is clean and the amount looks fine, but the gate checks the REAL
allow-list and the REAL balance and stops the action anyway. Then the same State
port is satisfied by a Kraken adapter with a fake client, to show the plug works.
"""
from ubag_core import (GatewayEngine, Registry, ToolRule, StaticStateProvider,
                       evaluate_plan, Action, legacy_context)


def line(): print("=" * 74)


# The deployment's ground truth: only these destinations are allowed, real balance is 500.
state = StaticStateProvider(allowed_destinations=["house", "primary", "clearing"], balance=500)

reg = Registry(default_allow=False)
reg.register("transfer", ToolRule(cost=1.0))
eng = GatewayEngine(reg, state=state)

line(); print("SINGLE ACTION — clean reason, but ground truth says no"); line()
cases = [
    ("allowed destination",        {"destination": "primary", "amount": 100}),
    ("unlisted destination",       {"destination": "acct-x", "amount": 100}),   # text is fine, not on allow-list
    ("amount over real balance",   {"destination": "primary", "amount": 900}),  # hallucinated funds
]
for label, args in cases:
    d = eng.decide(legacy_context("agent-1"), "transfer", args, reason="rebalance the operations float")
    print(f"  {label:24} -> {d.decision:6}  {d.reason[:44]}")

# Plan-session using the real allow-list for novelty.
print()
line(); print("PLAN-SESSION — novelty judged against the REAL allow-list"); line()
to_allowed = [Action(i, "transfer", "clearing", 110, f"rebalance tranche {i}") for i in range(1, 5)]
to_unlisted = [Action(i, "transfer", "acct-x", 110, f"rebalance tranche {i}") for i in range(1, 5)]
print(f"  4 x $110 to 'clearing' (on allow-list):   {evaluate_plan(to_allowed, state).decision}")
print(f"  4 x $110 to 'acct-x'   (not allow-listed): {evaluate_plan(to_unlisted, state).decision}")

# The same port, satisfied by a Kraken adapter (fake client so it runs without keys).
print()
line(); print("KRAKEN ADAPTER — same port, real-shaped client"); line()
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adapters.kraken_state import KrakenStateProvider

class FakeKraken:
    def get_balance(self): return {"USDC": 500.0, "XXBT": 0.01}

kstate = KrakenStateProvider(FakeKraken(), quote_asset="USDC",
                             allowed_destinations=["house", "primary"])
keng = GatewayEngine(Registry(default_allow=False, tools={"transfer": ToolRule()}), state=kstate)
for label, args in [("to primary $200", {"destination": "primary", "amount": 200}),
                    ("to primary $800 (over bal)", {"destination": "primary", "amount": 800}),
                    ("to unlisted $50", {"destination": "acct-x", "amount": 50})]:
    d = keng.decide(legacy_context("agent-1"), "transfer", args, reason="settle")
    print(f"  {label:28} -> {d.decision:6}  {d.reason[:40]}")
print(f"\n  (adapter read balance: ${kstate.available_balance():,.0f} USDC)")
