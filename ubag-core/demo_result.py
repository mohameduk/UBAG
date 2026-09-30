"""
UBAG core — result verification demo (the agent cannot invent success).

    python demo_result.py

After execution the gateway asks the system of record what ACTUALLY happened. If
the agent claims the order filled and the broker says it errored, the gateway
returns the truth, not the claim.
"""
from ubag_core import (GatewayEngine, Registry, ToolRule, StaticResultVerifier,
                       legacy_context)


def line(): print("=" * 74)


# System of record: the real status of three orders.
sor = StaticResultVerifier({
    "TX-1": {"success": True,  "price": 100.0, "filled_qty": 5},
    "TX-2": {"success": False, "error": "500 Internal Server Error", "price": 0},
    "TX-3": {"success": True,  "price": 100.0, "filled_qty": 5},
})

eng = GatewayEngine(Registry(default_allow=True), result_verifier=sor)

line(); print("RESULT VERIFICATION — claim vs system of record"); line()
cases = [
    ("claims success, really succeeded", "TX-1", {"success": True,  "price": 100.0}),
    ("claims success, really FAILED",    "TX-2", {"success": True,  "price": 100.0}),
    ("claims price 100, really 118",     "TX-3", {"success": True,  "price": 100.0},),
]
# Make TX-3 a price mismatch by telling the truth a different price:
sor._statuses["TX-3"]["price"] = 118.0

for label, ref, claim in cases:
    rc = eng.confirm_result(legacy_context("agent-1"), "place_order", ref, claim)
    print(f"  {label:34} -> {rc.verdict:12} {rc.reason[:40]}")
    print(f"       truth fed back to agent: {rc.truth}")

# Kraken adapter satisfies the same ResultVerifier port (fake client with query_order).
print()
line(); print("KRAKEN ADAPTER — same port, real-shaped order query"); line()
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adapters.kraken_state import KrakenStateProvider

class FakeKraken:
    def get_balance(self): return {"USDC": 500.0}
    def query_order(self, txid):
        return {"OABC": {"status": "canceled", "reason": "Insufficient funds", "vol_exec": 0, "price": 0}}.get(
            txid, {"status": "closed", "vol_exec": 0.05, "price": 62000})

kstate = KrakenStateProvider(FakeKraken())
keng = GatewayEngine(Registry(default_allow=True), result_verifier=kstate)
for ref, claim in [("OXYZ", {"success": True}), ("OABC", {"success": True})]:
    rc = keng.confirm_result(legacy_context("agent-1"), "place_order", ref, claim)
    print(f"  order {ref}: agent claims filled -> {rc.verdict:12} {rc.reason[:44]}")
