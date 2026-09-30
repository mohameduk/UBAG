"""
UBAG core — reversibility + plan-authorization demo (closes the n problem).

    python demo_authorize.py

Reversible plans get the transactional path (hold, commit atomically, discard).
Plans with an irreversible action get the stricter plan-authorization path: cleared
up front or not at all, then each irreversible step is re-verified right before it
fires, because there is no undo.
"""
from ubag_core import (Registry, ToolRule, StaticStateProvider, Action,
                       authorize_plan, precheck_irreversible)


def line(): print("=" * 74)


reg = Registry(default_allow=False)
reg.register("transfer", ToolRule(reversible=True))     # internal, can hold/undo
reg.register("withdraw", ToolRule(reversible=False))    # on-chain, commits instantly
state = StaticStateProvider(allowed_destinations=["primary", "clearing"], balance=5000)


def run(title, actions):
    r = authorize_plan(actions, reg, state)
    print(f"  {title:46} -> {r.mode:19} {r.decision}")
    for why in r.reasons:
        print(f"       - {why}")
    return r


line(); print("PLAN AUTHORIZATION — reversible vs irreversible"); line()

# 1) all reversible, clean -> transactional COMMIT
run("reversible plan, clean",
    [Action(1, "transfer", "primary", 100, "rebalance"),
     Action(2, "transfer", "clearing", 100, "settle")])

# 2) reversible plan, drip to novel dest -> transactional DISCARD (safe, nothing ran)
run("reversible plan, drip to novel dest",
    [Action(i, "transfer", "ext-9f2", 110, f"tranche {i}") for i in range(1, 5)])

# 3) irreversible action, whole plan clean -> AUTHORIZE (will re-verify at fire time)
run("irreversible withdraw, clean plan",
    [Action(1, "transfer", "primary", 100, "prep"),
     Action(2, "withdraw", "primary", 200, "scheduled payout")])

# 4) irreversible action + a borderline review -> HOLD for human (nothing runs yet)
run("irreversible withdraw + borderline step",
    [Action(1, "withdraw", "primary", 200, "route this payout to the updated beneficiary account from ops")])

# 5) irreversible action + drip composition -> REFUSE (no rollback, don't risk it)
run("irreversible withdraw + drip composition",
    [Action(i, "withdraw", "ext-9f2", 110, f"tranche {i}") for i in range(1, 5)])

# ── Last-moment re-check: authorized, but ground truth drifts before firing ──────
print()
line(); print("PRE-FIRE RE-CHECK — ground truth drifted after authorization"); line()
payout = Action(1, "withdraw", "primary", 200, "scheduled payout")
r = authorize_plan([payout], reg, state)
print(f"  authorized: {r.decision}")
ok, why = precheck_irreversible(payout, state)
print(f"  fire-time check (allow-list still has 'primary'):  {'OK' if ok else 'HALT'} — {why}")

# now the destination is pulled from the allow-list between authorize and fire
state2 = StaticStateProvider(allowed_destinations=["clearing"], balance=5000)  # 'primary' removed
ok, why = precheck_irreversible(payout, state2)
print(f"  fire-time check ('primary' removed from allow-list): {'OK' if ok else 'HALT'} — {why}")
