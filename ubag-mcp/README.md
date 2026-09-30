# UBAG MCP gateway

Credential isolation and transactional commit around the [UBAG core](../ubag-core). Source available for noncommercial use and research (PolyForm Noncommercial 1.0.0).

**One brain, many plugs.** ubag-core is the verdict engine; this package is the MCP *surface*: the enforcement point a customer actually deploys. The agent **never holds the keys**. It *proposes* a tool call; the gateway holds the credentials and *disposes*. On `ALLOW` the gateway injects the held credential and executes. On anything else the credential is never released, so nothing side-effects. This is the difference from an external monitor: the agent cannot act outside the gate, because it never had the keys.

Every proposal runs through `ubag_core.GatewayEngine`, so this surface gets **every core layer** - tool ACL and value ceilings, state verification, grounding (anti-hallucination), capability grants, reason signals, attack memory, argument injection scan, circuit breaker, and the high-value verification floor - and every future core layer, with no changes here.

## Install

```bash
git clone https://github.com/mohameduk/ubag
cd ubag
pip install -e ubag-core
pip install -e ubag-mcp                  # gateway primitives
pip install -e 'ubag-mcp[pilot]'         # MCP v2 transport + PostgreSQL adapter
cd ubag-mcp && python demo.py
python -m pytest -q tests
```

## Shadow pilot

Shadow mode preserves the real counterfactual verdict but never executes or
interrupts the customer's production path:

```python
from ubag_core import JsonlAudit
from ubag_mcp import Gateway, Tool, render_shadow_report

audit = JsonlAudit("pilot-data/decisions.jsonl")
gw = Gateway(context_provider=trusted_context, audit=audit)
gw.register(Tool("payments.transfer", transfer_executor))

observation = gw.observe("payments.transfer", proposal)
# {"decision": "BLOCK", "operating_mode": "SHADOW",
#  "production_action_interrupted": False, ...}

report = render_shadow_report(audit.records())
```

Generate the customer-facing artifact with:

```bash
python -m ubag_mcp.shadow pilot-data/decisions.jsonl --output pilot-report.md
```

## MCP Streamable HTTP transport

The optional `mcp` extra uses the official MCP Python SDK and exposes shadow,
single-action, and staged-plan tools:

```python
from ubag_mcp import create_mcp_server

mcp = create_mcp_server(gw)
mcp.run(transport="streamable-http", stateless_http=True,
        json_response=True)  # default endpoint: /mcp
```

The HTTP deployment must authenticate the request and make `context_provider`
resolve that trusted request context. Tenant/principal fields are intentionally
absent from MCP tool arguments.

## Multi-worker state

Use one initialized PostgreSQL adapter for breaker events, grant consumption,
plan sessions, and result correlations:

```python
from ubag_core import CircuitBreaker
from ubag_mcp import Gateway, PostgresSecurityStore

shared = PostgresSecurityStore(connection_factory)
shared.initialize()
gw = Gateway(
    context_provider=trusted_context,
    breaker=CircuitBreaker(store=shared),
    grant_replay_store=shared,
    gateway_state_store=shared,
)
```

The default in-memory stores are single-process development options.

## Single call (the `n+1` gate)

```python
from ubag_mcp import (Gateway, Tool, ToolRule, GroundingRule,
                      StaticStateProvider, StaticFactProvider, StaticDenyMemory,
                      SecurityContext)

context = SecurityContext("acme", "operator-7", "agent-42",
                          "kraken-primary", "kraken-key-1", "kraken")

gw = Gateway(
    state=StaticStateProvider(allowed_destinations=["primary"], balance=100_000),
    facts=StaticFactProvider(entities=["order:TX123"]),
    deny_memory=my_attack_memory,          # fed by the shadow judge / human review
    verify_floor=10_000,                   # large money never moves unverified
    context_provider=lambda: context,      # derived from authenticated transport
)
gw.register(Tool("transfer", my_transfer_fn, credential="KEY_HELD_BY_GATEWAY",
                 rule=ToolRule(value_arg="amount", block_value=50_000)))
gw.register(Tool("cancel_order", my_cancel_fn, credential="KEY_HELD_BY_GATEWAY",
                 grounding=GroundingRule(ref_args={"order_id": "order"})))

proposal = gw.propose("transfer", {"amount": 50, "destination": "primary",
                                   "reason": "scale into the long"})
# -> ALLOW, executed, credential injected by the gateway

gw.propose("cancel_order", {"order_id": "TX999"})
# -> BLOCK (hallucinated reference), key never released
```

Unknown tools are denied by default. Ground-truth ports (`state`, `facts`, `result_verifier`, `deny_memory`) pass straight through to the engine, so a deployment plugs its broker / ledger / CRM once and the surface never changes.

## Transactional and authorized plans (reaches `n`)

Hold the whole plan; nothing executes until the decision. `begin_plan()` returns a **session id** so concurrent callers never share a buffer, and staged arguments are **deep-copied** so mutating the caller's dict afterward can't change what was validated or what executes:

```python
sid = gw.begin_plan()
for i in range(1, 5):
    gw.stage(sid, "transfer", {"amount": 110, "destination": "ext-9f2",
                               "reason": f"rebalance float, tranche {i} of 4"})
gw.commit(sid)
# -> {"decision": "DISCARD", "executed": 0, "naive_would_have_run": 5, ...}
```

At commit, MCP delegates the entire held plan to core's `GatewayEngine.decide_plan`: every staged step goes through the **full engine**, composition and aggregate value/exposure are checked, and reversibility is routed centrally. Reversible-only plans get COMMIT/HOLD/DISCARD; plans containing irreversible steps get AUTHORIZE/HOLD/REFUSE. Even after AUTHORIZE, each irreversible step is **re-verified against current ground truth (including exposure) immediately before it fires**.

**Honest boundary on "atomic":** external executors touch real systems, so a committed plan is all-or-nothing on the *decision*, not database-atomic on *execution*. If an executor raises mid-plan, reversible tools that supplied a `compensator` are rolled back best-effort and the result is `ABORTED`; an irreversible step that already fired cannot be pulled back, which is why irreversible plans are the ones judged up front and re-checked at fire time. The result itemizes `executed_steps`, `compensated_steps`, `uncompensated_steps`, `compensation_failed_steps`, and `indeterminate_steps` for reconciliation.

## Result confirmation (the agent cannot invent success)

```python
gw.confirm("trade", "TX-981", {"success": True, "price": 43_000},
           correlation_id=proposal["correlation_id"])
# -> {"verdict": "CONTRADICTED", "truth": {...}}   feed the truth back, not the claim
```

## The audit trail is a ground-truth source

The gateway shares the core's pluggable audit sink with the engine. That means `AuditFactProvider` works out of the box: an agent claiming "my earlier transfer went through" is checked against what this gateway actually recorded, and fabricated history blocks.

## Brokered model calls (`delegate`)

The gateway can also broker calls to other agents or models. `gw.delegate(task, payload)` routes the task to the cheapest agent the policy allows, runs the call through the full engine (ACL, argument scan on the prompt, breaker, spend budget with the projected cost), and only on ALLOW releases that one agent's key from the vault. Every other key stays put, and the key is redacted from anything handed back.

## Credentials the agent never sees

For agents that write their own HTTP, a tool can declare its request shape (`Tool(http=HttpArgs(...))`). The agent is handed a placeholder (`ubag_ph_...`) bound to one host and one header. The gateway swaps in the real key at execution time, and a placeholder that shows up anywhere else (another host, the URL, the body) blocks the call as an exfiltration attempt. See `ubag_core.injection`.

## Demos

| Folder | What it is |
|---|---|
| [`demo/console`](demo/console) | The authorization console behind [demo.ubag.ai](https://demo.ubag.ai): configure an agent's grants, then watch real verdicts from the engine, including a live model loop, the egress guard and credential placeholders. `python demo/console/server.py`, no dependencies. |
| [`demo/live`](demo/live) | A deliberately vulnerable booking service (the cancel endpoint never checks ownership) and the live agent loop that attacks it, with and without the gateway. |

## License

Copyright (c) 2026 Dixit Algorizmi Inc. Source available under the [PolyForm Noncommercial License 1.0.0](LICENSE): free for personal use, research and noncommercial organizations. Commercial use requires a separate licence from Dixit Algorizmi ([dixitalgorizmi.com](https://dixitalgorizmi.com)). Methods patent pending.

## Related

- [ubag-core](../ubag-core): the deterministic engine, with benchmark results and the measured limits.
- [AATC](https://github.com/mohameduk/aatc): Agent Action Trust Criteria, testable controls for agents that act on data and money.
