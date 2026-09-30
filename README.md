# UBAG

**An authorization gateway for AI agents that act on data and money.**

The agent proposes an action; the gateway holds the credentials and decides. Every side effect is authorized before it runs, against deterministic rules you can read: which tools, which destinations, which values, which resources the caller actually owns, and how much it may spend. The agent never holds a live key, so a prompt injection has nothing to steal and no way to act outside the gate.

UBAG governs **authorization, not correctness**. It bounds what a wrong or hijacked agent can do. It does not make the agent's reasoning right.

## Evidence

On [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich), 629 attack/task pairs with `gemini-2.5-flash`:

| Arm | Attack success |
|---|---|
| Undefended agent | 47.7% |
| Deterministic gate (this repository) | 0.0% banking, 0.0% workspace, 16.4% travel, 34.3% slack |
| Gate + behavioral layer (commercial, not in this repository) | 0.64% |

The full breakdown, and the list of things we measured that **did not** work, is in [ubag-core/README.md](ubag-core/README.md#evidence).

## What is in here

| Folder | What it is |
|---|---|
| [`ubag-core/`](ubag-core) | The engine. Deterministic, no model and no network in the decision path. Tool ACL and value ceilings, state and grounding checks, signed capability grants, ownership binding, plan authorization, spend budgets, safe credential injection, the egress guard, audit and signed receipts. |
| [`ubag-mcp/`](ubag-mcp) | The gateway an operator deploys: MCP transport, credential custody, transactional plans, shadow mode, brokered model calls. |
| [`ubag-mcp/demo/`](ubag-mcp/demo) | The console behind [demo.ubag.ai](https://demo.ubag.ai) and a deliberately vulnerable booking service to attack. |

Two packages on purpose: the engine is one brain, and the MCP gateway is one of several surfaces that plug into it.

## Quick start

```bash
git clone https://github.com/mohameduk/ubag && cd ubag
pip install -e ubag-core -e ubag-mcp
python ubag-core/demo_engine.py          # every layer in one decision
python ubag-mcp/demo/console/server.py   # the console, then open http://127.0.0.1:8765
```

Tests:

```bash
pip install -r ubag-core/requirements-dev.txt
python -m pytest -q ubag-core/tests ubag-mcp/tests
```

## Related

[AATC, Agent Action Trust Criteria](https://github.com/mohameduk/aatc): 27 testable controls for agents that act on data and money. UBAG is its reference implementation.

## Licence

Copyright (c) 2026 Dixit Algorizmi Inc. Source available under the [PolyForm Noncommercial License 1.0.0](LICENSE): free for personal use, research and noncommercial organizations. Commercial use requires a separate licence from [Dixit Algorizmi](https://dixitalgorizmi.com). Methods patent pending.
