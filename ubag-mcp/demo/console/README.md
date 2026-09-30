# UBAG authorization console

Two tabs, one engine, opposite directions.

**MCP gateway** governs the agent you deploy: what it may do, on which sites, with which verbs, and
what happens to the credential. **Web layer** governs the agents that arrive at your site: which
issuers you trust, what each tier may do, and whether a granted verb still binds to resources the
caller owns.

The same `ubag_core.GatewayEngine` decides both. That is the point of putting them side by side:
one brain, two plugs, two different buyers.

The configuration screen an operator fills in **before** an agent is deployed, wired to the real
[UBAG core](../../../ubag-core) engine.

```bash
python server.py          # then open http://127.0.0.1:8765
```

No dependencies beyond `ubag-core`. It resolves the sibling checkout automatically.

## What it is

Every capability starts at **NOT ALLOWED**. The operator switches on what the agent may do, and
each switch opens the detail that capability needs.

Network and data authorization is **per site, per verb**. You name a site, press Enter, and it
appears with nothing granted. Then you tick the verbs that site may be used for: `read`, `create`,
`cancel`, `execute`. A verb granted on one domain grants nothing on another, and a verb left
unticked is refused there even when it is granted somewhere else.

That is the argument. You cannot enumerate what an agent must not do. The Melbourne gym user would
have had to think of *"do not probe the cancellation endpoint for missing authorization checks"*
in advance, and nobody thinks of that. You only enumerate what you need, and `cancel` is refused
because you never had a reason to tick it.

Nothing is on a hardcoded deny list. Tick `cancel` on the gym domain and the console will happily
allow the exact action that made the news, because that is what the operator asked for. The block
is policy, not theatre, and a viewer can prove it in one click.

## Nothing on screen is hardcoded

`server.py` translates the switches into a real `Registry`, `StateProvider` and `CompositionPolicy`,
hands them to `ubag_core.GatewayEngine`, and renders what comes back. Every ALLOW / REVIEW / BLOCK
is an engine decision. Turn a switch off and the verdicts change, because the policy changed.

The right-hand column replays real incidents against the operator's own configuration:

| Scenario | Kind | What it demonstrates |
|---|---|---|
| Melbourne gym booking | incident, 10 Aug 2026 | `cancel` is refused on a domain where the operator granted `read` and `create` |
| Hugging Face intrusion | incident, Jul 2026 | Metadata addresses, unapproved destinations and secret reads are refused |
| Composition drain | pattern | Ten steps that each pass, and a sequence that does not |
| Ordinary operations | benign control | Must stay green, or the policy is unusable |
| Large but legitimate | benign control | Reaches review rather than a refusal |

Benign controls are reported with equal prominence on purpose. A gate that blocks everything is
not a result.

## The comparison that matters

Each scenario shows two columns. **Conventional per-order control** models what a
push-notification-per-order approval actually sees: the size of the order in front of it, and
nothing else. **UBAG** shows the engine verdict per step, plus the whole-plan gate.

On the composition drain that reads:

```
Conventional per-order control        UBAG
approved all 10                       sequence refused
Sees one order at a time.             All 10 passed individually.
Cannot see the sequence.              The plan gate refused the sequence.
```

Both halves are true at once, and only one of them prevents the account being emptied.

## Tests

```bash
python test_console.py      # 79/79  authorization, proposed policy
python test_limits.py       # 37/37  rate limits, spend ceiling, deployed surface
```

The matrix asserts the security claim rather than the happy path: default deny, panel isolation,
per-site verb isolation in both directions, namespace crossover, empty allow-lists failing closed,
revocation, value ceilings, and the benign controls staying usable. It also asserts that
`booking.cancel` becomes allowed once granted, so the corpus cannot quietly drift into a rigged
deny list.

An earlier version failed three of these: a destination outside every configured namespace
returned "I cannot answer" and the engine skipped the check, so an allow-list could be escaped by
renaming the target. Fixed, and the tests keep it fixed.

## Keys, safe injection and shadow are one mechanism

The credential is the thing that gates reality, so all three are views of the same axis:

| Mode | Verdict | Gateway key | Reality |
|---|---|---|---|
| enforce | BLOCK | withheld | nothing happened |
| enforce | REVIEW | withheld | nothing happened, a human decides |
| enforce | ALLOW | **released** | it happened |
| shadow | ALLOW | withheld | it happened anyway, on the agent's own credential |
| shadow | BLOCK | withheld | **it happened anyway, and now you know what it cost you** |

**Shadow puts the gateway in shadow, not the agent.** The agent keeps its own credentials and its
own path to the system, so production actions continue and UBAG is never in the way. What a pilot
buys is the record of what would have been stopped, which is why it is genuinely zero-risk rather
than rhetorically zero-risk: `production_action_interrupted` is `false` on every shadow row.

The engine is identical across both and the suite asserts the verdicts are byte-identical. The only
thing the switch changes is whether the verdict binds.

Getting this backwards is worse than a wording bug. A console that stops the agent in shadow tells
a prospect that a shadow pilot breaks their agents, which is the opposite of the thing being sold,
so `test_agent.py` asserts directly that a BLOCK in shadow still lets the stranger's booking
disappear and that the same BLOCK in enforce saves it.

**Safe injection** gets one panel on the first allowed step, three boxes side by side: what the
agent proposed (no credential field exists), what the gateway sent (the held credential, injected
at execution), and what the audit kept (a reference id, never a value). The credential appears in
exactly one of them and it is never the one that gets stored.

**The shadow report** underneath is produced by `ubag_mcp.shadow.render_shadow_report`, the same
function `python -m ubag_mcp.shadow` writes for a customer, fed by the audit sink the engine wrote
during the run. Not a mock.

**The proposed policy** below it closes the loop. Shadow says what would have happened; this says
what the operator might switch on, drafted by `ubag_mcp.recommend.propose_policy` from the same
audit records. Tick a line and it flips the real switch in the panel above, which is the whole
onboarding story in one screen: run in shadow, read the draft, tick, enforce.

What it refuses to propose is the point. An ownership violation, an injection, a breaker trip or a
destination nobody named can never become a proposal, at any frequency, because frequency is what
an attack produces. In the console's own scenarios the metadata probe (`169.254.169.254`) and the
exfiltration target (`pastebin.com`) land in "needs a decision" and never in the checklist, and the
test suite asserts exactly that.

Nothing arrives pre-ticked and nothing applies itself. Acceptance is an explicit POST carrying an
explicit list, and the server re-derives the draft before applying it, so a grant that was never
proposed is refused there too rather than trusted because it arrived in the payload.

### Honest boundary

The console has no downstream system. ENFORCE means "the gateway releases the key and the call goes
out", not that this page called anything, and the engine records `executed=False` throughout. The
credential is a placeholder reference, not a secret. What is genuinely provable here is the shape:
the proposal carries no credential, and the audit record carries an id rather than a value. The UI
says so on the panel.

## The web layer tab

Same default-deny, keyed on the issuer that vouched for the visitor rather than on the destination,
because you will never know a stranger's thumbprint in advance.

| Scenario | Visitor | What it shows |
|---|---|---|
| Melbourne gym, from the site's side | attested, read + create | The endpoint with the missing auth check is unreachable, because `cancel` was never granted |
| Trusted agent, someone else's booking | attested, read + create + cancel | A granted verb still binds to ownership |
| Untrusted issuer, confident label | attested, unknown issuer | Issuer beats `agent_class`; it lands anonymous anyway |
| Unattested automation | no credential | What a site gets before configuring anything |
| Partner agent doing its job | attested partner | Must stay green |

Two toggles prove none of it is staged. Grant `cancel` to the gym's tier and the refusal changes
from *"tool booking.cancel is not on the allow-list"* to *"'booking:4471' belongs to another
principal"*: two independent layers, both real. Turn off the ownership checkbox and the overreach
scenario goes green, because that binding is genuine policy rather than a hardcoded block.

Backed by `ubagweb.enforce` in **UBAG Edge**, which is not part of this release. Without it the
console hides this tab and the other tabs run unchanged. The hosted demo at
[demo.ubag.ai](https://demo.ubag.ai) has it.

## Running it, locally and deployed

```bash
python server.py                 # local: stdlib only, no dependencies, port 8765
uvicorn asgi:app --port 8765     # the deployed surface
```

`server.py` keeps a dependency-free stdlib server so a prospect can start this anywhere.
`asgi.py` is what actually deploys. Both call the same `dispatch_get` / `dispatch_post`, so a route
cannot exist on one and not the other, and a test asserts that.

### What a public endpoint needed that a laptop did not

A demo with a real model behind it is a bill any stranger can run up, so there are two limits and
only one of them is load-bearing. Per-IP windows are **fairness**: one visitor cannot starve the
rest. The global daily ceiling is **cost**: it counts calls rather than callers, so it holds even
when visitor attribution is defeated completely. Watch the position at `/health`.

That distinction is not theoretical. `X-Forwarded-For` is a header the caller writes, so believing
it is opt-in (`UBAG_DEMO_TRUST_PROXY`, off by default) and even when trusted the **rightmost** entry
is read, because the caller controls the left of the list and the infrastructure appends on the
right. Reading the leftmost value, which is what most examples do, hands every visitor a free
spoofing primitive.

The subtler version of the same bug was live here and the tests now prevent it: **uvicorn enables
`--proxy-headers` by default**, and with it on uvicorn rewrites `request.client` from
`X-Forwarded-For` before any application code runs. A rotating forged header bought a rotating
rate-limit bucket, and `TRUST_PROXY` never got a say. Both entry points now pass
`--no-proxy-headers`, and whether that header is believed is decided in exactly one place.

| Limit | Default | Override |
|---|---|---|
| model calls per visitor per minute | 6 | `UBAG_DEMO_MODEL_PER_MIN` |
| model calls per visitor per hour | 40 | `UBAG_DEMO_MODEL_PER_HOUR` |
| model calls per day, all visitors | 1500 | `UBAG_DEMO_MODEL_PER_DAY` |
| other API calls per visitor per minute | 120 | `UBAG_DEMO_API_PER_MIN` |

Counting is per process, which is correct for this deployment and only this one: the console runs
at `--max-instances=1` because it holds session state in memory, so per-instance and global are the
same number. Scale it out and the counters must move to a shared store. `/health` reports the
assumption rather than hiding it.

## Scope

Three capability families ship on the core tab: money, network, data. Infrastructure, external
communication and DNS are in the engine's roadmap and deliberately absent. Adding a verb means
adding it to `NETWORK_VERB_TOOLS` or `DATA_VERB_TOOLS` in `server.py`; the engine already handles
the rest.

## Licence

Copyright (c) 2026 Dixit Algorizmi Inc. PolyForm Noncommercial 1.0.0, see [LICENSE](../../LICENSE).
Use and research are free; commercial use needs a separate licence. Methods patent pending.
