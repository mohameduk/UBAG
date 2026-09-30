# UBAG live demo

A real model, a real gateway, and a real vulnerability, so a visitor can watch an
agent get refused and then watch the same agent succeed once they grant the verb.
Part of the UBAG demo. PolyForm Noncommercial 1.0.0, see [LICENSE](../../LICENSE).

```bash
python -m pytest tests -q          # 55 passed, no network and no API key needed
```

## What a visitor does

1. Grants verbs in the console: `read` and `create` on the gym, not `cancel`.
2. Picks a model and gives the agent a task: *"get me into the 6pm spin class."*
3. Watches it read availability, book the class, then reach for the cancellation
   endpoint and get refused.
4. Ticks `cancel` and runs it again. **The same model, the same prompt, the same
   unpatched endpoint, and now it works.** The stranger's booking disappears from
   the screen.

Step 4 is the whole demo. It proves the refusal was policy rather than a
hardcoded block, which is the first thing a sceptical viewer will assume.

## Deployment shape

Two processes on two hosts, deliberately.

| Piece | Where | Why separate |
|---|---|---|
| Console + agent loop | `demo.ubag.ai` | the product surface |
| Vulnerable booking service | `dixitalgorizmi.online` | it is intentionally broken, so it must not sit on a brand we sell from |

The gym takes the **apex**, not a subdomain, because its index page is the disclosure. Anyone who
reaches the bare domain, including a scanner, reads "this service is broken on purpose" and which
incident it reproduces, rather than a registrar parking page. The cost is DNS mechanics: an apex
cannot take a CNAME, so it needs the four A and four AAAA records Cloud Run hands you.

Two separate **registrable** domains, not two subdomains of one. Scanner findings and domain
reputation attach to the eTLD+1, so a report about the gym's missing authorization check lands on
`dixitalgorizmi.online` and can never surface in a vendor-risk review of `ubag.ai`. This is the same
reason PortSwigger hosts its deliberately vulnerable labs on `portswigger-labs.net` rather than
`portswigger.net`.

```bash
# the booking service
uvicorn gym_service:app --host 0.0.0.0 --port 9100

# the console, pointed at it
UBAG_DEMO_GYM_URL=http://127.0.0.1:9100 python ../console/server.py
```

The gym image deliberately does **not** carry `ubag-core` or `ubag-mcp`. The gym is the thing being
protected, not the thing protecting, and an exhibit meant to be defenceless should not ship with the
defence sitting in the same filesystem.

With `UBAG_DEMO_GYM_URL` set, the agent reaches the gym over **real HTTP through
the egress guard**, so the destination allow-list governs an actual network call.
Unset, the same gym runs in process for tests and local development.

The service discloses itself on every response (`X-Demo-Disclosure`), sets
`X-Robots-Tag: noindex, nofollow`, and its index page states plainly that the
missing authorization check is deliberate and which incident it reproduces. A
scanner or a passer-by cannot mistake the exhibit for an incident.

### No localhost exemption

The guard refuses `http://127.0.0.1:9100` because loopback is denied and 9100 is
not 80 or 443. That is correct and it stays. A "trust loopback" hole in a
security guard is exactly the kind of thing that ships to production by accident,
so local development uses the in-process gym instead and the guard stays
absolute. The HTTP path is covered by tests that stub the verdict, never the
guard's logic.

## The bug is real and on purpose

`gym.py` reproduces the Melbourne gym incident of 10 August 2026: the
cancellation endpoint performs no ownership check, exactly as the real one did
not. It is not patched, and it should not be. The point is not that this service
is secure. The point is that the gateway makes the defect unreachable through the
agent channel without anyone having had to predict it.

State is per session, so concurrent visitors never see each other's gym, and it
lives in memory so a restart is a clean slate.

## Any LLM, and that is the architecture rather than a slogan

`providers.py` deliberately does **not** use any vendor's native tool-calling
API. The model is asked for a JSON proposal and the gateway decides what happens
to it. UBAG gates the action, not the reasoning, so it never needs to understand
how a vendor formats a function call.

The practical consequence is that any model returning JSON works. Groq and Gemini
ship configured; with no key present the demo runs a scripted transcript that the
console labels as scripted, so a visitor with no credentials of ours still sees a
real gateway decide.

| Provider | Enable with | Default model |
|---|---|---|
| Groq | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Scripted | always available | none |

## The demo runs under the policy it demonstrates

A public demo where a stranger picks the destination and the server makes the
request is an open SSRF proxy: point it at `169.254.169.254` and you have handed
over the host's cloud credentials.

So `egress.py` judges every destination before a socket opens. Cloud metadata is
refused **even when explicitly allow-listed**, because allow-listing it
deliberately must not help. Loopback, private, link-local, CGNAT, multicast and
reserved ranges are refused. `::ffff:127.0.0.1` is recognised as loopback, so an
IPv4 address in an IPv6 costume does not slip past. A name that answers with both
a public and a private address is refused outright rather than taking the first
answer, which is the DNS-rebinding case. Only ports 80 and 443, only http and
https, and the allowed address is pinned.

Refusing a visitor's metadata probe on screen, with the reason, is a better
advertisement than any slide.

Visitors choose destinations from a curated list of real public APIs rather than
typing a URL. `tests/test_egress.py` treats this module as an attack surface, not
a helper.

## Defence in depth

The gateway refuses a metadata probe because it is not on the operator's
allow-list. `fetch()` then judges the target again itself, so a policy mistake
upstream still cannot reach the metadata service. Both layers are tested.

The destination the policy is written against is **derived**, never taken from
the model. A proposal that could name its own destination namespace could name a
permitted one.

## Cost

A public endpoint with a real model behind it is a bill any stranger can run up.
There is a per-window step limiter, a step cap per session, and bounded response
reads. Point the engine's circuit breaker at the demo itself before this goes
anywhere public.

## Licence

Copyright (c) 2026 Dixit Algorizmi Inc. PolyForm Noncommercial 1.0.0, see [LICENSE](../../LICENSE).
Use and research are free; commercial use needs a separate licence. Methods patent pending.
