"""
Rate limit and deployment-surface tests.

The claim under test: a stranger cannot run up the model bill, and cannot do it
by lying about who they are either.

Run:  python test_limits.py
"""
from __future__ import annotations

import sys

import limits
import server

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = ""):
    (PASS if condition else FAIL).append(name)
    print(f"  [{'ok  ' if condition else 'FAIL'}] {name}"
          + (f"  <- {detail}" if detail and not condition else ""))


def fresh():
    return limits.Limiter()


T = 1_770_000_000.0

# ── 1. Client attribution ────────────────────────────────────────────────────
print("\n1. Who the visitor is, and who they can pretend to be")


class H(dict):
    """Header mapping with the case-insensitive get real frameworks provide."""
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == str(key).lower():
                return v
        return default


check("the socket address is used when there is no proxy header",
      limits.client_key(H(), "203.0.113.9", trust_proxy=True) == "203.0.113.9")

check("the forwarded header is IGNORED unless a proxy is trusted",
      limits.client_key(H({"X-Forwarded-For": "1.2.3.4"}), "203.0.113.9",
                        trust_proxy=False) == "203.0.113.9",
      "a direct client can write this header, so it must not be believed")

check("trusting a proxy is off by default",
      limits.TRUST_PROXY is False)

check("behind a trusted proxy, a spoofed left-hand entry is not the identity",
      limits.client_key(H({"X-Forwarded-For": "1.2.3.4, 203.0.113.9"}), "",
                        trust_proxy=True) == "203.0.113.9")

check("every forged prefix still resolves to the same real visitor",
      len({limits.client_key(H({"X-Forwarded-For": f"{i}.{i}.{i}.{i}, 203.0.113.9"}),
                             "", trust_proxy=True) for i in range(1, 30)}) == 1,
      "a spoofing client would otherwise get a fresh budget per forged value")

check("an untrusted request cannot rotate identity by rotating the header",
      len({limits.client_key(H({"X-Forwarded-For": f"{i}.{i}.{i}.{i}"}), "203.0.113.9",
                             trust_proxy=False) for i in range(1, 30)}) == 1)

check("an absent client and header does not crash",
      limits.client_key(None, "", trust_proxy=True) == "unknown")

# ── 2. Per-visitor fairness ──────────────────────────────────────────────────
print("\n2. One visitor cannot starve the rest")

lim = fresh()
allowed = sum(1 for _ in range(limits.MODEL_PER_IP_PER_MINUTE + 4)
              if lim.check_model("a", T).allowed)
check("the per-minute model allowance is enforced",
      allowed == limits.MODEL_PER_IP_PER_MINUTE,
      f"{allowed} allowed")

check("a different visitor is unaffected by the first one's spending",
      lim.check_model("b", T).allowed)

check("a refusal explains itself and says when to come back",
      (lambda v: v.reason and v.retry_after > 0 and v.scope == "ip-minute")(
          lim.check_model("a", T)))

check("the window slides, so the visitor is not banned forever",
      lim.check_model("a", T + limits.MINUTE + 1).allowed)

lim = fresh()
for i in range(limits.MODEL_PER_IP_PER_HOUR):
    lim.check_model("a", T + i * (limits.MINUTE + 1))
check("the hourly allowance is enforced above the per-minute one",
      lim.check_model("a", T + limits.MODEL_PER_IP_PER_HOUR * (limits.MINUTE + 1)
                      ).scope == "ip-hour")

# ── 3. The ceiling that actually protects the budget ─────────────────────────
print("\n3. The bill cannot be run up, even by a visitor who cannot be identified")

lim = fresh()
spent = 0
for i in range(limits.MODEL_GLOBAL_PER_DAY + 200):
    # A new forged identity every single call: per-IP limiting is defeated
    # completely and the only thing left standing is the global ceiling.
    if lim.check_model(f"forged-{i}", T + i * 0.01).allowed:
        spent += 1
check("a rotating identity cannot exceed the daily model ceiling",
      spent == limits.MODEL_GLOBAL_PER_DAY, f"{spent} calls got through")

check("the daily refusal names its scope and is not an IP problem",
      lim.check_model("anyone", T).scope == "global-day")

check("the ceiling rolls off after a day rather than latching",
      lim.check_model("anyone", T + limits.DAY + 1).allowed)

check("the current spend position is observable",
      fresh().describe()["model_calls_per_day"] == limits.MODEL_GLOBAL_PER_DAY)

# ── 4. Cheap routes are bounded too, but separately ──────────────────────────
print("\n4. Cheap routes are bounded, and do not consume the model budget")

lim = fresh()
for _ in range(limits.API_PER_IP_PER_MINUTE):
    lim.check_api("a", T)
check("the api allowance is enforced", not lim.check_api("a", T).allowed)
check("spending the api allowance leaves the model budget untouched",
      lim.check_model("a", T).allowed and lim.describe(T)["model_calls_today"] == 1)

# ── 5. Memory does not grow without bound ────────────────────────────────────
print("\n5. A public endpoint cannot be made to leak memory")

lim = fresh()
for i in range(500):
    lim.check_api(f"visitor-{i}", T)
lim.check_api("late", T + limits.FORGET_AFTER + limits.MINUTE + 1)
check("idle visitors are forgotten",
      lim.describe()["tracked_clients"] <= 1,
      f"{lim.describe()['tracked_clients']} still tracked")

# ── 6. One routing table, two transports ─────────────────────────────────────
print("\n6. The deployed surface and the local one cannot drift apart")

import asgi                                                # noqa: E402

routed = {r.path for r in asgi.app.routes}
check("every POST route the console defines is served by the ASGI app",
      set(server.POST_ROUTES) <= routed,
      str(set(server.POST_ROUTES) - routed))
check("every GET route the console defines is served by the ASGI app",
      set(server.GET_ROUTES) <= routed,
      str(set(server.GET_ROUTES) - routed))
check("the model routes are the ones that cost money and are limited as such",
      set(server.MODEL_ROUTES) == {"/api/live/step", "/api/web/live/step",
                                    "/api/egress/step", "/api/route/run"}
      and set(server.MODEL_ROUTES) <= set(server.POST_ROUTES))
check("the platform has a health check to poll", "/health" in routed)
check("the page itself is served", "/" in routed)

# Uvicorn enables proxy headers by DEFAULT, and when it does it rewrites
# request.client from X-Forwarded-For before any application code runs. That
# hands a direct caller their own rate-limit bucket for free, and it defeats
# limits.TRUST_PROXY without touching it. The property lives in how the process
# is launched rather than in importable code, so it is asserted at the source.
from pathlib import Path                                    # noqa: E402

asgi_source = Path("asgi.py").read_text(encoding="utf-8")
docker_source = Path("Dockerfile").read_text(encoding="utf-8")

check("the python entry point disables uvicorn's proxy headers",
      "proxy_headers=False" in asgi_source,
      "uvicorn would otherwise let a caller pick their own client address")
check("the container entry point disables uvicorn's proxy headers",
      "--no-proxy-headers" in docker_source)
check("the container runs a single worker, so the spend ceiling means something",
      "--workers 1" in docker_source)
check("the container does not run as root",
      "USER demo" in docker_source)


def raises_keyerror(path):
    try:
        server.dispatch_get(path)
    except KeyError:
        return True
    return False


check("an unrouted read raises rather than answering something",
      raises_keyerror("/api/does-not-exist"))

# ── 7. End to end over real HTTP ─────────────────────────────────────────────
print("\n7. The app answers over HTTP the way the browser expects")

try:
    from starlette.testclient import TestClient
    with TestClient(asgi.app) as http:
        page = http.get("/")
        check("the console page is served with the right content type",
              page.status_code == 200 and "text/html" in page.headers["content-type"])
        check("security headers are present on every response",
              page.headers.get("X-Content-Type-Options") == "nosniff"
              and page.headers.get("X-Frame-Options") == "DENY")

        scn = http.get("/api/scenarios")
        check("the scenario catalog is served", scn.status_code == 200
              and "scenarios" in scn.json())

        proposal = http.post("/api/policy-proposal", json={"config": {
            "mode": "SHADOW",
            "network": {"enabled": True,
                        "sites": [{"name": "api.gymbooking.com.au", "verbs": ["read"]}]}}})
        check("the proposal endpoint answers over HTTP",
              proposal.status_code == 200
              and proposal.json()["draft"]["safety"]["auto_apply"] is False)

        check("an unknown route is a 404", http.get("/api/nope").status_code == 404)
        check("a malformed body is a 400, not a stack trace",
              http.post("/api/evaluate", content=b"{not json")
              .status_code == 400)
        check("a non-object payload is refused",
              http.post("/api/evaluate", json=[1, 2, 3]).status_code == 400)

        health = http.get("/health")
        check("the health check reports the spend position",
              health.status_code == 200
              and "model_calls_today" in health.json()["limits"])
except ImportError:
    print("  [skip] starlette test client not installed")


print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} passed")
if FAIL:
    print("\nfailed:")
    for f in FAIL:
        print("  -", f)
sys.exit(1 if FAIL else 0)
