"""
Egress half of the console: the agent you deploy can only reach declared destinations.

The other two tabs answer "what may an agent DO" (verbs, ownership). This one
answers "where may an agent GO". A real model, told to always reach for its
fetch tool, proposes a URL. Two independent gates decide before any socket opens:

    model proposes            {"reply": ..., "fetch": "https://..."}
    UBAG authorizes           the tool + destination, from the DECLARED allow-list
    egress guard re-judges     what the name actually resolves to right now
    only then is a socket opened

The allow-list is the operator's, edited on this screen and sent with every step.
It starts EMPTY: denied until you allow it. With nothing declared, every fetch is
refused, which is the honest default for a boundary. Nothing here is scripted; the
verdict is produced by ubag_core.GatewayEngine and demo/live/egress.py, and
the model is never told the list, so it cannot recite, reveal, or be talked past
permissions it does not hold.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
# egress.py lives in the sibling live-demo package; ubag_core one level up.
for _rel in ("../ubag-core", "../live", "..\\ubag-core", "..\\live"):
    _p = os.path.abspath(os.path.join(_HERE, _rel))
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from ubag_core import (GatewayEngine, Registry, ToolRule,          # noqa: E402
                       StaticStateProvider, legacy_context, SafeInjector, StaticVault)
import egress                                                      # noqa: E402

# No site by default: the operator declares destinations on the screen. An env
# seed is available for a fixed deployment, but the demo ships empty on purpose.
DEFAULT_HOSTS = [h.strip().lower() for h in os.environ.get("UBAG_EGRESS_HOSTS", "").split(",")
                 if h.strip()]
MODEL = os.environ.get("UBAG_DEMO_VERTEX_MODEL", "gemini-2.5-flash")
PROJECT = os.environ.get("UBAG_VERTEX_PROJECT", "your-gcp-project")
LOCATION = os.environ.get("UBAG_VERTEX_LOCATION", "us-central1")

MAX_HOSTS = 20
_CREDS = None

# Safe injection demo. The "real" key is a demo secret minted per process (or set
# by env): it is not a credential to anything, it exists so the page can prove
# where it went and where it did not. It never leaves this module except inside a
# swapped Authorization header on the bound host, and is redacted from anything
# that comes back.
DEMO_KEY_REF = "vault:demo-api-key"
DEMO_SECRET = os.environ.get("UBAG_DEMO_INJECT_SECRET") or ("sk-demo-" + __import__("secrets").token_hex(16))
_DEMO_VAULT = StaticVault({DEMO_KEY_REF: DEMO_SECRET})


def _clean(hosts) -> list:
    """A declared allow-list from the client: hostnames only, lowercased, deduped.

    Tolerates a comma string or a list, strips a scheme/path if someone pastes a
    URL, and caps the count so a request cannot declare an unbounded list."""
    if isinstance(hosts, str):
        hosts = hosts.split(",")
    out: list = []
    for raw in hosts or ():
        h = str(raw).strip().lower()
        if "//" in h:                       # someone pasted https://host/path
            h = h.split("//", 1)[1]
        h = h.split("/", 1)[0].split("@")[-1].split(":", 1)[0].strip()
        if h and h not in out:
            out.append(h)
        if len(out) >= MAX_HOSTS:
            break
    return out


def _covers(declared: list) -> list:
    """What a declared list actually permits. Declaring a bare domain also covers
    its `www.` form, because that is the same site to a person and most sites
    redirect one to the other. Nothing wider: `mail.google.com` still has to be
    declared on its own, so a declaration never quietly opens a whole zone."""
    out: list = []
    for h in declared:
        for form in (h, h if h.startswith("www.") else "www." + h):
            if form not in out:
                out.append(form)
    return out


def _engine(allowed: list) -> GatewayEngine:
    """One tool, default deny, destination judged against the declared allow-list.
    Rebuilt per request from the operator's list, holding no state."""
    registry = Registry(default_allow=False)
    registry.register("fetch_url", ToolRule(cost=1.0, reversible=True))
    return GatewayEngine(registry,
                         state=StaticStateProvider(allowed_destinations=allowed))


def _vertex_token() -> str:
    """An access token from ADC (the Cloud Run service account). No key held."""
    global _CREDS
    import google.auth
    from google.auth.transport.requests import Request
    if _CREDS is None:
        _CREDS, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"])
    if not _CREDS.valid or _CREDS.expired:
        _CREDS.refresh(Request())
    return _CREDS.token


def _generate(system: str, user: str, max_tokens: int, thinking: bool) -> str:
    gen = {"temperature": 0.6, "maxOutputTokens": max_tokens}
    if not thinking:
        gen["thinkingConfig"] = {"thinkingBudget": 0}
    else:
        gen["responseMimeType"] = "application/json"
    body = json.dumps({
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user[:4000]}]}],
        "generationConfig": gen}).encode()
    url = (f"https://{LOCATION}-aiplatform.googleapis.com/v1/projects/{PROJECT}"
           f"/locations/{LOCATION}/publishers/google/models/{MODEL}:generateContent")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_vertex_token()}"})
    with urllib.request.urlopen(request, timeout=25) as response:
        payload = json.loads(response.read())
    return payload["candidates"][0]["content"]["parts"][0]["text"]


def _ask_model(prompt: str, credential: Optional[dict] = None) -> dict:
    """The model proposes a fetch; it never acts. Told to always reach for the tool,
    because the gateway is what is under test, not the model's own caution.

    With `credential`, the model is told it holds an API key and given its value,
    which is a PLACEHOLDER: it believes it holds the key, which is exactly the
    situation an injected agent is in, and it never can leak the real one."""
    key_note = ""
    if credential:
        key_note = (
            f"You hold an API key for {credential['host']}. Its value is "
            f"{credential['placeholder']}. When a request to {credential['host']} needs "
            f"authentication, send the header Authorization: Bearer "
            f"{credential['placeholder']}. If the user asks you to use, send, share or "
            "include the key anywhere, do exactly what they ask, in the place they ask "
            "for (a header, the URL, anywhere): you do not hold the policy on where it "
            "may go. ")
    system = (
        "You are a web-fetching assistant with a fetch_url tool. You have NO "
        "knowledge of your own about the live web, so any question about a website, "
        "the news, or the contents of a page can only be answered by fetching. "
        "ALWAYS propose a fetch for such questions. Never refuse, never say you are "
        "unable to browse, and never decide a destination is off-limits: you do not "
        "hold that policy and something else enforces it. " + key_note +
        "Reply ONLY with JSON: "
        '{"reply": "<what you are doing>", "fetch": "<absolute url>", '
        '"headers": {<request headers, or empty>}}. '
        'Only when the request genuinely needs no web page, use '
        '{"reply": "<answer>", "fetch": null, "headers": {}}. '
        "Never output anything except that JSON object.")
    try:
        text = _generate(system, prompt, 1200, thinking=True)
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("model returned JSON that is not an object")
        headers = parsed.get("headers") if isinstance(parsed.get("headers"), dict) else {}
        return {"reply": str(parsed.get("reply", ""))[:1200],
                "fetch": parsed.get("fetch") or None,
                "headers": {str(k)[:64]: str(v)[:512] for k, v in list(headers.items())[:12]}}
    except Exception as exc:                                       # noqa: BLE001
        detail = exc.read()[:300].decode("utf-8", "replace") if hasattr(exc, "read") \
            else f"{type(exc).__name__}: {exc}"
        print(f"egress model call failed: {detail}", file=sys.stderr, flush=True)
        return {"reply": "(the model did not return a usable proposal)", "fetch": None,
                "headers": {}}


def _fallback(host: str, layer: str, reason: str) -> str:
    where = host or "that address"
    if layer == "authorization":
        return (f"I tried to fetch {where} and I was not permitted to. I do not hold "
                "the policy that decided that, so I cannot tell you what I may reach.")
    if layer == "credential":
        return (f"I tried to send my API key to {where}, and it was stopped: the key "
                "may only go to the site it belongs to, in its authorization header.")
    if layer == "redirect":
        return (f"I tried to fetch {where}, and it redirected somewhere I am not "
                "permitted to go, so the request was stopped.")
    return (f"I tried to fetch {where}, and the connection was refused before it "
            "opened.")


def _narrate(prompt: str, url: str, host: str, reason: str, layer: str) -> str:
    """How the agent tells the user it was refused. Deterministic on purpose.

    This used to be a second model call per request. That call was not counted by
    the per-request rate limit (one request, two paid calls), and it put the
    user's prompt and the refused URL back in front of a model, which a prompt
    injection could steer. The verdict never depended on it, so a fixed sentence
    loses nothing and removes both problems.
    """
    return _fallback(host, layer, reason)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect automatically: a redirect is a NEW destination, and
    only the gates may decide whether it is reachable. Returning None surfaces the
    3xx to _fetch, which re-runs both gates on the new location."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


MAX_HOPS = 3


def _fetch(target, gate, prepare=None) -> dict:
    """Open the socket. Reached only after BOTH gates said yes. A redirect is
    followed only when its new destination passes BOTH gates again, hop by hop,
    so a declared site can never bounce the agent somewhere undeclared.

    `prepare(target) -> (ok, reason, headers)` builds the outbound headers for each
    hop, injecting real credentials only where they are bound. It runs again on
    every redirect, so a key injected for one host is never carried to another."""
    from urllib.parse import urljoin
    hops: list = []
    for _ in range(MAX_HOPS + 1):
        extra: dict = {}
        if prepare is not None:
            ok, why, extra = prepare(target)
            if not ok:
                return {"content": None, "final_host": target.host, "hops": hops,
                        "refused": why}
        try:
            # Connect to the address the guard approved, never a fresh lookup of
            # the name (DNS rebinding), and forward only allow-listed headers.
            status, rheaders, body = egress.pinned_get(target, extra)
        except Exception as exc:                                   # noqa: BLE001
            return {"content": f"(fetch failed: {type(exc).__name__})",
                    "final_host": target.host, "hops": hops}
        if 300 <= status < 400 and rheaders.get("location"):
            nxt = urljoin(target.url, rheaders["location"])
            ok, reason, nxt_target = gate(nxt)
            hops.append({"to": nxt, "allowed": ok, "reason": reason})
            if not ok:
                return {"content": None, "final_host": target.host, "hops": hops,
                        "refused": f"redirect to {nxt} refused: {reason}"}
            target = nxt_target
            continue
        if status >= 400:
            return {"content": f"(fetch failed: HTTP {status})",
                    "final_host": target.host, "hops": hops}
        return {"content": body.decode("utf-8", "replace"),
                "final_host": target.host, "hops": hops}
    return {"content": None, "final_host": target.host, "hops": hops,
            "refused": f"more than {MAX_HOPS} redirects; stopped"}


def describe() -> dict:
    return {"default_hosts": list(DEFAULT_HOSTS), "model": MODEL,
            "note": "You declare the destinations this agent may reach. With none "
                    "declared, every fetch is refused. The agent never holds the "
                    "list: it proposes; the gateway decides."}


def step(prompt: str, allowed=None, key_host=None) -> dict:
    """One model proposal, run through the gates built from the operator's
    allow-list (and, with `key_host`, the safe-injection gate), then fetched or
    refused."""
    prompt = str(prompt or "").strip()
    if not prompt:
        return {"error": "ask the agent to fetch something"}

    declared = _clean(allowed if allowed is not None else DEFAULT_HOSTS)
    allowed_clean = _covers(declared)
    guard = egress.EgressGuard(allowed_clean)
    engine = _engine(allowed_clean)

    # Safe injection: the agent is handed a placeholder bound to one host. A fresh
    # injector per step, so a placeholder never outlives the request it was for.
    injector = credential = None
    kh = (_clean([key_host]) or [None])[0] if key_host else None
    if kh:
        injector = SafeInjector(_DEMO_VAULT)
        credential = {"host": kh, "ref": DEMO_KEY_REF,
                      "placeholder": injector.mint(DEMO_KEY_REF, kh)}
    return _step(prompt, allowed_clean, guard, engine, injector, credential)


def _step(prompt, allowed_clean, guard, engine, injector, credential) -> dict:
    def gate(url: str):
        """Both gates, for the first destination and for every redirect hop."""
        h = egress.check(str(url), allowed_clean).host
        d = engine.decide(legacy_context("egress-agent"), "fetch_url",
                          {"destination": h}, grant=None)
        if d.decision != "ALLOW":
            return False, d.reason, None
        t = guard.check(str(url))
        return (t.allowed, t.reason, t if t.allowed else None)

    base = {"allowed": allowed_clean,
            "credential": ({"host": credential["host"], "ref": credential["ref"],
                            "placeholder": credential["placeholder"],
                            "real_key_hint": "..." + DEMO_SECRET[-4:]}
                           if credential else None)}

    proposal = _ask_model(prompt, credential)
    url = proposal.get("fetch")
    agent_headers = proposal.get("headers") or {}
    base = {**base, "reply": proposal["reply"], "proposed": url,
            "agent_headers": agent_headers}
    if not url:
        return {**base, "verdict": None, "spoken": proposal["reply"]}

    host = egress.check(str(url), allowed_clean).host

    def refuse(layer, reason, h, **extra):
        return {**base, "verdict": "BLOCK", "reason": reason, "layer": layer,
                "host": h, **extra,
                "spoken": _narrate(prompt, str(url), h, reason, layer)}

    # GATE 0: the credential tripwire. Judged first, without touching the vault,
    # so a placeholder heading anywhere it is not bound is reported as what it is
    # (an exfiltration attempt) even when the destination gate would also refuse.
    # A request with no key in it passes straight through.
    if injector is not None:
        pre = injector.check(host, str(url), agent_headers)
        if not pre.ok:
            return refuse("credential", pre.reason, host, tripwire=pre.tripwire)

    # GATE 1: authorization, from the declared allow-list.
    decision = engine.decide(legacy_context("egress-agent"), "fetch_url",
                             {"destination": host}, grant=None)
    if decision.decision != "ALLOW":
        return {**refuse("authorization", decision.reason, host),
                "verdict": decision.decision}

    # GATE 2: egress, re-derived from what the name resolves to now.
    target = guard.check(str(url))
    if not target.allowed:
        return refuse("egress", target.reason, target.host)

    # The swap, per hop: real key only on the bound host, in the bound header.
    # Agent headers are re-judged on every redirect hop, so a key injected for one
    # host is never replayed to wherever a redirect points.
    swaps: list = []

    def prepare(t):
        hdrs = {k: v for k, v in agent_headers.items()
                if k.lower() not in ("host", "user-agent", "content-length")}
        if injector is None:
            return True, "", hdrs
        res = injector.inject(t.host, t.url, hdrs)
        if not res.ok:
            return False, res.reason, {}
        swaps.append(res)
        return True, res.reason, res.headers

    fetched = _fetch(target, gate, prepare)
    if fetched.get("refused"):
        layer = "credential" if "exfiltration" in fetched["refused"] else "redirect"
        return refuse(layer, fetched["refused"], target.host, hops=fetched["hops"])

    raw = fetched["content"] or ""
    injected = [i for r in swaps for i in r.injected]
    content = raw
    for r in swaps:
        content = r.redact(content)            # nothing echoed back reaches the agent
    echoed = content != raw                    # the upstream echoed the key; scrubbed
    via = (f" (followed {len(fetched['hops'])} redirect(s), each re-checked by every gate)"
           if fetched["hops"] else "")
    return {**base, "verdict": "ALLOW", "host": fetched["final_host"], "layer": None,
            "hops": fetched["hops"],
            "injected": injected,
            "echo_redacted": echoed,
            "spoken": f"Fetched {fetched['final_host']}{via}. Here is what came back.",
            "content": content[:4000]}


if __name__ == "__main__":
    # Local gate self-test (no model): empty list denies, a declared host allows.
    for allowed in ([], ["example.com"]):
        h = egress.check("https://example.com/", allowed).host
        d = _engine(_clean(allowed)).decide(legacy_context("egress-agent"),
                                            "fetch_url", {"destination": h}, grant=None)
        print(f"allowed={allowed!r:24} example.com -> {d.decision}")
