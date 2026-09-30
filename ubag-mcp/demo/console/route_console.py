"""
Routing tab of the console: deterministic execution routing.

The planner (the customer's strongest model) decides WHAT a task is. This decides
WHO executes it: the cheapest agent that is compliant for the task's data class,
has the required capability, and meets the latency budget. The verdict is the
shipped ubag_core.Router, the same code a deployment uses. The interesting column
is compliance: a task carrying regulated data is refused every third-party agent
and pinned to the on-prem one, before cost is even considered.

`route()` is the decision alone (free, instant). `run()` brokers a real call
through ubag_mcp Gateway.delegate: route, full engine gate on the task, release
one live token, call the model, report real latency and tokens.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.path.join(_HERE, "..", "ubag-core"), os.path.join(_HERE, "..\\ubag-core")):
    if os.path.isdir(_c) and os.path.abspath(_c) not in sys.path:
        sys.path.insert(0, os.path.abspath(_c))

for _c in (os.path.join(_HERE, "..", "ubag-mcp"),):
    if os.path.isdir(_c) and os.path.abspath(_c) not in sys.path:
        sys.path.insert(0, os.path.abspath(_c))

import json                                                             # noqa: E402
import urllib.request                                                   # noqa: E402

from ubag_core import (Router, RouteCandidate, RouteTask, StaticVault,  # noqa: E402
                       CredentialVault, SecurityContext)

# The fleet from the pitch: every production key sits in UBAG's vault and the agent
# holds none. The local model may touch any governed data; OpenAI and Claude run
# under enterprise zero-retention terms, so they may take internal data; DeepSeek
# and Qwen are public-only. The last agent is the precondition made visible: it
# carries its own key, so UBAG cannot govern it and will never route to it, even
# though it is the cheapest thing in the fleet.
FLEET_SPEC = [
    {"id": "local (on-prem)", "cost": 1.0, "latency_ms": 40, "key": "vault:local-agent",
     "allowed": ["public", "internal", "pii", "regulated"],
     "caps": ["chat", "extract", "classify"], "local": True},
    {"id": "OpenAI agent", "cost": 2.0, "latency_ms": 220, "key": "vault:openai-prod",
     "allowed": ["public", "internal"], "caps": ["chat", "extract", "vision", "reason"],
     "local": False},
    {"id": "Claude agent", "cost": 2.5, "latency_ms": 200, "key": "vault:anthropic-prod",
     "allowed": ["public", "internal"], "caps": ["chat", "extract", "vision", "reason"],
     "local": False},
    {"id": "DeepSeek agent", "cost": 0.2, "latency_ms": 150, "key": "vault:deepseek-prod",
     "allowed": ["public"], "caps": ["chat", "extract", "reason"], "local": False},
    {"id": "Qwen agent", "cost": 0.25, "latency_ms": 130, "key": "vault:qwen-prod",
     "allowed": ["public"], "caps": ["chat", "extract"], "local": False},
    {"id": "shadow agent (own key)", "cost": 0.05, "latency_ms": 60, "key": "",
     "allowed": ["public", "internal", "pii"], "caps": ["chat", "extract"], "local": False},
]

# Placeholder values only. The demo never resolves a secret: it shows WHICH vault
# reference a decision would release, which is the claim being demonstrated.
_VAULT = StaticVault({s["key"]: "placeholder" for s in FLEET_SPEC if s["key"]})


def _router() -> Router:
    return Router([RouteCandidate(
        id=s["id"], cost=s["cost"], latency_ms=s["latency_ms"],
        allowed_data_classes=frozenset(s["allowed"]),
        capabilities=frozenset(s["caps"]), local=s["local"],
        credential_ref=s["key"]) for s in FLEET_SPEC], vault=_VAULT)


def describe() -> dict:
    return {
        "fleet": [{"id": s["id"], "cost": s["cost"], "latency_ms": s["latency_ms"],
                   "allowed": s["allowed"], "caps": s["caps"], "local": s["local"],
                   "key": s["key"], "stand_in": STAND_IN.get(s["id"])} for s in FLEET_SPEC],
        "data_classes": ["public", "internal", "pii", "regulated", "top_secret"],
        "capabilities": sorted({c for s in FLEET_SPEC for c in s["caps"]}),
        "objectives": ["cost", "latency"],
        "note": "Every production key is in UBAG's vault. The planner decides the task; "
                "UBAG routes it to the cheapest compliant agent, gates the call, and "
                "releases that one key only.",
    }


def _task_from(payload: dict):
    data_class = str(payload.get("data_class") or "public")
    caps = frozenset(str(c) for c in (payload.get("capabilities") or []) if str(c).strip())
    raw_slo = payload.get("max_latency_ms")
    try:
        slo = float(raw_slo) if raw_slo not in (None, "") else None
    except (TypeError, ValueError):
        slo = None
    objective = str(payload.get("objective") or "cost")
    if objective not in ("cost", "latency", "balanced"):
        objective = "cost"
    return RouteTask(data_class=data_class, required_capabilities=caps,
                     max_latency_ms=slo), objective


# ── live run: UBAG brokers the call and injects only the routed key ────────────
# The demo holds no OpenAI / Anthropic / DeepSeek / Qwen keys, so each agent is
# served by a real Vertex model standing in for that provider, and the page says
# so. What is NOT a stand-in: the vault releases a real short-lived access token
# for the chosen reference only, the executor can call its model with nothing
# else, and the call runs through the shipped ubag_mcp Gateway.delegate.
STAND_IN = {
    "local (on-prem)": "gemini-2.5-flash-lite",
    "OpenAI agent": "gemini-2.5-flash",
    "Claude agent": "gemini-2.5-flash",
    "DeepSeek agent": "gemini-2.5-flash-lite",
    "Qwen agent": "gemini-2.5-flash-lite",
}
PROJECT = os.environ.get("UBAG_VERTEX_PROJECT", "your-gcp-project")
LOCATION = os.environ.get("UBAG_VERTEX_LOCATION", "us-central1")
MAX_PROMPT = 1500


class _AdcVault(CredentialVault):
    """Holds the fleet's references; resolving one mints a real access token from
    the service account (ADC). Nothing is minted unless a routed decision asks."""
    def __init__(self, refs):
        self._refs = set(refs)
        self.resolved: list = []

    def has(self, ref: str) -> bool:
        return bool(ref) and ref in self._refs

    def resolve(self, ref: str) -> str:
        if not self.has(ref):
            raise KeyError(ref)
        import egress_console                     # shares the ADC credential cache
        self.resolved.append(ref)
        return egress_console._vertex_token()


def _executor(agent_id: str):
    model = STAND_IN[agent_id]

    def call(payload: dict) -> dict:
        body = json.dumps({
            "system_instruction": {"parts": [{"text":
                f"You are the {agent_id} in a routed agent fleet. Do the task in at "
                "most five short sentences. Plain text, no markdown."}]},
            "contents": [{"role": "user", "parts": [{"text": payload["prompt"]}]}],
            "generationConfig": {"temperature": 0.4, "maxOutputTokens": 400,
                                 "thinkingConfig": {"thinkingBudget": 0}}}).encode()
        url = (f"https://{LOCATION}-aiplatform.googleapis.com/v1/projects/{PROJECT}"
               f"/locations/{LOCATION}/publishers/google/models/{model}:generateContent")
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            # The ONLY credential this executor has is the one UBAG released.
            "Authorization": f"Bearer {payload['_credential']}"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            out = json.loads(resp.read())
        parts = out["candidates"][0].get("content", {}).get("parts", [])
        usage = out.get("usageMetadata", {})
        return {"text": "".join(p.get("text", "") for p in parts).strip()[:1500],
                "model": model,
                "tokens_in": usage.get("promptTokenCount", 0),
                "tokens_out": usage.get("candidatesTokenCount", 0)}
    return call


_RUN_CONTEXT = SecurityContext("demo", "visitor", "planner", "demo-account",
                               "demo-credential", "route-console")


def run(payload: dict) -> dict:
    """Route the task, then broker a real model call through Gateway.delegate."""
    from ubag_mcp import Gateway, ModelAgent
    payload = payload or {}
    prompt = str(payload.get("prompt") or "").strip()[:MAX_PROMPT]
    if not prompt:
        return {"error": "give the planner a task to hand down"}
    task, objective = _task_from(payload)

    vault = _AdcVault(s["key"] for s in FLEET_SPEC if s["key"])
    gw = Gateway(context_provider=lambda: _RUN_CONTEXT, router=Router(vault=vault))
    for s in FLEET_SPEC:
        cand = RouteCandidate(
            id=s["id"], cost=s["cost"], latency_ms=s["latency_ms"],
            allowed_data_classes=frozenset(s["allowed"]),
            capabilities=frozenset(s["caps"]), local=s["local"],
            credential_ref=s["key"])
        if s["key"]:
            gw.register_agent(ModelAgent(cand, _executor(s["id"])))
        else:
            # The shadow agent carries its own key. It cannot be registered as a
            # brokered agent at all; it sits in the router only so the page shows
            # custody refusing it.
            gw.router.register(cand)

    r = gw.delegate(task, {"prompt": prompt, "reason": prompt}, objective=objective)
    result = r.get("result") if isinstance(r.get("result"), dict) else {}
    if r.get("error"):
        print(f"route run failed: {r['error'][:300]}", file=sys.stderr, flush=True)
    return {
        "decision": r["decision"], "executed": r["executed"],
        "execution_status": r["execution_status"], "reason": r["reason"],
        "chosen": r["route"]["chosen"], "released": r["released"],
        "withheld": r["route"]["withheld"], "considered": r["route"]["considered"],
        "projected_cost": round(r["route"]["projected_cost"], 4),
        "data_class": task.data_class, "objective": objective,
        "keys_minted": list(vault.resolved),
        "stand_in_model": result.get("model"),
        "text": result.get("text"),
        "tokens_in": result.get("tokens_in"), "tokens_out": result.get("tokens_out"),
        "latency_ms": round(r["latency_ms"]) if r.get("latency_ms") else None,
        "error": "the model call failed" if r.get("error") else None,
    }


def route(payload: dict) -> dict:
    payload = payload or {}
    data_class = str(payload.get("data_class") or "public")
    caps = frozenset(str(c) for c in (payload.get("capabilities") or []) if str(c).strip())
    raw_slo = payload.get("max_latency_ms")
    try:
        slo = float(raw_slo) if raw_slo not in (None, "") else None
    except (TypeError, ValueError):
        slo = None
    objective = str(payload.get("objective") or "cost")
    if objective not in ("cost", "latency", "balanced"):
        objective = "cost"

    task = RouteTask(data_class=data_class, required_capabilities=caps,
                     max_latency_ms=slo)
    d = _router().route(task, objective=objective)
    return {
        "chosen": d.chosen, "routed": d.routed, "reason": d.reason,
        "projected_cost": round(d.projected_cost, 4), "latency_ms": d.latency_ms,
        "objective": objective, "data_class": data_class,
        "released": d.credential_ref, "withheld": d.withheld,
        "considered": [{"id": i, "ok": ok, "why": why} for i, ok, why in d.considered],
    }
