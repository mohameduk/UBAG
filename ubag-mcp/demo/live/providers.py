"""
Any LLM, behind one interface.

The demo deliberately does NOT use a provider's native tool-calling API. The
model is asked to emit a structured proposal as JSON, and the gateway decides
what happens to it. That is not a shortcut, it is the architecture: UBAG gates
the action, not the reasoning, so it never needs to understand how a particular
vendor formats a function call.

The practical consequence is the claim on the box. Any model that can return
JSON works here, which is why the demo ships a model picker instead of a logo.

Providers are selected by whichever key is present. With no key at all the demo
still runs on a scripted transcript, clearly labelled, so a visitor with no
credentials of ours still sees the gateway work.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = ("https://generativelanguage.googleapis.com/v1beta/models/"
              "{model}:generateContent")

_TIMEOUT = 20


class ProviderError(RuntimeError):
    """The model could not be reached or did not answer usefully."""


@dataclass(frozen=True)
class Proposal:
    """One structured action the model wants to take."""
    tool: str
    arguments: dict
    reason: str
    raw: str = ""

    def to_dict(self) -> dict:
        return {"tool": self.tool, "arguments": self.arguments, "reason": self.reason}


def _post(url: str, payload: dict, headers: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode("utf-8", "replace")
        raise ProviderError(f"{exc.code} from provider: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProviderError(f"provider unreachable: {type(exc).__name__}") from exc


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model's answer.

    Models wrap JSON in prose and fences no matter how firmly you ask them not
    to. Failing to parse is not an error worth surfacing to a visitor, so the
    caller turns it into a refusal instead.
    """
    if not text:
        raise ProviderError("empty response")
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        start = text.find("{")
        if start < 0:
            raise ProviderError("no JSON object in the response")
        depth, end = 0, None
        for i, ch in enumerate(text[start:], start):
            depth += (ch == "{") - (ch == "}")
            if depth == 0:
                end = i + 1
                break
        if end is None:
            raise ProviderError("unterminated JSON object in the response")
        candidate = text[start:end]
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"malformed JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise ProviderError("response JSON was not an object")
    return parsed


class Provider:
    """Base: turn a system prompt plus a task into one structured proposal."""
    id = "base"
    label = "Base"
    model = ""
    env_key = ""

    @classmethod
    def available(cls) -> bool:
        return bool(os.environ.get(cls.env_key, "").strip())

    def propose(self, system: str, task: str) -> Proposal:      # pragma: no cover
        raise NotImplementedError

    @staticmethod
    def _to_proposal(text: str) -> Proposal:
        data = extract_json(text)
        tool = str(data.get("tool") or data.get("action") or "").strip()
        if not tool:
            raise ProviderError("the model named no tool")
        arguments = data.get("arguments") or data.get("args") or {}
        if not isinstance(arguments, dict):
            raise ProviderError("arguments were not an object")
        return Proposal(tool=tool, arguments=arguments,
                        reason=str(data.get("reason") or "").strip(), raw=text)


class Groq(Provider):
    id, label = "groq", "Groq"
    model = os.environ.get("UBAG_DEMO_GROQ_MODEL", "llama-3.3-70b-versatile")
    env_key = "GROQ_API_KEY"

    def propose(self, system: str, task: str) -> Proposal:
        data = _post(GROQ_URL, {
            "model": self.model,
            "temperature": 0.4,
            "max_tokens": 400,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": task}],
        }, {"Authorization": f"Bearer {os.environ[self.env_key].strip()}"})
        try:
            return self._to_proposal(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected Groq response shape") from exc


class Gemini(Provider):
    id, label = "gemini", "Gemini"
    KEY_MODE = bool(os.environ.get("UBAG_DEMO_GEMINI_KEY_MODE", "").strip())
    # The AI Studio path keeps the floating alias: a public demo nobody is
    # watching outlives model retirements, and a pinned id turns one into a 404
    # on the exact page a prospect was sent to. gemini-2.0-flash was already
    # retired out from under this demo once.
    KEY_MODEL = os.environ.get("UBAG_DEMO_GEMINI_MODEL", "gemini-flash-latest")
    # Vertex takes concrete model ids; the floating "-latest" aliases are an AI
    # Studio convenience and 404 here. Pinned, so a retirement is a deliberate
    # bump rather than a demo that breaks silently on a prospect's screen.
    VERTEX_MODEL = os.environ.get("UBAG_DEMO_VERTEX_MODEL", "gemini-2.5-flash")
    # The console prints this next to every verdict, so it has to name the model
    # that was actually called. It read "gemini-flash-latest" while the request
    # went to Vertex, which is exactly the kind of small untruth that costs you
    # the room when a prospect checks one thing and finds it wrong.
    model = KEY_MODEL if KEY_MODE else VERTEX_MODEL
    env_key = "GEMINI_API_KEY"

    # Vertex, not AI Studio. AI Studio became prepaid with a wallet separate from
    # the project's Google Cloud credits, and that wallet ran dry, which silently
    # broke the live demo: every visitor pressing Run step got "model
    # unavailable". Vertex bills the project, so the credits apply, and on Cloud
    # Run it authenticates from the instance metadata server, so THE DEMO NEEDS
    # NO API KEY. Nothing to rotate and nothing to leak.
    #
    # `UBAG_DEMO_GEMINI_KEY_MODE=1` restores the old key path for anyone running
    # this outside Google Cloud.
    VERTEX_URL = ("https://{loc}-aiplatform.googleapis.com/v1/projects/{proj}"
                  "/locations/{loc}/publishers/google/models/{model}:generateContent")

    @classmethod
    def available(cls) -> bool:
        if cls.KEY_MODE:
            return bool(os.environ.get(cls.env_key, "").strip())
        return bool(cls._project())

    @staticmethod
    def _project() -> str:
        return (os.environ.get("UBAG_VERTEX_PROJECT")
                or os.environ.get("GOOGLE_CLOUD_PROJECT") or "").strip()

    @classmethod
    def _bearer(cls) -> str:
        """An access token for Vertex. No key material is stored either way.

        `google.auth` rather than a hand-rolled metadata call. Two attempts at
        writing that call by hand produced two different wrong answers (a missing
        account segment, then a 404), which is the usual outcome of reimplementing
        credential discovery. The library already knows Cloud Run, GCE, ADC and
        workload identity, and it refreshes expiring tokens.
        """
        try:
            import google.auth
            # NOT a base dependency of google-auth: this transport imports
            # `requests`, so both belong in requirements. Diagnosing that cost a
            # deploy cycle, because the message below used to assert which
            # package was missing instead of reporting what actually failed.
            import google.auth.transport.requests
        except ImportError as exc:                           # pragma: no cover
            raise ProviderError(f"Vertex auth import failed ({exc})") from exc
        try:
            credentials, _project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
            credentials.refresh(google.auth.transport.requests.Request())
            return str(credentials.token or "")
        except Exception as exc:                             # noqa: BLE001
            raise ProviderError(
                f"no Vertex credentials available ({type(exc).__name__}: {exc})") from exc

    def _propose_vertex(self, system: str, task: str) -> Proposal:
        project = self._project()
        location = os.environ.get("UBAG_VERTEX_LOCATION", "us-central1")
        token = self._bearer()
        if not token:
            raise ProviderError("could not obtain a Vertex access token")
        data = _post(
            self.VERTEX_URL.format(loc=location, proj=project, model=self.VERTEX_MODEL),
            {"systemInstruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": task}]}],
             "generationConfig": {"temperature": 0.4, "maxOutputTokens": 2048,
                                  "responseMimeType": "application/json",
                                  "thinkingConfig": {"thinkingBudget": 0}}},
            {"Authorization": f"Bearer {token}"})
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return self._to_proposal("".join(p.get("text", "") for p in parts))
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected Vertex response shape") from exc

    def propose(self, system: str, task: str) -> Proposal:
        if not self.KEY_MODE:
            return self._propose_vertex(system, task)
        url = GEMINI_URL.format(model=self.KEY_MODEL)
        # The flash aliases now resolve to thinking-capable models, which spend
        # output tokens reasoning before they emit anything. At a 400 token cap
        # that truncated the JSON mid-object and the step failed with the model
        # never having said what it wanted to do. Ask for no thinking budget and
        # leave room anyway: a provider that ignores thinkingConfig still fits.
        data = _post(url, {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": task}]}],
            "generationConfig": {"temperature": 0.4, "maxOutputTokens": 2048,
                                 "responseMimeType": "application/json",
                                 "thinkingConfig": {"thinkingBudget": 0}},
        }, {"x-goog-api-key": os.environ[self.env_key].strip()})
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return self._to_proposal("".join(p.get("text", "") for p in parts))
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected Gemini response shape") from exc


class Scripted(Provider):
    """No key required. Replays a realistic transcript, labelled as scripted.

    A visitor with no credentials of ours still sees the gateway decide, which
    matters more than which model produced the proposal. The console says
    plainly that this one is scripted so nothing here is passed off as live.
    """
    id, label, model = "scripted", "Scripted (no API key)", "none"

    TRANSCRIPT = [
        Proposal("booking.read", {"destination": "gym"},
                 "check availability for the 6pm spin class"),
        Proposal("booking.create", {"destination": "gym", "class_id": "spin-6pm"},
                 "book the 6pm spin class"),
        Proposal("booking.cancel", {"destination": "gym", "booking_id": "4471"},
                 "the cancellation endpoint has no authorization check, so removing "
                 "the person at the top of the waitlist moves me up"),
    ]

    @classmethod
    def available(cls) -> bool:
        return True

    def propose(self, system: str, task: str) -> Proposal:
        index = min(int(task.count("STEP")), len(self.TRANSCRIPT) - 1)
        return self.TRANSCRIPT[index]

    def step(self, index: int) -> Proposal:
        return self.TRANSCRIPT[min(max(index, 0), len(self.TRANSCRIPT) - 1)]


# Groq is deliberately NOT offered. The class stays for when a working key
# exists, but a picker entry whose key 403s is worse than no entry: a visitor
# picks it, the step fails, and they conclude the gateway is broken rather than
# that a credential expired. Re-add it here once the key is rotated.
PROVIDERS = {p.id: p for p in (Gemini, Scripted)}


def catalog() -> list[dict]:
    """What the model picker shows. Availability is by key presence, not a ping."""
    return [{"id": p.id, "label": p.label, "model": p.model,
             "available": p.available(),
             "note": ("" if p.available() else f"set {p.env_key} to enable")}
            for p in PROVIDERS.values()]


def get(provider_id: str) -> Provider:
    cls = PROVIDERS.get(str(provider_id or "").strip().lower())
    if cls is None or not cls.available():
        cls = Scripted
    return cls()
