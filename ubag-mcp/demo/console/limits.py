"""
Spend and abuse limits for a public demo with a real model behind it.

Two limits, because they defend against different things and only one of them
is actually load-bearing.

    per-IP window      fairness. One visitor cannot starve the rest.
    global daily cap   cost. The bill cannot exceed this no matter what.

The global cap is the real protection. Per-IP limiting on Cloud Run rests on
`X-Forwarded-For`, and a client can prepend whatever it likes to that header, so
IP attribution is a best effort and must never be the only thing between a
stranger and the credit card. The daily ceiling holds even when attribution is
defeated entirely, because it counts calls rather than callers.

Everything is in-process and therefore per-instance. That is correct for this
deployment and only this deployment: the console runs at `--max-instances=1`
because it holds session state in memory, so per-instance and global are the
same number. Scale it out and this must move to a shared store, which is why
`describe()` reports the assumption rather than hiding it.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


# Model calls: the ones that cost money.
MODEL_PER_IP_PER_MINUTE = _int_env("UBAG_DEMO_MODEL_PER_MIN", 6)
MODEL_PER_IP_PER_HOUR = _int_env("UBAG_DEMO_MODEL_PER_HOUR", 40)
MODEL_GLOBAL_PER_DAY = _int_env("UBAG_DEMO_MODEL_PER_DAY", 1500)

# Everything else: cheap, but still worth a ceiling so the box stays responsive.
API_PER_IP_PER_MINUTE = _int_env("UBAG_DEMO_API_PER_MIN", 120)

# Whether anything in front of this process appends the true client address to
# X-Forwarded-For. A fact about the deployment, so it is configured rather than
# guessed, and it defaults to "no" because guessing wrong means trusting a
# header the caller wrote. Set it when a trusted proxy (e.g. Cloud Run) fronts the console.
TRUST_PROXY = os.environ.get("UBAG_DEMO_TRUST_PROXY", "").strip().lower() in (
    "1", "true", "yes", "on")

MINUTE, HOUR, DAY = 60.0, 3600.0, 86400.0

# A visitor who has been idle longer than the widest window can be forgotten.
# Without this the map grows for the lifetime of the instance, which is a slow
# memory leak with a public endpoint attached to it.
FORGET_AFTER = HOUR * 2
MAX_TRACKED_CLIENTS = 20_000


@dataclass
class Verdict:
    allowed: bool
    reason: str = ""
    retry_after: int = 0
    scope: str = ""

    def to_dict(self) -> dict:
        return {"error": self.reason, "rate_limited": True,
                "retry_after_seconds": self.retry_after, "scope": self.scope}


@dataclass
class _Window:
    """Sliding window of hit timestamps, newest last."""
    hits: deque = field(default_factory=deque)

    def trim(self, now: float, span: float) -> None:
        while self.hits and now - self.hits[0] >= span:
            self.hits.popleft()

    def count(self, now: float, span: float) -> int:
        return sum(1 for t in self.hits if now - t < span)


class Limiter:
    """Per-IP windows plus one global daily ceiling."""

    def __init__(self):
        self._lock = threading.Lock()
        self._clients: dict[str, _Window] = {}
        self._api: dict[str, _Window] = {}
        self._day: deque = deque()
        self._last_sweep = 0.0

    # ── the two checks ────────────────────────────────────────────────────────

    def check_model(self, client: str, now: float | None = None) -> Verdict:
        """A call that will reach a language model, so a call that costs money."""
        now = time.time() if now is None else now
        with self._lock:
            self._sweep(now)

            # Global first. It is the limit that actually protects the budget,
            # so it is checked before anything that depends on trusting a header.
            while self._day and now - self._day[0] >= DAY:
                self._day.popleft()
            if len(self._day) >= MODEL_GLOBAL_PER_DAY:
                return Verdict(False, "This demo has reached its daily limit of "
                                      f"{MODEL_GLOBAL_PER_DAY} model calls. It resets "
                                      "on a rolling 24 hour window.",
                               retry_after=int(DAY - (now - self._day[0])) + 1,
                               scope="global-day")

            window = self._clients.setdefault(client, _Window())
            window.trim(now, HOUR)
            if window.count(now, MINUTE) >= MODEL_PER_IP_PER_MINUTE:
                return Verdict(False, f"Slow down: {MODEL_PER_IP_PER_MINUTE} agent "
                                      "steps a minute per visitor.",
                               retry_after=self._retry(window, now, MINUTE),
                               scope="ip-minute")
            if window.count(now, HOUR) >= MODEL_PER_IP_PER_HOUR:
                return Verdict(False, f"You have used this demo's hourly allowance of "
                                      f"{MODEL_PER_IP_PER_HOUR} agent steps.",
                               retry_after=self._retry(window, now, HOUR),
                               scope="ip-hour")

            window.hits.append(now)
            self._day.append(now)
            return Verdict(True)

    def check_api(self, client: str, now: float | None = None) -> Verdict:
        """A call that costs only CPU. Loose, but not unbounded."""
        now = time.time() if now is None else now
        with self._lock:
            self._sweep(now)
            window = self._api.setdefault(client, _Window())
            window.trim(now, MINUTE)
            if len(window.hits) >= API_PER_IP_PER_MINUTE:
                return Verdict(False, "Too many requests. Wait a moment.",
                               retry_after=self._retry(window, now, MINUTE),
                               scope="ip-minute")
            window.hits.append(now)
            return Verdict(True)

    # ── housekeeping ──────────────────────────────────────────────────────────

    @staticmethod
    def _retry(window: _Window, now: float, span: float) -> int:
        return max(1, int(span - (now - window.hits[0])) + 1) if window.hits else 1

    def _sweep(self, now: float) -> None:
        """Drop clients nobody has heard from. Caller holds the lock."""
        if now - self._last_sweep < MINUTE:
            return
        self._last_sweep = now
        for table in (self._clients, self._api):
            stale = [key for key, window in table.items()
                     if not window.hits or now - window.hits[-1] > FORGET_AFTER]
            for key in stale:
                table.pop(key, None)
            if len(table) > MAX_TRACKED_CLIENTS:
                # Pathological case: more distinct sources than we will track.
                # Keep the most recently active and let the global cap carry the
                # rest, rather than growing without bound.
                keep = sorted(table.items(), key=lambda kv: kv[1].hits[-1],
                              reverse=True)[:MAX_TRACKED_CLIENTS]
                table.clear()
                table.update(keep)

    def describe(self, now: float | None = None) -> dict:
        with self._lock:
            now = time.time() if now is None else now
            while self._day and now - self._day[0] >= DAY:
                self._day.popleft()
            return {
                "model_calls_today": len(self._day),
                "model_calls_per_day": MODEL_GLOBAL_PER_DAY,
                "model_per_ip_per_minute": MODEL_PER_IP_PER_MINUTE,
                "model_per_ip_per_hour": MODEL_PER_IP_PER_HOUR,
                "api_per_ip_per_minute": API_PER_IP_PER_MINUTE,
                "tracked_clients": len(self._clients),
                "trust_proxy": TRUST_PROXY,
                "scope": "per instance; correct only at --max-instances=1",
            }


LIMITER = Limiter()


def client_key(headers, fallback: str = "", trust_proxy: bool | None = None) -> str:
    """Best-effort visitor identity, used for fairness and never for spend.

    `X-Forwarded-For` is a header the caller writes. It is worth reading only
    when something in front of us is known to append the true address, which is
    a fact about the deployment topology and not about the request. So trusting
    it is opt-in: set UBAG_DEMO_TRUST_PROXY=1 where a proxy really does append
    (Cloud Run does), and leave it off everywhere else. Off, every request from
    a direct client is attributed to its socket address, which the client cannot
    choose.

    Even trusted, the rightmost entry is the one to read, not the leftmost: the
    caller controls the left of the list and the infrastructure appends on the
    right. Reading the leftmost value, which is what most examples do, hands
    every visitor a free spoofing primitive.

    It is still only best effort. NAT puts a whole office behind one address and
    a determined caller has more than one. That is why the daily ceiling does
    not depend on this function at all.
    """
    if trust_proxy is None:
        trust_proxy = TRUST_PROXY
    if trust_proxy and headers is not None:
        forwarded = (headers.get("x-forwarded-for")
                     or headers.get("X-Forwarded-For") or "")
        parts = [p.strip() for p in str(forwarded).split(",") if p.strip()]
        if parts:
            return parts[-1][:64]
    return (str(fallback) or "unknown")[:64]
