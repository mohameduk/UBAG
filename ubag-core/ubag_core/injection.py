"""
Safe injection - the agent carries a placeholder, never the key.

For agents that make their own outbound calls (a coding agent in a sandbox, a
browsing agent, anything that writes its own HTTP), the credential has to appear
in the request somewhere. Handing the agent the real key means a prompt injection
can read it and send it anywhere. So the agent is given a PLACEHOLDER instead:

    ubag_ph_<random>     bound to exactly one host, one header, one vault entry

At the egress boundary, and only there, the placeholder is swapped for the real
secret, and only when every condition holds:

  1. the placeholder was minted here   (a forged or guessed one is refused)
  2. it travels in its bound header    (never the URL, the body, another header)
  3. the request goes to its bound host (anywhere else is exfiltration)

Any placeholder that shows up outside those conditions is not quietly dropped:
the whole request is BLOCKED, because a placeholder heading somewhere it was never
bound is the signature of an agent being talked into leaking its credential. The
placeholder is a tripwire as well as a stand-in.

Two more guarantees:
  - the vault is read only for a request that passed every check, and only for
    the entries that request actually uses;
  - `redact()` strips every released secret from whatever comes back, so an
    upstream that echoes the key (a debug endpoint, an error page) cannot hand it
    to the agent on the return trip.

Deterministic, no model, no network. Hosts are compared exactly (lowercased).

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import re
import secrets
import threading
from dataclasses import dataclass, field
from typing import Optional

from .router import CredentialVault

PLACEHOLDER_PREFIX = "ubag_ph_"
_PLACEHOLDER_RE = re.compile(r"ubag_ph_[0-9a-f]{24}")
_ANY_PLACEHOLDER_RE = re.compile(r"ubag_ph_[0-9A-Za-z]+")


@dataclass(frozen=True)
class Binding:
    placeholder: str
    host: str                       # the only host the real key may reach
    ref: str                        # vault reference, never the secret
    header: str = "authorization"   # the only place the placeholder may travel


@dataclass
class InjectionResult:
    ok: bool
    reason: str
    headers: dict = field(default_factory=dict)   # outbound headers, real keys in place
    injected: list = field(default_factory=list)  # [{"ref","host","header"}] swapped
    tripwire: bool = False                         # True when a placeholder tried to leave
    _secrets: list = field(default_factory=list, repr=False)

    def redact(self, value):
        """Strip every secret this request released from `value` (str/dict/list)."""
        return redact(value, self._secrets)


def _forms(secret: str) -> list:
    """Every spelling of a secret we scrub: as-is, and fully escaped as JSON
    unicode escapes (one backslash-u sequence per character, lower and upper hex),
    which a downstream JSON parser decodes back into the secret. Partially escaped
    spellings cannot be enumerated; the placeholder design (the agent never holds
    the real key) is the primary defence, this is the backstop for echoes."""
    bs = chr(92)
    lower = "".join(bs + "u%04x" % ord(c) for c in secret)
    upper = "".join(bs + "u%04X" % ord(c) for c in secret)
    return [secret, lower, upper]


def redact(value, secrets_list, mask: str = "[REDACTED BY UBAG]"):
    """Strip every released secret from `value`, recursively.

    Longest secrets first, so a secret that is a prefix of another cannot leave
    the tail of the longer one behind. Dict KEYS, sets and frozensets are scrubbed
    too, not only values."""
    secrets_ = sorted({s for s in (secrets_list or []) if s}, key=len, reverse=True)
    if not secrets_:
        return value
    forms = sorted({f for s in secrets_ for f in _forms(s)}, key=len, reverse=True)

    def scrub(v):
        if isinstance(v, str):
            for f in forms:
                v = v.replace(f, mask)
            return v
        if isinstance(v, bytes):
            return scrub(v.decode("utf-8", "replace")).encode("utf-8")
        if isinstance(v, dict):
            return {scrub(k) if isinstance(k, str) else k: scrub(x) for k, x in v.items()}
        if isinstance(v, (list, tuple, set, frozenset)):
            return type(v)(scrub(x) for x in v)
        return v
    return scrub(value)


class SafeInjector:
    """Mints placeholders and performs the swap at the egress boundary."""

    def __init__(self, vault: CredentialVault):
        self._vault = vault
        self._bindings: dict[str, Binding] = {}
        self._lock = threading.Lock()

    def mint(self, ref: str, host: str, *, header: str = "authorization") -> str:
        """Create a placeholder for vault entry `ref`, usable only on `host`."""
        if not self._vault.has(ref):
            raise KeyError(f"no credential held in the vault for {ref!r}")
        host = (host or "").strip().lower()
        if not host:
            raise ValueError("a placeholder must be bound to a host")
        ph = PLACEHOLDER_PREFIX + secrets.token_hex(12)
        with self._lock:
            self._bindings[ph] = Binding(ph, host, ref, header.strip().lower())
        return ph

    def binding(self, placeholder: str) -> Optional[Binding]:
        return self._bindings.get(placeholder)

    def check(self, host: str, url: str = "", headers: Optional[dict] = None,
              body: str = "") -> InjectionResult:
        """The same judgement as `inject`, without reading the vault or swapping.
        Lets a surface report a tripwire before any other gate runs."""
        return self.inject(host, url, headers, body, _dry=True)

    def inject(self, host: str, url: str = "", headers: Optional[dict] = None,
               body: str = "", *, _dry: bool = False) -> InjectionResult:
        """Judge one outbound request and, if clean, return it with real keys."""
        host = (host or "").strip().lower()
        headers = {str(k): str(v) for k, v in (headers or {}).items()}

        # Where every placeholder-looking token sits in the request.
        sightings: list[tuple[str, str]] = []           # (token, location)
        for tok in _ANY_PLACEHOLDER_RE.findall(url or ""):
            sightings.append((tok, "the URL"))
        for tok in _ANY_PLACEHOLDER_RE.findall(body or ""):
            sightings.append((tok, "the request body"))
        for name, val in headers.items():
            for tok in _ANY_PLACEHOLDER_RE.findall(name):
                sightings.append((tok, f"a header name ({name})"))
            for tok in _ANY_PLACEHOLDER_RE.findall(val):
                sightings.append((tok, f"header:{name.lower()}"))

        if not sightings:
            return InjectionResult(True, "no credential in this request", headers)

        use: dict[str, Binding] = {}
        for tok, where in sightings:
            b = self._bindings.get(tok) if _PLACEHOLDER_RE.fullmatch(tok) else None
            if b is None:
                return InjectionResult(False, f"unknown placeholder in {_loc(where)}: "
                                       "it was never minted here, so nothing is injected",
                                       tripwire=True)
            if where != f"header:{b.header}":
                return InjectionResult(False, f"the credential for {b.host} appeared in "
                                       f"{_loc(where)}; it may only travel in the "
                                       f"{b.header} header. Blocked as an exfiltration "
                                       "attempt", tripwire=True)
            if host != b.host:
                return InjectionResult(False, f"the credential bound to {b.host} was sent "
                                       f"to {host or 'an unknown host'}. Blocked as an "
                                       "exfiltration attempt", tripwire=True)
            use[tok] = b

        if _dry:
            return InjectionResult(True, f"{len(use)} placeholder(s) bound to {host}, "
                                   "in their bound header", headers,
                                   [{"ref": b.ref, "host": b.host, "header": b.header}
                                    for b in use.values()])
        out = dict(headers)
        released: list[str] = []
        injected: list[dict] = []
        for tok, b in use.items():
            secret = self._vault.resolve(b.ref)         # read only now, only these
            released.append(secret)
            for name in list(out):
                if name.lower() == b.header:
                    out[name] = out[name].replace(tok, secret)
            injected.append({"ref": b.ref, "host": b.host, "header": b.header})
        return InjectionResult(True, f"swapped {len(injected)} placeholder(s) for the "
                               f"real credential on {host}", out, injected,
                               _secrets=released)


def _loc(where: str) -> str:
    return f"the {where[7:]} header" if where.startswith("header:") else where
