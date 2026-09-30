"""
Credential placeholders on the MCP surface: the tripwire and the swap.

On MCP the agent normally holds no key at all: it names a tool and the gateway
injects the credential server-side. Two cases still need placeholders:

  1. An HTTP-shaped tool (`http_request(url, headers)`) where the agent builds
     the request itself, key included. The agent is handed a placeholder, and the
     swap happens when the tool runs, only in the bound header, only on the bound
     host (ubag_core.SafeInjector).
  2. The tripwire. A tricked agent leaks a key by pasting it somewhere ordinary: an
     email body, a ticket, a booking note. If its "key" is a placeholder, every tool
     call can be scanned for it. A placeholder in any argument of any other tool, or
     in the stated reason, is an exfiltration attempt and the call is refused before
     the engine, the executor or the vault are touched.

One function, `judge`, is shared by ubag_mcp.Gateway and the demo console, so the
page shows exactly what the product does.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from ubag_core import SafeInjector, InjectionResult

_ANY = re.compile(r"ubag_ph_[0-9A-Za-z]+")


@dataclass(frozen=True)
class HttpArgs:
    """Which arguments of an HTTP-shaped tool carry the URL and the headers."""
    url: str = "url"
    headers: str = "headers"


@dataclass
class CredentialVerdict:
    ok: bool
    reason: str = ""
    tripwire: bool = False
    carries_credential: bool = False          # a placeholder is present, legitimately
    sightings: list = field(default_factory=list)


def find_placeholders(value, path: str = "args") -> list:
    """Every placeholder-looking token anywhere in `value`, with its path."""
    out: list = []
    if isinstance(value, str):
        out += [(path, tok) for tok in _ANY.findall(value)]
    elif isinstance(value, dict):
        for k, v in value.items():
            out += [(f"{path}.{k}", tok) for tok in _ANY.findall(str(k))]
            out += find_placeholders(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            out += find_placeholders(v, f"{path}[{i}]")
    return out


def _host(url: str) -> str:
    try:
        return (urlsplit(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        return ""


def judge(injector: Optional[SafeInjector], tool: str, args: dict, reason: str = "",
          http: Optional[HttpArgs] = None) -> CredentialVerdict:
    """Decide whether a tool call's placeholders are where they may be.

    Never reads the vault. With no injector there is nothing to judge."""
    if injector is None:
        return CredentialVerdict(True)
    args = args if isinstance(args, dict) else {}
    seen = find_placeholders(args) + find_placeholders(reason or "", "reason")
    if not seen:
        return CredentialVerdict(True)

    if http is None:
        where = seen[0][0]
        return CredentialVerdict(
            False, f"a credential placeholder appeared in {where} of '{tool}'. Keys only "
                   "travel in an HTTP tool's authorization header, so this is refused as "
                   "an exfiltration attempt", tripwire=True, sightings=seen)

    # HTTP-shaped tool: the only legitimate place is the headers argument. The URL
    # and headers go to SafeInjector, which enforces header + host binding; any
    # placeholder in another argument (or the reason) is the tripwire.
    stray = [(p, t) for p, t in seen if not p.startswith(f"args.{http.headers}")
             and p != f"args.{http.url}"]
    if stray:
        return CredentialVerdict(
            False, f"a credential placeholder appeared in {stray[0][0]} of '{tool}'; it "
                   f"may only travel in the {http.headers} argument's authorization "
                   "header. Refused as an exfiltration attempt", tripwire=True,
            sightings=seen)
    url = str(args.get(http.url, ""))
    headers = args.get(http.headers) if isinstance(args.get(http.headers), dict) else {}
    res = injector.check(_host(url), url, headers)
    if not res.ok:
        return CredentialVerdict(False, res.reason, tripwire=res.tripwire, sightings=seen)
    return CredentialVerdict(True, res.reason, carries_credential=True, sightings=seen)


def swap(injector: SafeInjector, args: dict, http: HttpArgs) -> tuple[InjectionResult, dict]:
    """Right before execution: real key into the headers argument, nowhere else.
    Returns the result (use `.redact()` on whatever the tool returns) and the
    arguments to execute with. Call only after `judge` passed and the engine
    allowed the call."""
    url = str(args.get(http.url, ""))
    headers = args.get(http.headers) if isinstance(args.get(http.headers), dict) else {}
    res = injector.inject(_host(url), url, headers)
    if not res.ok:
        return res, args
    return res, {**args, http.headers: res.headers}


def placeholder_note(host: str, placeholder: str, tool: str = "http.request",
                     headers_arg: str = "headers") -> str:
    """How to tell an agent about the key it holds (it is a placeholder)."""
    return (f"You hold an API key for {host}. Its value is {placeholder}. To call "
            f"{host} with it, use {tool} with arguments "
            + json.dumps({"url": f"https://{host}/...",
                          headers_arg: {"Authorization": f"Bearer {placeholder}"}}))
