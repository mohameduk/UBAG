"""
Tool registry — capability control and per-tool policy (the ACL + value layer).

Deterministic, secure-default-deny: an unknown tool is BLOCKED. Each allowed tool
carries its own rules (is it allowed at all, value thresholds that REVIEW/BLOCK an
oversized call, a per-call cost for the breaker budget, whether to scan its string
arguments for injection). A trade gateway needs this: place_order, cancel, and
withdraw are not the same risk and cannot share one limit.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterator, Optional

from .policy import ALLOW, BLOCK, REVIEW, PolicyDecision, canonical_signature


@dataclass
class ToolRule:
    allowed: bool = True
    cost: float = 0.0                       # $ attributed to the breaker budget per call
    value_arg: Optional[str] = None         # name of a monetary argument to ceiling-check
    block_value: Optional[float] = None     # value strictly above this -> BLOCK
    review_value: Optional[float] = None    # value strictly above this -> REVIEW
    scan_args: bool = True                  # run the injection scan on this tool's string args
    reversible: bool = True                 # can this action be held/escrowed and undone?
                                            # False = commits the instant it touches the world
                                            # (on-chain send, cleared wire, hard delete, sent email)


@dataclass
class Registry:
    default_allow: bool = False             # secure default: unknown tools are denied
    tools: dict[str, ToolRule] = field(default_factory=dict)

    def register(self, name: str, rule: Optional[ToolRule] = None) -> None:
        self.tools[name] = rule or ToolRule()


def _iter_strings(value) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        # Mapping keys are attacker-controlled too. Scanning only values misses
        # prototype-pollution and reserved-control-key payloads.
        for k, v in value.items():
            if isinstance(k, str):
                yield k
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def _coerce_float(val) -> Optional[float]:
    """Coerce to a FINITE float, or None. NaN and +/-inf are rejected: NaN defeats
    every ceiling comparison (nan > x is always False), so it must never be treated
    as a usable amount. A caller that gets None for a present-but-garbage value must
    fail closed, not skip the check (see check_tool)."""
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        f = float(val)
    elif isinstance(val, str):
        try:
            f = float(val.replace(",", "").strip())
        except (ValueError, AttributeError):
            return None
    else:
        return None
    return f if math.isfinite(f) else None


def check_tool(registry: Registry, tool_name: str, arguments: Optional[dict]) -> PolicyDecision:
    """ACL + value verdict for one tool call. BLOCK on deny/unknown/over-block-value,
    REVIEW on over-review-value, else ALLOW. Deterministic — no reason text here."""
    sig = canonical_signature(tool_name, arguments)
    rule = registry.tools.get(tool_name)

    if rule is None:
        if not registry.default_allow:
            return PolicyDecision(BLOCK, f"tool '{tool_name}' is not on the allow-list",
                                  flags=[{"check": "Tool ACL", "severity": "CRITICAL"}], signature=sig)
        rule = ToolRule()
    elif not rule.allowed:
        return PolicyDecision(BLOCK, f"tool '{tool_name}' is explicitly denied",
                              flags=[{"check": "Tool ACL", "severity": "CRITICAL"}], signature=sig)

    if not isinstance(arguments, dict):
        return PolicyDecision(BLOCK, "arguments must be an object", score=0.9,
                              flags=[{"check": "Argument schema", "severity": "HIGH"}],
                              signature=sig)

    if rule.value_arg and rule.value_arg not in arguments:
        return PolicyDecision(BLOCK, f"required value argument '{rule.value_arg}' is missing",
                              score=0.9,
                              flags=[{"check": "Value ceiling", "severity": "HIGH"}],
                              signature=sig)

    # Validate the conventional `amount` field even without an explicit ceiling.
    # Invalid and signed debit amounts must not become "no check".
    value_arg = rule.value_arg or ("amount" if "amount" in arguments else None)
    if value_arg is not None:
        val = _coerce_float(arguments.get(value_arg))
        if val is None:
            # A ceiling is configured and the value is PRESENT but not a finite
            # number (garbage, NaN, inf). We cannot verify it, so fail closed
            # rather than skip the check — the NaN-bypass hole.
            return PolicyDecision(BLOCK, f"value argument '{value_arg}' is not a finite number",
                                  score=0.9,
                                  flags=[{"check": "Value validation", "severity": "HIGH"}],
                                  signature=sig)
        else:
            if val < 0:
                return PolicyDecision(BLOCK, f"value argument '{value_arg}' cannot be negative",
                                      score=0.9,
                                      flags=[{"check": "Value validation", "severity": "HIGH"}],
                                      signature=sig)
            if rule.block_value is not None and val > rule.block_value:
                return PolicyDecision(BLOCK, f"value {val:,.2f} exceeds block ceiling "
                                      f"{rule.block_value:,.2f}", score=0.9,
                                      flags=[{"check": "Value ceiling", "severity": "HIGH"}], signature=sig)
            if rule.review_value is not None and val > rule.review_value:
                return PolicyDecision(REVIEW, f"value {val:,.2f} exceeds review threshold "
                                      f"{rule.review_value:,.2f}", score=0.5,
                                      flags=[{"check": "Value threshold", "severity": "MEDIUM"}], signature=sig)

    return PolicyDecision(ALLOW, "within tool policy", signature=sig)


def scan_arguments(registry: Registry, tool_name: str, arguments: Optional[dict],
                   detector) -> list[str]:
    """Run an injection detector over every string argument, if the tool opts in.
    `detector` is a callable str -> list[str] (the deployment supplies it)."""
    rule = registry.tools.get(tool_name) or ToolRule()
    if not (rule.scan_args and arguments and detector):
        return []
    hits: list[str] = []
    for s in _iter_strings(arguments):
        if s and len(s) >= 4:
            hits.extend(detector(s))
    return list(dict.fromkeys(hits))
