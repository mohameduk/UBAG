"""
Policy primitives — decisions, verdicts, and stricter-wins merge.

Deterministic banding: a numeric score maps to exactly one of three decisions.
merge() combines two verdicts by taking the stricter, so an extra check can only
ever ADD suspicion, never clear a bad one.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"
_RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2}

# Default bands. Score at/above BLOCK_AT -> BLOCK; at/below ALLOW_AT -> ALLOW; else REVIEW.
BLOCK_AT = 0.70
ALLOW_AT = 0.30


def band(score: float) -> str:
    if score >= BLOCK_AT:
        return BLOCK
    if score <= ALLOW_AT:
        return ALLOW
    return REVIEW


@dataclass
class PolicyDecision:
    decision: str                       # ALLOW | REVIEW | BLOCK
    reason: str = ""
    score: float = 0.0
    flags: list[dict] = field(default_factory=list)
    signature: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def to_dict(self) -> dict:
        return {"decision": self.decision, "reason": self.reason, "score": round(self.score, 3),
                "flags": self.flags, "signature": self.signature}


def merge(base: PolicyDecision, extra: PolicyDecision) -> PolicyDecision:
    """Take the stricter of two decisions (BLOCK > REVIEW > ALLOW). Never downgrades."""
    if _RANK[extra.decision] > _RANK[base.decision]:
        winner, loser = extra, base
    else:
        winner, loser = base, extra
    return PolicyDecision(
        decision=winner.decision,
        reason=winner.reason or loser.reason,
        score=max(base.score, extra.score),
        flags=(base.flags or []) + (extra.flags or []),
        signature=winner.signature or loser.signature,
    )


def canonical_signature(tool_name: str, arguments: Optional[dict]) -> str:
    """Stable (tool, arguments) signature so identical repeated calls collide."""
    try:
        payload = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        payload = repr(arguments)
    digest = hashlib.sha256(f"{tool_name}\x00{payload}".encode()).hexdigest()[:16]
    return f"{tool_name}:{digest}"
