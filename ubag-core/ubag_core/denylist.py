"""
Attack memory - a permanent, deterministic denylist of confirmed attacks.

The rule-factory bridge. A semantic judge (or a human reviewer) catches an attack
ONCE, somewhere outside this core; its normalized fingerprint lands here, and from
then on the deterministic core blocks that attack - and its recase / reorder /
de-leet variants - forever, with no LLM in the decision path. The teacher runs in
shadow; this store is what enforces inline, and it is owned, not rented.

Same universal-plug pattern as the other ports: core defines one question
(is this fingerprint a confirmed attack?), the deployment answers it against
whatever it has (in-memory set, database table, shared service). Writers must use
the same normalization as `normalize_fingerprint` (NFKC fold -> lowercase ->
de-leet -> unique sorted alnum tokens -> sha256) or reads will not match.

Deny-only by design: this layer can BLOCK, never clear. A text that is not in the
store says nothing about its safety; the other layers still judge it.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Iterable, Optional

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s",
})

_STOPWORDS = {"a", "an", "and", "for", "in", "into", "of", "on", "the", "to"}

_MIN_TEXT_LEN = 4      # shorter strings are too generic to fingerprint safely


def normalize_fingerprint(text: str) -> str:
    """Version-independent normalized signature of a text: NFKC fold -> lowercase
    -> de-leet -> unique sorted alnum tokens -> sha256. Recasing, reordering, and
    light leet obfuscation of the same words collapse to the same fingerprint."""
    t = unicodedata.normalize("NFKC", str(text)).lower().translate(_LEET_MAP)
    tokens = sorted(set(re.findall(r"[a-z0-9]+", t)) - _STOPWORDS)
    return hashlib.sha256(" ".join(tokens).encode("utf-8", errors="ignore")).hexdigest()


class DenyMemory:
    """Implement against your store. Return True only for confirmed attacks."""

    def is_denied(self, fingerprint: str) -> bool:
        return False


class StaticDenyMemory(DenyMemory):
    """Reference / test implementation backed by an in-memory fingerprint set.
    Seed it with stored fingerprints, or teach it raw texts via learn()."""

    def __init__(self, fingerprints: Optional[Iterable[str]] = None):
        self._fps = set(fingerprints or [])

    def learn(self, text: str) -> str:
        """Record a confirmed attack text. Returns the fingerprint (persist it)."""
        fp = normalize_fingerprint(text)
        self._fps.add(fp)
        return fp

    def is_denied(self, fingerprint: str) -> bool:
        return fingerprint in self._fps


def scan_denied(memory: Optional[DenyMemory], texts: Iterable[str]) -> Optional[str]:
    """Fingerprint every candidate text and ask the memory. Returns the fingerprint
    of the first confirmed attack, or None. Deterministic comparison only."""
    if memory is None:
        return None
    for t in texts:
        if isinstance(t, str) and len(t.strip()) >= _MIN_TEXT_LEN:
            fp = normalize_fingerprint(t)
            if memory.is_denied(fp):
                return fp
    return None
