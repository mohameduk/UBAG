"""
Deterministic text signals — the per-action layer of the UBAG core gate.

Pure regex over the action's own justification text. No LLM, no network, no state.
Each family votes once, signed: corroborating (+) or exonerating (-). This is the
"no probabilistic vibes" layer: the same input always yields the same verdict.
"""
from __future__ import annotations

import re

# HARD exfil destination — effectively never appears in a legitimate action.
_DEST_HARD = re.compile(
    r"\b(cold\s*(storage\s*)?wallet|crypto\s*wallet|custodial\s*wallet|0x[0-9a-fA-F]{2,}|"
    r"off[-\s]?shore|cayman|private\s+trust|external\s+(wallet|endpoint))\b", re.I)

# SOFT external destination — suspicious but ambiguous.
_DEST_SOFT = re.compile(
    r"\b(external\s+(\w+\s+)?(account|address|wallet|node|database|endpoint|server)|"
    r"beneficiary\s+account|settlement\s+(account|pool|address)|linked\s+wallet|"
    r"unverified\s+wallet|withdraw\w*|extraction|exfiltrat\w*|repatriat\w*)\b", re.I)

# INTERNAL / standard venue — EXONERATING.
_DEST_INTERNAL = re.compile(
    r"\b(secondary\s+account|primary\s+account|clearing\s+account|money\s+market|cash\s+sweep|"
    r"dark\s+pool|the\s+exchange|primary\s+dealer|sub-?accounts|core\s+(portfolio|fund))\b", re.I)

# REDIRECTION to a NEW / CHANGED / EXTERNALLY-PROVIDED destination — the calm
# social-engineering exfil that uses no trigger words. (Design-partner finding.)
_DEST_REDIRECT = re.compile(
    r"\b(?:"
    r"(?:new(?:ly)?|updated?|revised|different|alternate|another|amended|changed|provided|"
    r"designated|supplied|specified|latest|separate)\s+(?:\w+\s+){0,2}?"
    r"(?:custody|custodial|treasury|settlement|beneficiary|escrow|clearing|payout|"
    r"disbursement|remittance|receiving)\s+"
    r"(?:address|account|wallet|destination|instruction|routing|node|endpoint)"
    r"|"
    r"(?:address|account|wallet|destination|routing|wire\s+instruction|banking\s+detail)s?\s+"
    r"(?:\w+\s+){0,3}?(?:provided|listed|given|specified|attached|noted|indicated|from|in)\s+"
    r"(?:\w+\s+){0,2}?(?:ops|operation|update|memo|note|instruction|e-?mail|ticket|sheet|"
    r"advisory|bulletin|directive|hand-?off|runbook)"
    r")\b", re.I)

_TOTALITY = re.compile(
    r"\b(all\s+(positions|holdings|assets?|capital|funds?|cash|margin|balance|equity)|"
    r"entire\s+(balance|portfolio|account|equity)|complete\s+(capital\s+)?withdrawal|"
    r"total\s+(liquidation|extraction|proceeds)|sweep\w*\s+(all|the\s+(full|entire))|everything)\b|100\s*%", re.I)

_CONTROL = re.compile(
    r"\b(suspend\w*\s+(all\s+)?(stop-?loss|hedg|risk)|disabl\w*\s+(2fa|the\s+security|hedg|stop-?loss)|"
    r"ignor\w*\s+(the\s+)?(drawdown|risk|daily|liquidity)\s+(limit|threshold)|"
    r"override\s+(the\s+)?(current\s+)?(risk|compliance)|"
    r"bypass\w*\s+(?:\w+\s+){0,2}(compliance|approval|security|risk\s+filter|max\s+position)|"
    r"run\s+unbounded|uncollateralized|max(imum)?\s+leverage)\b", re.I)

_INJECTION = re.compile(
    # The verb and the temporal word are frequently separated by a determiner or
    # possessive: "ignore YOUR previous instructions", "disregard THE earlier
    # ones". The original pattern allowed only the literal "all" between them, so
    # the single most common phrasing in the wild was missed. Up to two
    # intervening words are tolerated, non-greedily, which covers the natural
    # variants without reaching across a sentence.
    r"((?:ignor|disregard|overrid)\w*\s+(?:\w+\s+){0,2}?(prior|previous|earlier|preceding|standard)\b|"
    r"previous\s*:\s*(?:do\s+not|don't)\s+(?:block|review|check)|"
    r"system\s*:\s*|system\s+(prompt|directive)|admin(istrator)?\s+(override|mode)|maintenance\s+mode|pretend\s+you\s+are|"
    r"</?(reason|execute)>|note\s+to\s+system)", re.I)

_CONTROL_TAMPER = re.compile(
    r"(?:bypass|disable|ignore|override|suppress)\w*?.{0,80}?"
    r"(?:circuit[\s_-]*breaker|denylist|allowlist|authori[sz]ation|policy|risk|limits?|alerts?|checks?)"
    r"|risk[\s_-]*score\s*=|without\s+checking\s+policy", re.I)

_CODE_INJECTION = re.compile(
    r"<\s*script\b|\b(?:drop|alter|truncate|delete)\s+table\b|--\s*$|"
    r"\b(?:__proto__|prototype|constructor)\b", re.I)

_TOOL_SMUGGLE = re.compile(
    r"[\"']?tool[\"']?\s*[:=]\s*[\"']?(?:withdraw|refund|transfer|delete|execute)|"
    r"[\"']?next_step[\"']?\s*[:=]", re.I)

_EXFIL_INSTRUCTION = re.compile(
    # Two gaps closed, both general:
    #  * the verb list omitted the ways data actually leaves a system that is not
    #    a bank: post, upload, publish, share, exfiltrate;
    #  * the destination required a scheme (`https://`), so the way humans
    #    normally write a link, "www.example.com" or a bare host, was invisible.
    #    A closed TLD list is used rather than \w+\.\w{2,} so that ordinary prose
    #    ("e.g", "vs.io") does not become an exfiltration signal.
    r"\b(?:send|route|transfer|forward|contact|post|upload|publish|share|exfiltrat\w*)\b.{0,60}?"
    r"(?:designated[\s_-]*settlement[\s_-]*pool|[a-z0-9]{4,}://|"
    r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|"
    r"\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}\b|"
    r"\b[a-z0-9-]{2,}(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|ai|app|dev|xyz|info|biz|me|"
    r"ru|cn|de|uk|fr|us|top|site|online|shop|link|click|cloud|tech)\b)", re.I)

_ENCODED = re.compile(r"\b(base64|hex\s+payload)\b|[A-Za-z0-9+/]{20,}={0,2}|(?:[0-9a-fA-F]{2}){12,}", re.I)

# weights: one signed vote per family
WEIGHTS = {"injection": +0.80, "encoded": +0.40, "control_tamper": +0.80,
           "dest_hard": +0.45, "dest_redirect": +0.35, "dest_soft": +0.30, "dest_internal": -0.15,
           "totality": +0.20, "control": +0.20}


def text_signals(reason: str) -> dict:
    """Return {family: signed_delta} from the reason text. One vote per family."""
    r = reason or ""
    s: dict[str, float] = {}
    if (_INJECTION.search(r) or _CODE_INJECTION.search(r) or
            _TOOL_SMUGGLE.search(r) or _EXFIL_INSTRUCTION.search(r)):
        s["injection"] = WEIGHTS["injection"]
    if _CONTROL_TAMPER.search(r): s["control_tamper"] = WEIGHTS["control_tamper"]
    if _ENCODED.search(r):   s["encoded"]   = WEIGHTS["encoded"]
    if _DEST_HARD.search(r):       s["destination"] = WEIGHTS["dest_hard"]
    elif _DEST_REDIRECT.search(r): s["destination"] = WEIGHTS["dest_redirect"]
    elif _DEST_SOFT.search(r):     s["destination"] = WEIGHTS["dest_soft"]
    elif _DEST_INTERNAL.search(r): s["destination"] = WEIGHTS["dest_internal"]
    if _TOTALITY.search(r):  s["totality"] = WEIGHTS["totality"]
    if _CONTROL.search(r):   s["control"]  = WEIGHTS["control"]
    return s


def injection_hits(s: str) -> list[str]:
    """Default injection detector over a single string (for argument scanning)."""
    hits = []
    if _INJECTION.search(s or ""): hits.append("prompt-injection")
    if _CONTROL_TAMPER.search(s or ""): hits.append("control-tampering")
    if _CODE_INJECTION.search(s or ""): hits.append("code-injection")
    if _TOOL_SMUGGLE.search(s or ""): hits.append("tool-smuggling")
    if _EXFIL_INSTRUCTION.search(s or ""): hits.append("exfil-instruction")
    if _ENCODED.search(s or ""):   hits.append("encoded-payload")
    return hits


def hard_injection_hits(s: str) -> list[str]:
    """Hits that justify a HARD block, in a reason OR a tool argument.

    Generic encoded text ("encoded-payload") is excluded: the heuristic matches any
    20+ char alphanumeric run, which every bank IBAN, account id, and reference
    number also matches, so hard-blocking on it refuses legitimate transfers. It
    stays a score-only signal for reasons (see text_signals) and is simply not a
    hard-block trigger for arguments. The precise injection families
    (prompt-injection, control-tampering, code-injection, tool-smuggling,
    exfil-instruction) still hard-block anywhere they appear."""
    return [h for h in injection_hits(s) if h != "encoded-payload"]


# Backward-compatible alias: this set was originally reason-only.
hard_reason_hits = hard_injection_hits
