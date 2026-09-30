"""
Argument provenance: which values in this action did anyone actually ask for?

THE GAP THIS FILLS
Every other check here asks whether an action is permitted. None asks where its
VALUES came from. An agent that builds a rule, a payment or a filter fills in fields
nobody named, and each field is individually plausible: a threshold, an account, a
currency, a schedule. The action passes every allow-list because the destination is
fine and the tool is granted. The number is simply invented.

So this classifies each argument by ORIGIN, not by content:

    OPERATOR      the person's own words account for this value
    STATE         the operator's system supplied it (an account they own, a payee
                  they have paid, a default the deployment declared)
    MISMATCH  the operator gave a value of this kind and the agent used a
                  DIFFERENT one. "January" became "May". Always a hold: this is
                  the shape every argument-rewriting injection takes.
    UNSOURCED     the operator gave nothing of this kind and the agent filled it
                  in. Not malicious, just unasked-for, and normal assistant
                  behaviour. Held only where a deployment says so.

Keeping those last two apart is what makes this usable. Collapsing them held every
booking where the customer had not stated dates, and a control that fires on
ordinary work gets switched off in a week. `expected_unsourced` skips a field
entirely; `hold_invented` decides whether inventions are acted on at all.

WHAT IT CANNOT DO, STATED PLAINLY
It traces VALUES, not MEANINGS. If the operator says "payments" and the agent fills a
trigger field with "New payment request", no string relationship connects those two,
and this reports the field as unsourced because deterministically it is. Recognising
that one is the rendering of the other is a judgment about meaning, which is the same
wall that killed deterministic read gating at 78% false positives.

So this is sharp on amounts, addresses, identifiers, names and places, which is where
invented values actually cause harm, and blunt on descriptive labels. Label-like
fields belong in `expected_unsourced`. Anyone demonstrating field provenance over
prose labels is showing a model's judgment, not this.

MONOTONIC, like every other layer. It only ever adds suspicion. It cannot clear a
destination the state provider refused, and it returns findings rather than verdicts
so the caller composes them with `merge`.

Deterministic: no model, no network. Same input, same report.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Optional

OPERATOR = "OPERATOR"
STATE = "STATE"
MISMATCH = "MISMATCH"
UNSOURCED = "UNSOURCED"

# MISMATCH and UNSOURCED are NOT the same finding and must not carry the same
# weight. The operator said January and the agent booked May: that is a
# CONTRADICTION, it is the shape every argument-rewriting injection takes, and it
# should always be held. The operator said nothing about dates and the agent picked
# some: that is an INVENTION, it is what a useful assistant does all day, and
# holding it by default is how a control becomes an annoyance and gets switched off.
#
# Collapsing the two was the first version of this file and it held every booking
# where the customer had not stated dates. Telling them apart needs no extra
# information: a contradiction is only possible when the operator supplied a
# comparable value in the first place.

# "25k" and "1.5m" are how people write amounts out loud, and an agent that renders
# them as 25000 has not invented anything. Matching only digits would flag it.
_SUFFIX = {"k": 1_000.0, "m": 1_000_000.0, "b": 1_000_000_000.0}
_NUMBER_RE = re.compile(r"(?<![\w.])(\d[\d,\s]*(?:\.\d+)?)\s*([kmb])?\b", re.I)
_WORD_RE = re.compile(r"[a-z0-9@._+/-]+")

# Worst-wins ordering for a compound argument.
_RANK = {OPERATOR: 0, STATE: 1, UNSOURCED: 2, MISMATCH: 3}


@dataclass
class Origin:
    name: str
    value: object
    origin: str
    detail: str = ""


@dataclass
class ProvenanceReport:
    origins: list = field(default_factory=list)

    @property
    def contradicted(self) -> list:
        """Operator gave a value of this kind; the agent used a different one."""
        return [o for o in self.origins if o.origin == MISMATCH]

    @property
    def unsourced(self) -> list:
        """Operator gave nothing of this kind; the agent filled it in."""
        return [o for o in self.origins if o.origin == UNSOURCED]

    @property
    def clean(self) -> bool:
        return not self.contradicted and not self.unsourced

    def holds(self, *, hold_invented: bool = False) -> list:
        """The findings a deployment actually acts on.

        Contradictions always. Inventions only where the deployment says an
        invented value is dangerous for that tool, which is true of an amount and
        usually false of a date.
        """
        return self.contradicted + (self.unsourced if hold_invented else [])

    def summary(self, *, hold_invented: bool = True) -> str:
        """Describes what was FOUND. `holds()` decides what is acted on, and the
        two must not be confused: a summary that hides inventions by default
        made `clean` and `summary` disagree about the same report."""
        bad = self.holds(hold_invented=hold_invented)
        if not bad:
            return "every value is accounted for"
        contra = [o.name for o in bad if o.origin == MISMATCH]
        made_up = [o.name for o in bad if o.origin == UNSOURCED]
        parts = []
        if contra:
            parts.append(f"{len(contra)} value{'s' if len(contra) > 1 else ''} "
                         f"the operator asked for differently: {', '.join(contra[:4])}")
        if made_up:
            parts.append(f"{len(made_up)} value{'s' if len(made_up) > 1 else ''} "
                         f"nobody asked for: {', '.join(made_up[:4])}")
        return "; ".join(parts)


def _fold(text) -> str:
    """Lowercase, strip accents, collapse whitespace. Comparison form only."""
    s = unicodedata.normalize("NFKD", str(text or ""))
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", s).strip().lower()


def _numbers(text: str) -> set:
    """Every number a human might have written, normalized to a float.

    '25k', '25,000', '$25,000.00' and '25000' all land on 25000.0, so an agent that
    renders the operator's own figure in a different notation is not inventing it.
    """
    found = set()
    for raw, suffix in _NUMBER_RE.findall(text or ""):
        try:
            value = float(re.sub(r"[,\s]", "", raw))
        except ValueError:
            continue
        found.add(value)
        if suffix:
            found.add(value * _SUFFIX[suffix.lower()])
    return found


# ── dates ───────────────────────────────────────────────────────────────────
# Dates are the second class with a canonical form, and the one that carries the
# most real harm: bookings, transfers, schedules, expiries, access windows. Without
# this, "1st of January" and "2024-01-01" do not match, so an HONEST booking is
# flagged exactly as loudly as a rewritten one, which is a 100% false positive and
# the fastest way to get a control switched off.
#
# The year is deliberately allowed to be unknown. People say "the 1st of January"
# and mean the one coming; the agent renders a full date. Matching on month and day
# is what makes those the same date, and it is why a rewrite from January to May
# still fails to match.
_MONTHS = {m: i for i, m in enumerate(
    ("january", "february", "march", "april", "may", "june", "july",
     "august", "september", "october", "november", "december"), 1)}
_MONTHS.update({m[:3]: i for m, i in list(_MONTHS.items())})
_MONTH_RE = "|".join(sorted(_MONTHS, key=len, reverse=True))

# 2024-05-01, 2024/05/01
_ISO_RE = re.compile(r"\b(\d{4})[-/](\d{1,2})[-/](\d{1,2})\b")
# 1st of January, 1 Jan, January 1st, Jan 1 2024
_DMY_RE = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?({_MONTH_RE})\b",
                     re.I)
_MDY_RE = re.compile(rf"\b({_MONTH_RE})\s+(\d{{1,2}})(?:st|nd|rd|th)?\b", re.I)


def dates_in(text: str) -> set:
    """Every (month, day) a human might have written, plus (year, month, day).

    Both shapes are returned so a value carrying a year can match an operator who
    did not give one, without letting a bare (month, day) match a different year
    when both sides do state it.
    """
    found = set()
    raw = str(text or "")
    for y, m, d in _ISO_RE.findall(raw):
        m, d = int(m), int(d)
        if 1 <= m <= 12 and 1 <= d <= 31:
            found.add((m, d))
            found.add((int(y), m, d))
    for d, m in _DMY_RE.findall(raw):
        if 1 <= int(d) <= 31:
            found.add((_MONTHS[m.lower()], int(d)))
    for m, d in _MDY_RE.findall(raw):
        if 1 <= int(d) <= 31:
            found.add((_MONTHS[m.lower()], int(d)))
    return found


def _as_date(value):
    """The (month, day) forms a single argument value denotes, or an empty set.

    Deliberately NOT a general date parser. An ambiguous numeric form like 01/05
    is left unmatched rather than guessed at, because guessing US or EU ordering
    would silently authorize the wrong day, and being unmatched only costs a
    review.
    """
    return dates_in(value) if isinstance(value, str) else set()


def _as_number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = re.sub(r"[^\d.\-]", "", str(value or ""))
    if not text or text in ("-", ".", "-."):
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _scalars(value, depth: int = 0):
    """Flatten a nested argument into the scalars actually worth tracing."""
    if depth > 4:
        return
    if isinstance(value, dict):
        for v in value.values():
            yield from _scalars(v, depth + 1)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _scalars(v, depth + 1)
    elif value is not None and not isinstance(value, bool):
        yield value


def trace_value(value, *, operator_text: str = "",
                state_values: Optional[Iterable] = None):
    """(origin, detail) for one scalar."""
    text = _fold(operator_text)
    folded = _fold(value)

    # STATE first. A value the operator's own system supplied is accounted for even
    # when the operator never uttered it, which is what keeps account numbers and
    # known payees from drowning the report.
    for known in (state_values or ()):
        k = _fold(known)
        if k and k == folded:
            return STATE, f"supplied by your system ({known})"

    if not folded:
        return UNSOURCED, "empty"
    if text:
        # Boundary-anchored, never a bare substring. 'adm' must not match 'admin':
        # a loose match is a silent false NEGATIVE, which is the direction that
        # lets an invented value claim the operator asked for it.
        if re.search(r"(?<!\w)" + re.escape(folded) + r"(?!\w)", text):
            return OPERATOR, f"from '{value}'"
        # Dates before numbers: "2024-05-01" is a date, and letting the number
        # path see it as 20240501 would compare it against figures the operator
        # wrote as amounts, which is meaningless in both directions.
        mine = _as_date(value)
        if mine:
            theirs = dates_in(text)
            mine_full = {t for t in mine if len(t) == 3}
            theirs_full = {t for t in theirs if len(t) == 3}
            # When BOTH sides state a year, compare years. Falling back to month
            # and day here would let a rewrite from 2024 to 2023 pass as the
            # operator's own date, which is the same attack a month later.
            if mine_full and theirs_full:
                if mine_full & theirs_full:
                    return OPERATOR, f"the date {value} is one the operator gave"
                return MISMATCH, f"the operator gave a date, but not {value}"
            # Otherwise one side left the year open ("the 1st of January"), so
            # month and day are all there is to agree on.
            if {t for t in mine if len(t) == 2} & {t for t in theirs if len(t) == 2}:
                return OPERATOR, f"the date {value} is one the operator gave"
            if theirs:
                return MISMATCH, f"the operator gave a date, but not {value}"
            return UNSOURCED, "nobody named a date"
        number = _as_number(value)
        if number is not None:
            theirs = _numbers(text)
            if number in theirs:
                return OPERATOR, f"from the figure {value}"
            if theirs:
                return MISMATCH, f"the operator gave a figure, but not {value}"
    return UNSOURCED, "nobody named this"


def trace_arguments(arguments: Optional[dict], *, operator_text: str = "",
                    state_values: Optional[Iterable] = None,
                    expected_unsourced: Iterable = ()) -> ProvenanceReport:
    """Classify every argument of a proposed action by where its value came from.

    `expected_unsourced` names arguments a deployment ACCEPTS the agent filling in:
    currency, timezone, page size. Declaring them is what makes this usable rather
    than a machine for holding ordinary work. They are reported as STATE with the
    reason recorded, never silently dropped, so the report still shows the operator
    what was assumed on their behalf.
    """
    report = ProvenanceReport()
    expected = {str(n) for n in (expected_unsourced or ())}
    known = list(state_values or ())

    for name, value in (arguments or {}).items():
        parts = list(_scalars(value))
        if not parts:
            continue
        if str(name) in expected:
            report.origins.append(Origin(str(name), value, STATE,
                                         "declared default for this tool"))
            continue
        # A compound argument is only accounted for when EVERY scalar in it is. One
        # unsourced recipient hidden in a cc list is the whole attack, so the worst
        # scalar decides the field. Ranked explicitly rather than with a chain of
        # ifs: the first version handled only two of the four origins, so a
        # MISMATCH silently kept its field reported as OPERATOR.
        worst, detail = OPERATOR, ""
        for part in parts:
            origin, why = trace_value(part, operator_text=operator_text,
                                      state_values=known)
            if _RANK[origin] > _RANK[worst]:
                worst, detail = origin, why
            elif not detail:
                detail = why
            if worst == MISMATCH:
                break
        report.origins.append(Origin(str(name), value, worst, detail))
    return report
