"""Policy proposals derived from a shadow observation window.

`shadow.py` answers "what would UBAG have done". This answers the question an
operator asks straight afterwards: "so what should I actually switch on?"

The naive version of this feature is a security hole. An agent under prompt
injection produces exactly what a learner reads as demand: the same refused
action, over and over, with rising frequency. Count refusals and propose the
most frequent ones and you have built a system that reads an attack off the wire
and recommends it as policy. In our own demo the agent repeatedly tries to
cancel a stranger's booking; a frequency-ranked learner would propose granting
`cancel`, which is the Melbourne gym incident written as a checkbox.

So frequency is never the signal. The refusal CAUSE is:

    Tool ACL, and nothing else        the operator under-configured   -> candidate
    destination not allow-listed      might be config, might be exfil -> review
    ownership violation               that is the attack              -> finding
    attack memory, injection, breaker that is the attack              -> finding
    anything this module does not
    positively recognise              unknown                         -> finding

That last row is the load-bearing one. Causes are allow-listed into candidacy,
never deny-listed out of it, so a check added to the engine tomorrow cannot
silently start generating grant proposals. Same fail-closed posture as the engine
itself.

Nothing here applies anything. Every proposal comes out unselected, carrying the
evidence an operator needs to judge it, and an irreversible verb is separated out
and never presented as routine.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ubag_core import ALLOW, BLOCK, REVIEW, AuditRecord, JsonlAudit

# ---------------------------------------------------------------------------
# Refusal causes
# ---------------------------------------------------------------------------

CANDIDATE = "candidate"      # a real policy gap: propose it
REVIEW_REQUIRED = "review"   # could be a gap, could be an incident: make them look
FINDING = "finding"          # never a gap: this is the security report

# The one check that means "the operator did not grant this verb here". It is a
# candidate only when it is the SOLE check on the record, see classify().
ACL_CHECK = "Tool ACL"

# "the operator allow-listed destinations and this was not one of them". On a
# destination they already named it is a verb gap; anywhere else it is the agent
# reaching somewhere nobody planned, which is the exfiltration and SSRF shape.
DESTINATION_CHECK = "State: destination"

# The two checks that can mean "this was never granted here" and nothing worse.
# A refusal carrying only these is eligible; a refusal carrying anything else is
# not, however often it appears.
GAP_CHECKS = frozenset({ACL_CHECK, DESTINATION_CHECK})

# Checks that are a question about configuration rather than an accusation. A
# wrong tick here is still an incident, so they are surfaced separately and are
# never proposals.
REVIEW_CHECKS = {
    "State: destination": "the agent reached a destination that is not allow-listed",
    "Ownership: unproven": "nobody could say who owns the resource being acted on",
    "Ownership: unidentified resource": "an irreversible verb arrived without naming its target",
    "Verification floor": "high value with no positive ground-truth confirmation",
    "Value ceiling": "value above the configured block ceiling",
    "Value threshold": "value above the configured review threshold",
}

# Causes that are never, under any evidence, a policy gap. Kept explicit so the
# report can name them, not so classification can depend on the list.
FINDING_CHECKS = {
    "Ownership: not owned": "the agent acted on another principal's resource",
    "Attack memory": "matched a confirmed attack fingerprint",
    "Reason injection": "the stated reason carried an injection payload",
    "Identity revocation": "a revoked identity or blocked credential",
    "Identity resolution": "the agent's identity could not be resolved",
    "Argument schema": "malformed arguments",
    "State: amount": "an invalid or negative amount",
    "State: balance": "more than the account actually holds",
    "State: exposure": "beyond the standing exposure ceiling",
}

# Refusals the engine raises without a `check` flag. Recognised by reason prefix
# purely so the report can label them; none of them is ever a candidate.
REASON_MARKERS = (
    ("capability:", "capability grant missing or invalid"),
    ("argument injection:", "injection payload inside the arguments"),
    ("circuit breaker:", "velocity, cost or loop breaker"),
    ("behavioral reason signals", "behavioral signals in the stated reason"),
    ("attack memory:", "matched a confirmed attack fingerprint"),
    ("plan accumulation:", "the plan as a whole crossed a ceiling"),
    ("unsafe reason payload:", "the stated reason carried an injection payload"),
    ("grounding:", "an unverifiable or contradicted premise"),
)

# Verbs that commit the instant they touch the world. Mirrors the web layer's
# vocabulary deliberately; duplicated rather than imported because ubag-mcp sits
# underneath ubagweb and must not depend upward.
IRREVERSIBLE_VERBS = frozenset({"cancel", "execute", "delete", "transfer", "send", "pay"})


def verb_of(tool: str) -> str:
    """`booking.cancel` -> `cancel`. The suffix after the last dot."""
    return str(tool or "").rsplit(".", 1)[-1].strip().lower()


def resource_of(tool: str) -> str:
    """`booking.cancel` -> `booking`. Empty when the tool carries no namespace."""
    text = str(tool or "").strip()
    return text.rsplit(".", 1)[0] if "." in text else ""


def _checks(record: AuditRecord) -> set:
    return {str(f.get("check")) for f in (record.flags or [])
            if isinstance(f, dict) and f.get("check")}


def classify(record: AuditRecord, known_destinations=frozenset()) -> tuple:
    """Return (bucket, label) for one refused proposal.

    Candidacy requires the gap check to be the only thing that fired. Any
    co-occurring signal, and any cause this module does not positively
    recognise, demotes the record out of candidacy. Unknown is never a gap.

    `known_destinations` is the set the operator has already named somewhere in
    their policy. It is what separates the two things a destination refusal can
    mean, which the audit record alone cannot distinguish:

        cancel on a site already trusted for read   a verb gap      -> candidate
        anything on a site named nowhere            the agent went
                                                    somewhere new   -> review

    Supplying it is optional and never widens anything on its own: a destination
    the operator already wrote down is one they have already accepted, and the
    proposal is still only a proposal.
    """
    checks = _checks(record)
    reason = str(record.reason or "").lower()

    for marker, label in REASON_MARKERS:
        if marker in reason:
            return FINDING, label

    for name, label in FINDING_CHECKS.items():
        if name in checks:
            return FINDING, label

    # The gap checks fire together on the ordinary case: a verb that is not in
    # the registry is also not granted on any destination. That is one ground
    # stated twice, not two independent grounds, so the pair stays eligible
    # while anything outside the pair does not.
    if checks and checks <= GAP_CHECKS:
        # A destination the operator never named is not a gap in their policy,
        # it is the agent going somewhere they did not choose. Absent and
        # unknown are treated the same, which is the fail-closed reading.
        if DESTINATION_CHECK in checks or record.destination:
            if record.destination not in known_destinations:
                return REVIEW_REQUIRED, REVIEW_CHECKS[DESTINATION_CHECK]
            return CANDIDATE, "the verb is not granted on this destination"
        return CANDIDATE, "the verb is not granted at all"

    if checks & GAP_CHECKS:
        # Refused for a gap AND something else. The something else decides, and
        # co-occurrence alone is enough to disqualify.
        return FINDING, "refused on more than one ground"

    for name, label in REVIEW_CHECKS.items():
        if name in checks:
            return REVIEW_REQUIRED, label

    return FINDING, "refused for a cause this report does not classify"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """What actually happened, so an operator can judge a proposal.

    Deliberately not a score. A single number invites ticking whatever ranks
    highest, and ranking by volume is the failure mode this module exists to
    avoid.
    """
    tool: str
    destination: str = ""
    observations: int = 0
    agents: set = field(default_factory=set)
    principals: set = field(default_factory=set)
    tenants: set = field(default_factory=set)
    correlations: set = field(default_factory=set)
    days: set = field(default_factory=set)
    per_correlation: dict = field(default_factory=lambda: defaultdict(int))
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    labels: set = field(default_factory=set)

    def add(self, record: AuditRecord, label: str) -> None:
        self.observations += 1
        self.labels.add(label)
        if record.agent_id:
            self.agents.add(record.agent_id)
        if record.principal_id:
            self.principals.add(record.principal_id)
        if record.tenant_id:
            self.tenants.add(record.tenant_id)
        key = record.correlation_id or f"~{record.ts}"
        self.correlations.add(key)
        self.per_correlation[key] += 1
        self.days.add(_day(record.ts))
        self.first_seen = record.ts if self.first_seen is None else min(self.first_seen, record.ts)
        self.last_seen = record.ts if self.last_seen is None else max(self.last_seen, record.ts)

    @property
    def spread(self) -> str:
        """Sustained workload looks different from a burst, and only one of the
        two is evidence that a human meant it to happen."""
        if len(self.days) >= 2 and len(self.correlations) >= 2:
            return "recurring"
        if len(self.correlations) >= 2:
            return "repeated"
        return "single-session"

    def to_dict(self) -> dict:
        verb = verb_of(self.tool)
        return {
            "tool": self.tool,
            # A grant is a verb ON a destination. Proposing the verb alone would
            # widen it to every destination the agent can name, which is a
            # bigger grant than anything actually observed.
            "destination": self.destination,
            "grant": f"{self.destination}::{self.tool}" if self.destination else self.tool,
            "destination_known": bool(self.destination),
            "resource": resource_of(self.tool),
            "verb": verb,
            "irreversible": verb in IRREVERSIBLE_VERBS,
            "observations": self.observations,
            "distinct_agents": len(self.agents),
            "distinct_principals": len(self.principals),
            "distinct_tenants": len(self.tenants),
            "distinct_sessions": len(self.correlations),
            "days_observed": len(self.days),
            "busiest_session": max(self.per_correlation.values()) if self.per_correlation else 0,
            "spread": self.spread,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "why_refused": sorted(self.labels),
            # Nothing this module emits is ever pre-selected. Drafting is
            # automatic; granting is a person.
            "preselected": False,
        }


# ---------------------------------------------------------------------------
# The proposal
# ---------------------------------------------------------------------------

def propose_policy(records: Iterable[AuditRecord], *,
                   granted: Optional[Iterable[str]] = None,
                   known_destinations: Optional[Iterable[str]] = None) -> dict:
    """Draft a policy checklist from an observation window.

    `granted` is the tool list currently switched on. Supply it and the draft
    also reports grants that were never exercised, because least privilege runs
    in both directions and an unused grant is pure standing risk.

    `known_destinations` is every destination the operator has already named.
    See `classify`: it is what lets a missing verb on a trusted site be told
    apart from an agent reaching somewhere nobody planned.
    """
    known = frozenset(str(d) for d in (known_destinations or ()) if str(d).strip())
    observed = [r for r in records if r.decision in (ALLOW, REVIEW, BLOCK)]
    refused = [r for r in observed if r.decision in (REVIEW, BLOCK)]

    buckets: dict = {CANDIDATE: {}, REVIEW_REQUIRED: {}, FINDING: {}}
    for record in refused:
        bucket, label = classify(record, known)
        destination = str(record.destination or "")
        key = (record.tool, destination)
        evidence = buckets[bucket].setdefault(
            key, Evidence(tool=record.tool, destination=destination))
        evidence.add(record, label)

    exercised = {r.tool for r in observed if r.decision == ALLOW}
    proposals = [e.to_dict() for e in buckets[CANDIDATE].values()]
    reversible = [p for p in proposals if not p["irreversible"]]
    irreversible = [p for p in proposals if p["irreversible"]]

    timestamps = [r.ts for r in observed]
    draft = {
        "generated_from": "shadow observations",
        "observations": len(observed),
        "refusals": len(refused),
        "window": {"start": _iso(min(timestamps) if timestamps else None),
                   "end": _iso(max(timestamps) if timestamps else None),
                   "days": len({_day(t) for t in timestamps})},
        # Split so a UI cannot render the dangerous ones in the same list as the
        # routine ones, whatever it does with the rest of the payload.
        "proposals": _rank(reversible),
        "irreversible_proposals": _rank(irreversible),
        "review_required": _rank([e.to_dict() for e in buckets[REVIEW_REQUIRED].values()]),
        "findings": _rank([e.to_dict() for e in buckets[FINDING].values()]),
        "grants_exercised": sorted(exercised),
        "safety": {
            "auto_apply": False,
            "preselected": 0,
            "note": "Proposals are drafted from observed refusals and are never "
                    "applied. Ownership violations, injection and breaker events "
                    "can never become proposals, whatever their volume.",
        },
    }
    if granted is not None:
        current = sorted({str(t) for t in granted if str(t).strip()})
        draft["unused_grants"] = [t for t in current if t not in exercised]
        draft["grants_reviewed"] = len(current)
    return draft


def _rank(items: list) -> list:
    """Scoped before unscoped, recurring before bursty, then reach, then volume.

    Volume is the last tiebreak on purpose. An injection loop produces volume;
    it does not produce a proposal seen across many days, many sessions and many
    principals. A proposal whose destination is unknown ranks below one that can
    be scoped, because granting it means granting it everywhere.
    """
    order = {"recurring": 0, "repeated": 1, "single-session": 2}
    return sorted(items, key=lambda i: (not i["destination_known"],
                                        order.get(i["spread"], 3),
                                        -i["distinct_principals"],
                                        -i["days_observed"],
                                        -i["observations"],
                                        i["tool"], i["destination"]))


def render_policy_proposal(records: Iterable[AuditRecord], *,
                           granted: Optional[Iterable[str]] = None,
                           known_destinations: Optional[Iterable[str]] = None,
                           title: str = "UBAG Proposed Policy") -> str:
    draft = propose_policy(records, granted=granted,
                           known_destinations=known_destinations)
    window = draft["window"]
    lines = [
        f"# {title}",
        "",
        "Drafted from shadow observations. **Nothing here has been applied.** "
        "Every line is a proposal for a person to accept or reject.",
        "",
        f"- Proposals observed: **{draft['observations']}**",
        f"- Refused: **{draft['refusals']}**",
        f"- Window: {window['start'] or 'n/a'} to {window['end'] or 'n/a'} "
        f"({window['days']} day(s))",
        "",
        "## Proposed grants",
        "",
        "Refused only because the verb was not granted, on a destination the "
        "operator had already named. No other signal fired on these, which is "
        "what makes them candidates rather than findings.",
        "",
    ]
    lines.extend(_table(draft["proposals"]))

    lines.extend([
        "",
        "## Proposed grants that cannot be undone",
        "",
        "Separated because a wrong tick here is the incident, not a support "
        "ticket. Same evidence, higher bar, and no default.",
        "",
    ])
    lines.extend(_table(draft["irreversible_proposals"]))

    lines.extend(["", "## Needs a decision, not a tick", "",
                  "Could be a gap in the configuration, could be the first move of "
                  "an incident. The evidence here does not distinguish them, so "
                  "neither does this report.", "",
                  "| Destination | Tool | Times | Sessions | Why |",
                  "|---|---|---:|---:|---|"])
    lines.extend(f"| {i['destination'] or 'n/a'} | {i['tool']} | {i['observations']} "
                 f"| {i['distinct_sessions']} | {'; '.join(i['why_refused'])} |"
                 for i in draft["review_required"])
    if not draft["review_required"]:
        lines.append("| | Nothing | 0 | 0 | |")

    lines.extend(["", "## Findings: never proposable", "",
                  "Ownership violations, injection, revoked identity and breaker "
                  "trips. These are what the gateway is for. They do not become "
                  "policy at any frequency.", "",
                  "| Destination | Tool | Times | Sessions | Cause |",
                  "|---|---|---:|---:|---|"])
    lines.extend(f"| {i['destination'] or 'n/a'} | {i['tool']} | {i['observations']} "
                 f"| {i['distinct_sessions']} | {'; '.join(i['why_refused'])} |"
                 for i in draft["findings"])
    if not draft["findings"]:
        lines.append("| | Nothing | 0 | 0 | |")

    if "unused_grants" in draft:
        lines.extend(["", "## Granted but never used", "",
                      "Standing permission nobody exercised in this window. "
                      "Removing it costs nothing and shrinks the blast radius.", ""])
        lines.extend(f"- `{tool}`" for tool in draft["unused_grants"])
        if not draft["unused_grants"]:
            lines.append("- Every current grant was exercised.")

    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "These are counterfactual decisions from a shadow window. A proposal "
        "means the agent asked and policy refused; it does not mean the agent "
        "should have been allowed. That judgement is the operator's and this "
        "report deliberately does not make it.",
        "",
    ])
    return "\n".join(lines)


def _table(items: list) -> list:
    header = ["| Destination | Tool | Verb | Times | Sessions | Principals | Days | Pattern |",
              "|---|---|---|---:|---:|---:|---:|---|"]
    if not items:
        return header + ["| | Nothing proposed | | 0 | 0 | 0 | 0 | |"]
    return header + [
        f"| {i['destination'] or '**any (unscoped)**'} | {i['tool']} | {i['verb']} "
        f"| {i['observations']} | {i['distinct_sessions']} | {i['distinct_principals']} "
        f"| {i['days_observed']} | {i['spread']} |"
        for i in items]


def _iso(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _day(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Draft a UBAG policy checklist from a shadow audit log")
    parser.add_argument("audit", help="JSONL audit path")
    parser.add_argument("--granted", help="comma-separated tools currently granted")
    parser.add_argument("--known-destinations", dest="known",
                        help="comma-separated destinations already named in policy "
                             "(e.g. net:gym.example). Without these, a refusal on "
                             "any destination stays under review rather than "
                             "becoming a proposal.")
    parser.add_argument("--output", help="Markdown output path; stdout when omitted")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    args = parser.parse_args(argv)

    records = JsonlAudit(args.audit, fsync=False).records()
    csv = lambda raw: [t.strip() for t in raw.split(",") if t.strip()] if raw else None
    granted, known = csv(args.granted), csv(args.known)
    output = (json.dumps(propose_policy(records, granted=granted,
                                        known_destinations=known),
                         indent=2, sort_keys=True)
              if args.json else render_policy_proposal(records, granted=granted,
                                                       known_destinations=known))
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
