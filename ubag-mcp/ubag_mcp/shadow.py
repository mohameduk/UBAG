"""Shadow-pilot reporting over UBAG audit records."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ubag_core import ALLOW, BLOCK, REVIEW, AuditRecord, JsonlAudit


POLICY_DECISIONS = {ALLOW, REVIEW, BLOCK}


def summarize_shadow(records: Iterable[AuditRecord]) -> dict:
    """Return a JSON-serializable counterfactual pilot summary."""
    decisions = [record for record in records if record.decision in POLICY_DECISIONS]
    decision_counts = Counter(record.decision for record in decisions)
    tool_counts = Counter(record.tool for record in decisions)
    reason_counts = Counter(record.reason for record in decisions)
    tenant_counts = Counter(record.tenant_id or "unattributed" for record in decisions)
    timestamps = [record.ts for record in decisions]
    total = len(decisions)
    return {
        "operating_mode": "SHADOW",
        "production_actions_interrupted": 0,
        "observations": total,
        "decisions": {name: decision_counts.get(name, 0)
                      for name in (ALLOW, REVIEW, BLOCK)},
        "would_restrict": decision_counts.get(REVIEW, 0) + decision_counts.get(BLOCK, 0),
        "would_restrict_rate": (
            (decision_counts.get(REVIEW, 0) + decision_counts.get(BLOCK, 0)) / total
            if total else 0.0),
        "tools": dict(tool_counts.most_common()),
        "tenants": dict(tenant_counts.most_common()),
        "top_reasons": [{"reason": reason, "count": count}
                        for reason, count in reason_counts.most_common(10)],
        "window": {
            "start": _iso(min(timestamps)) if timestamps else None,
            "end": _iso(max(timestamps)) if timestamps else None,
        },
    }


def render_shadow_report(records: Iterable[AuditRecord], *,
                         title: str = "UBAG Shadow Pilot Report") -> str:
    summary = summarize_shadow(records)
    decisions = summary["decisions"]
    lines = [
        f"# {title}",
        "",
        "Mode: **SHADOW** — UBAG observed and evaluated proposals; it did not "
        "interrupt the production execution path.",
        "",
        "## Executive summary",
        "",
        f"- Proposals observed: **{summary['observations']}**",
        f"- Would allow: **{decisions[ALLOW]}**",
        f"- Would review: **{decisions[REVIEW]}**",
        f"- Would block: **{decisions[BLOCK]}**",
        f"- Would restrict rate: **{summary['would_restrict_rate']:.1%}**",
        "- Production actions interrupted: **0**",
        "",
        "## Observation window",
        "",
        f"- Start: {summary['window']['start'] or 'n/a'}",
        f"- End: {summary['window']['end'] or 'n/a'}",
        "",
        "## Activity by tool",
        "",
        "| Tool | Proposals |",
        "|---|---:|",
    ]
    lines.extend(f"| {tool} | {count} |" for tool, count in summary["tools"].items())
    if not summary["tools"]:
        lines.append("| No observations | 0 |")
    lines.extend(["", "## Most frequent decision reasons", "",
                  "| Reason | Count |", "|---|---:|"])
    lines.extend(f"| {_markdown_cell(item['reason'])} | {item['count']} |"
                 for item in summary["top_reasons"])
    if not summary["top_reasons"]:
        lines.append("| No observations | 0 |")
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "These are counterfactual UBAG policy decisions from shadow observations. "
        "They do not prove that an upstream action executed, succeeded, or was prevented.",
        "",
    ])
    return "\n".join(lines)


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate a UBAG shadow-pilot report")
    parser.add_argument("audit", help="JSONL audit path")
    parser.add_argument("--output", help="Markdown output path; stdout when omitted")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    args = parser.parse_args(argv)
    records = JsonlAudit(args.audit, fsync=False).records()
    output = (json.dumps(summarize_shadow(records), indent=2, sort_keys=True)
              if args.json else render_shadow_report(records))
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
