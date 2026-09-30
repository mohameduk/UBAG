"""
Audit sink — append-only record of every decision.

Core defines the interface and ships an in-memory default. A production deployment
swaps in a durable, tamper-evident store (append-only DB, WORM bucket, hash chain)
without changing any calling code.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class AuditRecord:
    ts: float
    agent_id: str
    tool: str
    decision: str
    reason: str
    executed: bool
    signature: str = ""
    flags: list = field(default_factory=list)
    tenant_id: str = ""
    principal_id: str = ""
    account_id: str = ""
    credential_id: str = ""
    integration_id: str = ""
    correlation_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    # The policy-relevant object of the action (`net:gym.example`, `wallet:x`,
    # `booking:4471`). Not a payload value: arguments are deliberately never
    # recorded, and this is the one field policy is actually written against, so
    # a decision can be reviewed without reconstructing it out of prose. Optional
    # and defaulted, so audit lines written before this field still load.
    destination: str = ""


class AuditSink:
    """Interface. Implement `record` for a durable backend."""
    def record(self, rec: AuditRecord) -> None:                # pragma: no cover
        raise NotImplementedError


class InMemoryAudit(AuditSink):
    def __init__(self):
        self.records: list[AuditRecord] = []

    def record(self, rec: AuditRecord) -> None:
        self.records.append(rec)

    def recent(self, n: int = 50) -> list[AuditRecord]:
        return self.records[-n:]


class JsonlAudit(AuditSink):
    """Durable append-only JSON Lines audit sink for pilots and single hosts.

    PostgreSQL/WORM storage remains the appropriate multi-instance production
    choice.  This sink deliberately fsyncs each record by default so a process
    restart does not erase a pilot's observations.
    """
    def __init__(self, path, *, fsync: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fsync = fsync
        self._lock = threading.Lock()

    def record(self, rec: AuditRecord) -> None:
        line = json.dumps(asdict(rec), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                if self.fsync:
                    os.fsync(handle.fileno())

    def records(self) -> list[AuditRecord]:
        if not self.path.exists():
            return []
        result = []
        with self._lock:
            with self.path.open("r", encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        result.append(AuditRecord(**json.loads(line)))
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise ValueError(
                            f"invalid audit record at {self.path}:{number}") from exc
        return result

    def recent(self, n: int = 50) -> list[AuditRecord]:
        return self.records()[-n:]


def make_record(identity, tool: str, decision, executed: bool, *, correlation_id: str = "",
                plan_id: str = "", step_id: str = "",
                destination: str = "") -> AuditRecord:
    """Convenience: build a record from a PolicyDecision-like object."""
    return AuditRecord(
        ts=time.time(), agent_id=getattr(identity, "agent_id", str(identity)), tool=tool,
        decision=getattr(decision, "decision", str(decision)),
        reason=getattr(decision, "reason", ""),
        executed=executed,
        signature=getattr(decision, "signature", ""),
        flags=list(getattr(decision, "flags", []) or []),
        tenant_id=getattr(identity, "tenant_id", ""),
        principal_id=getattr(identity, "principal_id", ""),
        account_id=getattr(identity, "account_id", ""),
        credential_id=getattr(identity, "credential_id", ""),
        integration_id=getattr(identity, "integration_id", ""),
        correlation_id=correlation_id, plan_id=plan_id, step_id=step_id,
        destination=str(destination or ""),
    )
