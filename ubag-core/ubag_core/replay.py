"""
A replay store that survives more than one process.

WHY THIS EXISTS
`InMemoryReplayStore` makes a receipt single-use *within one Python process*. That
is honest protection for a single-instance deployment and it is silently worthless
the moment there are two: the same receipt redeemed against two workers is accepted
twice, because neither has heard of the other. Nothing errors, nothing logs, the
guarantee just quietly stops being true. That is the worst shape a security control
can fail in.

This is the same port backed by SQLite, so the guarantee holds across every process
on a host, with no service to run and no dependency to install.

    store = SqliteReplayStore("/var/lib/ubag/replay.db")
    verify_receipt(pub, tool, args, receipt, replay_store=store, consume=True)

WHAT IT IS AND IS NOT
It is correct across processes on ONE machine. It is not a distributed store: a
fleet spread over several hosts needs a shared one, and the port is deliberately two
methods so Redis (`SET key val NX PX ttl`) or Firestore (a transaction) drop in
behind the same interface. The rule that matters is the one this file exists to
enforce: **the check and the record must be a single atomic step.** A read followed
by a write is a race, and the window is exactly when an attacker replays.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import sqlite3
import threading

from .capability import ReplayStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ubag_replay (
    jti TEXT PRIMARY KEY,
    exp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ubag_replay_exp ON ubag_replay (exp);
"""


class SqliteReplayStore(ReplayStore):
    """Cross-process single-use enforcement for receipts and capability grants."""

    def __init__(self, path: str, *, timeout: float = 5.0):
        self._lock = threading.Lock()
        # isolation_level=None hands transaction control to us, which is what makes
        # BEGIN IMMEDIATE below meaningful rather than decorative.
        self._db = sqlite3.connect(path, timeout=timeout, isolation_level=None,
                                   check_same_thread=False)
        # WAL is what lets a second process read while this one writes. Without it
        # concurrent access degrades to lock contention and timeouts, and a store
        # that times out under load fails in the direction of accepting nothing,
        # which is safe but unusable.
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:                        # pragma: no cover
            pass                                             # :memory: and some FS
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)

    def seen_or_record(self, jti: str, exp: float, now: float) -> bool:
        """True if this jti was already used. Atomic: one statement decides.

        The insert IS the check. `INSERT OR IGNORE` either claims the id or does
        not, and `rowcount` reports which, so there is no window between asking and
        recording for a second caller to slip through.
        """
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                # Expired ids are indistinguishable from unused ones, matching
                # InMemoryReplayStore. In practice an expired receipt is rejected
                # before it ever reaches a store, so this only bounds growth.
                self._db.execute("DELETE FROM ubag_replay WHERE exp < ?", (now,))
                cur = self._db.execute(
                    "INSERT OR IGNORE INTO ubag_replay (jti, exp) VALUES (?, ?)",
                    (str(jti), float(exp)))
                claimed = cur.rowcount == 1
                self._db.execute("COMMIT")
            except sqlite3.DatabaseError:
                # Fail CLOSED. An unreachable replay store must report "already
                # used" so the caller refuses, never "fresh" so it proceeds.
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.DatabaseError:                # pragma: no cover
                    pass
                return True
            return not claimed

    def close(self) -> None:
        with self._lock:
            self._db.close()
