"""PostgreSQL shared-state adapter for breaker and capability replay controls.

The deployment supplies a DB-API connection factory (for example psycopg.connect).
Core remains dependency-free; this adapter performs each state transition under a
PostgreSQL transaction-scoped advisory lock.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from ubag_core import BreakerStore, ReplayStore
from .gateway_state import GatewayStateStore


class PostgresSecurityStore(BreakerStore, ReplayStore, GatewayStateStore):
    def __init__(self, connection_factory: Callable):
        self._connect = connection_factory

    def initialize(self) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ubag_breaker_events (
                    scope TEXT NOT NULL,
                    occurred_at DOUBLE PRECISION NOT NULL,
                    signature TEXT NOT NULL,
                    cost DOUBLE PRECISION NOT NULL
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS ubag_breaker_scope_time
                ON ubag_breaker_events (scope, occurred_at)
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ubag_grant_replay (
                    jti TEXT PRIMARY KEY,
                    expires_at DOUBLE PRECISION NOT NULL
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS ubag_grant_replay_expiry
                ON ubag_grant_replay (expires_at)
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ubag_gateway_plans (
                    session_id TEXT PRIMARY KEY,
                    owner_key TEXT NOT NULL,
                    items JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_at DOUBLE PRECISION NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ubag_execution_correlations (
                    correlation_id TEXT PRIMARY KEY,
                    owner_key TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    occurred_at DOUBLE PRECISION NOT NULL
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS ubag_execution_correlation_time
                ON ubag_execution_correlations (occurred_at)
            """)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _lock(cur, namespace: str, key: str) -> None:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (namespace + ":" + key,))

    def record(self, scope: str, *, now: float, window_s: float,
               loop_window_s: float, signature: str, cost: float):
        conn = self._connect()
        try:
            cur = conn.cursor()
            self._lock(cur, "breaker", scope)
            cur.execute("DELETE FROM ubag_breaker_events WHERE scope=%s AND occurred_at < %s",
                        (scope, now - window_s))
            cur.execute("INSERT INTO ubag_breaker_events(scope, occurred_at, signature, cost) "
                        "VALUES (%s, %s, %s, %s)", (scope, now, signature, float(cost)))
            cur.execute("""
                SELECT COALESCE(SUM(cost), 0),
                       COUNT(*) FILTER (WHERE signature=%s AND occurred_at >= %s)
                FROM ubag_breaker_events WHERE scope=%s
            """, (signature, now - loop_window_s, scope))
            total, repeats = cur.fetchone()
            conn.commit()
            return float(total), int(repeats)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def reset(self, scope: Optional[str] = None):
        conn = self._connect()
        try:
            cur = conn.cursor()
            if scope is None:
                cur.execute("DELETE FROM ubag_breaker_events")
            else:
                self._lock(cur, "breaker", scope)
                cur.execute("DELETE FROM ubag_breaker_events WHERE scope=%s", (scope,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def seen_or_record(self, jti: str, exp: float, now: float) -> bool:
        conn = self._connect()
        try:
            cur = conn.cursor()
            self._lock(cur, "grant", jti)
            cur.execute("DELETE FROM ubag_grant_replay WHERE expires_at < %s", (now,))
            cur.execute("INSERT INTO ubag_grant_replay(jti, expires_at) VALUES (%s, %s) "
                        "ON CONFLICT (jti) DO NOTHING", (jti, exp))
            replayed = cur.rowcount == 0
            conn.commit()
            return replayed
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_plan(self, session_id: str, owner_key: str, created_at: float) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO ubag_gateway_plans(session_id, owner_key, items, created_at) "
                "VALUES (%s, %s, '[]'::jsonb, %s)",
                (session_id, owner_key, created_at))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def append_plan(self, session_id: str, owner_key: str, item: dict) -> int:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT owner_key, items FROM ubag_gateway_plans "
                "WHERE session_id=%s FOR UPDATE", (session_id,))
            row = cur.fetchone()
            if row is None:
                raise KeyError("unknown or closed plan session")
            if row[0] != owner_key:
                raise PermissionError(
                    "plan session belongs to a different security context")
            items = json.loads(row[1]) if isinstance(row[1], str) else list(row[1])
            items.append(item)
            cur.execute("UPDATE ubag_gateway_plans SET items=%s::jsonb WHERE session_id=%s",
                        (json.dumps(items, separators=(",", ":")), session_id))
            conn.commit()
            return len(items)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def pop_plan(self, session_id: str, owner_key: str) -> list[dict]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT owner_key, items FROM ubag_gateway_plans "
                "WHERE session_id=%s FOR UPDATE", (session_id,))
            row = cur.fetchone()
            if row is None:
                raise KeyError("unknown or already-closed plan session")
            if row[0] != owner_key:
                raise PermissionError(
                    "plan session belongs to a different security context")
            items = json.loads(row[1]) if isinstance(row[1], str) else list(row[1])
            cur.execute("DELETE FROM ubag_gateway_plans WHERE session_id=%s", (session_id,))
            conn.commit()
            return items
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def remember_execution(self, correlation_id: str, owner_key: str,
                           tool_name: str, occurred_at: float) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM ubag_execution_correlations WHERE occurred_at < %s",
                        (occurred_at - 86400.0,))
            cur.execute(
                "INSERT INTO ubag_execution_correlations"
                "(correlation_id, owner_key, tool_name, occurred_at) "
                "VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (correlation_id) DO UPDATE SET "
                "owner_key=EXCLUDED.owner_key, tool_name=EXCLUDED.tool_name, "
                "occurred_at=EXCLUDED.occurred_at",
                (correlation_id, owner_key, tool_name, occurred_at))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_execution(self, correlation_id: str):
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT owner_key, tool_name, occurred_at "
                "FROM ubag_execution_correlations WHERE correlation_id=%s",
                (correlation_id,))
            row = cur.fetchone()
            return tuple(row) if row is not None else None
        finally:
            conn.close()
