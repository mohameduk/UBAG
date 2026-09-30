"""Real PostgreSQL concurrency tests (requires UBAG_TEST_POSTGRES_DSN)."""
import os
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ubag-core"))
sys.path.insert(0, str(ROOT / "ubag-mcp"))

psycopg = pytest.importorskip("psycopg")

from ubag_mcp import PostgresSecurityStore


DSN = os.environ.get("UBAG_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="set UBAG_TEST_POSTGRES_DSN for integration test")


def _store():
    return PostgresSecurityStore(lambda: psycopg.connect(DSN))


def test_same_jti_concurrent_double_spend_exactly_one_wins():
    store_a, store_b = _store(), _store()
    store_a.initialize()
    jti = "race-" + uuid.uuid4().hex
    barrier = threading.Barrier(3)
    results, errors = [], []

    def attempt(store):
        try:
            barrier.wait(timeout=10)
            results.append(store.seen_or_record(jti, time.time() + 60, time.time()))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(store_a,)),
               threading.Thread(target=attempt, args=(store_b,))]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=15)

    assert not errors
    assert not any(thread.is_alive() for thread in threads)
    assert sorted(results) == [False, True]  # first use, then replay
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ubag_grant_replay WHERE jti=%s", (jti,))
            assert cur.fetchone()[0] == 1


def test_same_jti_remains_single_winner_under_repeated_contention():
    store = _store()
    store.initialize()
    for _ in range(20):
        jti = "stress-" + uuid.uuid4().hex
        barrier = threading.Barrier(9)
        results = []

        def attempt():
            barrier.wait(timeout=10)
            results.append(store.seen_or_record(jti, time.time() + 60, time.time()))

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=15)
        assert results.count(False) == 1
        assert results.count(True) == 7


def test_plan_and_correlation_state_crosses_store_instances():
    first, second = _store(), _store()
    first.initialize()
    session = "plan-" + uuid.uuid4().hex
    owner = "tenant-a|principal-a"
    first.create_plan(session, owner, time.time())
    assert second.append_plan(
        session, owner,
        {"tool": "trade", "args": {"amount": 1}, "grant": None, "claims": []}) == 1
    items = first.pop_plan(session, owner)
    assert items[0]["tool"] == "trade"

    correlation = "corr-" + uuid.uuid4().hex
    first.remember_execution(correlation, owner, "trade", time.time())
    resolved = second.get_execution(correlation)
    assert resolved[:2] == (owner, "trade")
