"""Unit tests for AuditLedger SQLite and PostgreSQL paths, provenance, and rollback."""

from __future__ import annotations

import json
import sqlite3
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from lta.audit_ledger import AuditLedger, GENESIS_HASH


class _FakeCursor:
    def __init__(self, state: Dict[str, Any]) -> None:
        self._state = state
        self._last_result: Any = None

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        sql_upper = sql.upper().strip()
        self._state["executed"].append((sql, params))
        if self._state.get("fail_on_next_execute"):
            self._state["fail_on_next_execute"] = False
            raise RuntimeError("simulated DB failure")

        if sql_upper.startswith("SELECT 1"):
            self._last_result = (1,)
        elif "ORDER BY SEQ_ID DESC LIMIT 1" in sql_upper:
            rows = self._state["rows"]
            self._last_result = (rows[-1]["entry_hash"],) if rows else None
        elif sql_upper.startswith("INSERT INTO AUDIT_EVENTS"):
            seq_id = len(self._state["rows"]) + 1
            (
                ts,
                tenant_id,
                endpoint,
                policy_pack,
                policy_version,
                policy_sha256,
                config_fingerprint,
                provenance_hash,
                provenance_json,
                provider,
                action,
                http_status,
                vector,
                redactions_json,
                payload_sha256,
                rounded_latency,
                prev_hash,
                entry_hash,
            ) = params
            self._state["rows"].append(
                {
                    "seq_id": seq_id,
                    "timestamp_utc": ts,
                    "tenant_id": tenant_id,
                    "endpoint": endpoint,
                    "policy_pack": policy_pack,
                    "policy_version": policy_version,
                    "policy_sha256": policy_sha256,
                    "config_fingerprint": config_fingerprint,
                    "provenance_hash": provenance_hash,
                    "provenance_json": provenance_json,
                    "provider": provider,
                    "action": action,
                    "http_status": http_status,
                    "vector": vector,
                    "redactions_json": redactions_json,
                    "payload_sha256": payload_sha256,
                    "latency_ms": rounded_latency,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                }
            )
            self._last_result = (seq_id,)
        elif "FROM AUDIT_EVENTS ORDER BY SEQ_ID ASC" in sql_upper:
            self._last_result = [
                (
                    r["seq_id"],
                    r["timestamp_utc"],
                    r["tenant_id"],
                    r["endpoint"],
                    r["policy_pack"],
                    r["policy_version"],
                    r["policy_sha256"],
                    r["config_fingerprint"],
                    r["provenance_hash"],
                    r["provenance_json"],
                    r["provider"],
                    r["action"],
                    r["http_status"],
                    r["vector"],
                    r["redactions_json"],
                    r["payload_sha256"],
                    r["latency_ms"],
                    r["prev_hash"],
                    r["entry_hash"],
                )
                for r in self._state["rows"]
            ]
        elif "FROM AUDIT_EVENTS" in sql_upper:
            self._last_result = [
                (
                    r["seq_id"],
                    r["timestamp_utc"],
                    r["tenant_id"],
                    r["endpoint"],
                    r["policy_pack"],
                    r["policy_version"],
                    r["policy_sha256"],
                    r["config_fingerprint"],
                    r["provenance_hash"],
                    r["provenance_json"],
                    r["provider"],
                    r["action"],
                    r["http_status"],
                    r["vector"],
                    r["redactions_json"],
                    r["payload_sha256"],
                    r["latency_ms"],
                    r["prev_hash"],
                    r["entry_hash"],
                )
                for r in self._state["rows"]
            ]
        else:
            self._last_result = None

    def fetchone(self) -> Any:
        return self._last_result

    def fetchall(self) -> List[Any]:
        if isinstance(self._last_result, list):
            return self._last_result
        return []


class _FakeConn:
    def __init__(self, state: Dict[str, Any]) -> None:
        self._state = state

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._state)

    def commit(self) -> None:
        self._state["commits"] += 1

    def rollback(self) -> None:
        self._state["rollbacks"] += 1

    def close(self) -> None:
        self._state["closed"] = True

    def __enter__(self) -> "_FakeConn":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is not None:
            self.rollback()
        return False


class _FakePoolCtx:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def __enter__(self) -> _FakeConn:
        return self._conn

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False


class _FakeConnectionPool:
    def __init__(self, conninfo: str, **kwargs: Any) -> None:
        self.conninfo = conninfo
        self.kwargs = kwargs
        self.state: Dict[str, Any] = {
            "rows": [],
            "executed": [],
            "commits": 0,
            "rollbacks": 0,
            "closed": False,
            "fail_on_next_execute": False,
        }
        self._conn = _FakeConn(self.state)

    @staticmethod
    def check_connection(conn: Any) -> None:
        return None

    def connection(self) -> _FakePoolCtx:
        return _FakePoolCtx(self._conn)

    def close(self) -> None:
        self.state["closed"] = True


def test_sqlite_record_verify_tamper_export_and_close(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger_unit.db"
    ledger = AuditLedger(f"sqlite:///{db_file}")
    assert ledger.ping() is True

    r1 = ledger.record(
        tenant_id="p2_pilot",
        endpoint="/v1/chat/completions",
        policy_pack="fmcsa",
        provider="mock",
        action="ALLOW",
        http_status=200,
        vector=None,
        redactions=[],
        raw_payload_for_digest="dispatch 1",
        latency_ms=4.25,
        policy_version="2.4.0",
        policy_sha256="a" * 64,
        config_fingerprint="b" * 64,
        request_id="req-1",
    )
    assert r1.seq_id == 1
    assert r1.prev_hash == GENESIS_HASH

    r2 = ledger.record(
        tenant_id="other_tenant",
        endpoint="/v1/chat/completions",
        policy_pack="fmcsa",
        provider="mock",
        action="ALLOW_REDACTED",
        http_status=200,
        vector=None,
        redactions=["ssn"],
        raw_payload_for_digest="dispatch 2",
        latency_ms=7.5,
        policy_version="2.4.0",
        policy_sha256="a" * 64,
        config_fingerprint="b" * 64,
        request_id="req-2",
    )
    assert r2.prev_hash == r1.entry_hash

    valid, total, broken = ledger.verify_chain()
    assert valid is True
    assert total == 2
    assert broken is None

    exported_p2 = ledger.export_jsonl(tenant_id="p2_pilot")
    lines = [json.loads(line) for line in exported_p2.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["tenant_id"] == "p2_pilot"
    assert lines[0]["policy_version"] == "2.4.0"

    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute("UPDATE audit_events SET action = 'TAMPERED' WHERE seq_id = 1")
        conn.commit()
    finally:
        conn.close()

    valid_after, total_after, broken_after = ledger.verify_chain()
    assert valid_after is False
    assert total_after == 2
    assert broken_after == 1

    ledger.close()
    assert ledger.ping() is False


def test_sqlite_ping_false_and_rollback_on_error(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger_err.db"
    ledger = AuditLedger(f"sqlite:///{db_file}")

    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("DROP TABLE audit_events")
    raw_conn.commit()
    raw_conn.close()

    with pytest.raises(sqlite3.OperationalError):
        ledger.record(
            tenant_id="p2_pilot",
            endpoint="/v1/chat/completions",
            policy_pack="fmcsa",
            provider="mock",
            action="ALLOW",
            http_status=200,
            vector=None,
            redactions=[],
            raw_payload_for_digest="x",
            latency_ms=1.0,
        )

    ledger.close()
    assert ledger.ping() is False


def test_postgres_pool_and_psycopg_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    pool_mod = types.ModuleType("psycopg_pool")
    pool_mod.ConnectionPool = _FakeConnectionPool
    monkeypatch.setitem(sys.modules, "psycopg_pool", pool_mod)

    pg_ledger = AuditLedger("postgresql://user:pass@localhost:5432/lta")
    assert pg_ledger.ping() is True

    rec = pg_ledger.record(
        tenant_id="p2_pilot",
        endpoint="/v1/chat/completions",
        policy_pack="fmcsa",
        provider="mock",
        action="ALLOW",
        http_status=200,
        vector=None,
        redactions=[],
        raw_payload_for_digest="pg payload",
        latency_ms=5.0,
    )
    assert rec.seq_id == 1

    valid, total, broken = pg_ledger.verify_chain()
    assert valid is True
    assert total == 1
    assert broken is None

    pg_ledger.close()
    assert pg_ledger.ping() is False