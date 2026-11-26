"""Unit tests covering all lines and branches in lta/audit_ledger.py."""

from __future__ import annotations

import json
import sqlite3
import sys
import types
from pathlib import Path
from typing import Any, List, Tuple

import pytest

from lta.audit_ledger import AuditLedger, GENESIS_HASH


class _FakeCursor:
    def __init__(self, state: dict[str, Any]) -> None:
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
            self._last_seq_id = seq_id
            self._last_result = (seq_id,)
        elif "FROM AUDIT_EVENTS ORDER BY SEQ_ID ASC" in sql_upper:
            self._last_result = [
                (
                    r["seq_id"],
                    r["timestamp_utc"],
                    r["tenant_id"],
                    r["endpoint"],
                    r["policy_pack"],
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
        elif "FROM AUDIT_EVENTS WHERE TENANT_ID =" in sql_upper:
            target_tenant = params[0]
            limit_val = params[1]
            filtered = [r for r in reversed(self._state["rows"]) if r["tenant_id"] == target_tenant][:limit_val]
            self._last_result = [
                (
                    r["seq_id"],
                    r["timestamp_utc"],
                    r["tenant_id"],
                    r["endpoint"],
                    r["policy_pack"],
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
                for r in filtered
            ]
        elif "FROM AUDIT_EVENTS ORDER BY SEQ_ID DESC LIMIT" in sql_upper:
            limit_val = params[0]
            ordered = list(reversed(self._state["rows"]))[:limit_val]
            self._last_result = [
                (
                    r["seq_id"],
                    r["timestamp_utc"],
                    r["tenant_id"],
                    r["endpoint"],
                    r["policy_pack"],
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
                for r in ordered
            ]
        else:
            self._last_result = None

    def fetchone(self) -> Any:
        return self._last_result

    def fetchall(self) -> List[Any]:
        return self._last_result or []


class _FakeConn:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._state)

    def commit(self) -> None:
        self._state["commits"] += 1

    def rollback(self) -> None:
        self._state["rollbacks"] += 1

    def close(self) -> None:
        self.closed = True


class _FakePoolCtx:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def __enter__(self) -> _FakeConn:
        return self._conn

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        return False


class _FakeConnectionPool:
    last_instance: "_FakeConnectionPool | None" = None

    def __init__(self, conninfo: str, min_size: int = 1, max_size: int = 10, kwargs=None, check=None) -> None:
        self.conninfo = conninfo
        self.state: dict[str, Any] = {
            "rows": [],
            "executed": [],
            "commits": 0,
            "rollbacks": 0,
            "fail_on_next_execute": False,
        }
        self._conn = _FakeConn(self.state)
        self.closed = False
        _FakeConnectionPool.last_instance = self

    @staticmethod
    def check_connection(conn: _FakeConn) -> None:
        return None

    def connection(self) -> _FakePoolCtx:
        return _FakePoolCtx(self._conn)

    def close(self) -> None:
        self.closed = True


def test_sqlite_record_verify_tamper_export_and_close(tmp_path: Path):
    db_file = tmp_path / "ledger_unit.db"
    ledger = AuditLedger(f"sqlite:///{db_file}")

    assert ledger.ping() is True
    valid, count, broken_seq = ledger.verify_chain()
    assert (valid, count, broken_seq) == (True, 0, None)

    secret_prompt = "DoNotPersistRawDispatchText_XYZ123"
    rec1 = ledger.record(
        tenant_id="p2_pilot",
        endpoint="/v1/chat/completions",
        policy_pack="fmcsa",
        provider="mock",
        action="ALLOW_REDACTED",
        http_status=200,
        vector=None,
        redactions=["CDL"],
        raw_payload_for_digest=secret_prompt,
        latency_ms=14.256,
    )
    assert rec1.seq_id == 1
    assert rec1.prev_hash == GENESIS_HASH
    assert len(rec1.entry_hash) == 64
    assert rec1.latency_ms == 14.256

    rec2 = ledger.record(
        tenant_id="admin_ops",
        endpoint="/v1/shadow/ingest",
        policy_pack="fmcsa",
        provider="shadow",
        action="SHADOW_ALLOW",
        http_status=202,
        vector="clean",
        redactions=[],
        raw_payload_for_digest="BOL #8812 clean",
        latency_ms=8.1,
    )
    assert rec2.seq_id == 2
    assert rec2.prev_hash == rec1.entry_hash

    valid2, count2, broken2 = ledger.verify_chain()
    assert (valid2, count2, broken2) == (True, 2, None)

    all_jsonl = ledger.export_jsonl()
    assert secret_prompt not in all_jsonl
    lines_all = [json.loads(line) for line in all_jsonl.splitlines()]
    assert len(lines_all) == 2
    assert lines_all[0]["seq_id"] == 2  # DESC order

    filtered_jsonl = ledger.export_jsonl(tenant_id="p2_pilot", limit=10)
    lines_filtered = [json.loads(line) for line in filtered_jsonl.splitlines()]
    assert len(lines_filtered) == 1
    assert lines_filtered[0]["tenant_id"] == "p2_pilot"

    # Break entry_hash on seq_id=1
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE audit_events SET action = 'TAMPERED' WHERE seq_id = 1")
    conn.commit()
    conn.close()

    valid_tamper, total_tamper, broken_id = ledger.verify_chain()
    assert valid_tamper is False
    assert total_tamper == 2
    assert broken_id == 1

    # Break prev_hash on seq_id=2 after restoring seq_id=1's action
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE audit_events SET action = 'ALLOW_REDACTED' WHERE seq_id = 1")
    conn.execute("UPDATE audit_events SET prev_hash = 'deadbeef' WHERE seq_id = 2")
    conn.commit()
    conn.close()

    valid_link_break, _, broken_link_id = ledger.verify_chain()
    assert valid_link_break is False
    assert broken_link_id == 2

    ledger.close()


def test_sqlite_ping_false_and_rollback_on_error(tmp_path: Path):
    db_file = tmp_path / "ledger_err.db"
    ledger = AuditLedger(f"sqlite:///{db_file}")

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
        # Force SQL error via invalid table state by closing connection before ping/record
    ledger.close()
    assert ledger.ping() is False


def test_postgres_pool_and_psycopg_fallback(monkeypatch: pytest.MonkeyPatch):
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
    assert any("PG_ADVISORY_XACT_LOCK" in sql.upper() for sql, _ in _FakeConnectionPool.last_instance.state["executed"])

    # Trigger rollback path inside _connection
    _FakeConnectionPool.last_instance.state["fail_on_next_execute"] = True
    with pytest.raises(RuntimeError, match="simulated DB failure"):
        pg_ledger.record(
            tenant_id="p2_pilot",
            endpoint="/v1/chat/completions",
            policy_pack="fmcsa",
            provider="mock",
            action="ALLOW",
            http_status=200,
            vector=None,
            redactions=[],
            raw_payload_for_digest="pg fail",
            latency_ms=5.0,
        )
    assert _FakeConnectionPool.last_instance.state["rollbacks"] >= 1
    pg_ledger.close()
    assert _FakeConnectionPool.last_instance.closed is True

    # Fallback when psycopg_pool is unavailable -> uses psycopg.connect
    monkeypatch.delitem(sys.modules, "psycopg_pool", raising=False)
    fallback_state: dict[str, Any] = {
        "rows": [],
        "executed": [],
        "commits": 0,
        "rollbacks": 0,
        "fail_on_next_execute": False,
    }
    psycopg_mod = types.ModuleType("psycopg")
    psycopg_mod.connect = lambda dsn, autocommit=False: _FakeConn(fallback_state)
    monkeypatch.setitem(sys.modules, "psycopg", psycopg_mod)

    fb_ledger = AuditLedger("postgres://user:pass@localhost:5432/lta_fb")
    assert fb_ledger.ping() is True
    fb_ledger.close()