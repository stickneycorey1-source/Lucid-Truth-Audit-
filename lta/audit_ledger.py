"""Tamper-evident SHA-256 hash-chained persistent audit ledger (Hardened v2.4).

Supports SQLite out of the box and PostgreSQL via `psycopg_pool.ConnectionPool`
(with fallback to `psycopg.connect`) using transactional `pg_advisory_xact_lock`,
automatic `rollback()` on errors, an O(1) `ping()` for `/readyz` probes, and a
composite `(tenant_id, seq_id DESC)` index for fast SIEM exports.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, List, Optional, Tuple


GENESIS_HASH = "0" * 64
PG_CHAIN_LOCK_ID = 728391045


@dataclass
class AuditRecord:
    seq_id: int
    timestamp_utc: str
    tenant_id: str
    endpoint: str
    policy_pack: str
    provider: str
    action: str
    http_status: int
    vector: Optional[str]
    redactions: List[str]
    payload_sha256: str
    latency_ms: float
    prev_hash: str
    entry_hash: str


def _normalize_redactions(redactions_value: Any) -> List[str]:
    if isinstance(redactions_value, list):
        return [str(item) for item in redactions_value]
    if isinstance(redactions_value, str) and redactions_value.strip():
        try:
            parsed = json.loads(redactions_value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except ValueError:
            pass
    return []


def _compute_entry_hash(
    prev_hash: str,
    timestamp_utc: str,
    tenant_id: str,
    endpoint: str,
    policy_pack: str,
    provider: str,
    action: str,
    http_status: int,
    vector: Optional[str],
    redactions_json: Any,
    payload_sha256: str,
    latency_ms: float,
) -> str:
    normalized_redactions = _normalize_redactions(redactions_json)
    canonical = json.dumps(
        {
            "prev_hash": str(prev_hash),
            "timestamp_utc": str(timestamp_utc),
            "tenant_id": str(tenant_id),
            "endpoint": str(endpoint),
            "policy_pack": str(policy_pack),
            "provider": str(provider),
            "action": str(action),
            "http_status": int(http_status),
            "vector": str(vector or ""),
            "redactions": normalized_redactions,
            "payload_sha256": str(payload_sha256),
            "latency_ms": round(float(latency_ms), 3),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLedger:
    """Append-only cryptographic hash-chained audit log (SQLite or PostgreSQL)."""

    def __init__(self, db_url: str = "sqlite:///./lta_audit_ledger.db") -> None:
        self.db_url = db_url
        self._lock = threading.Lock()
        self._is_postgres = db_url.startswith("postgresql://") or db_url.startswith(
            "postgres://"
        )
        self._pool = None
        self._conn = None

        if self._is_postgres:
            try:
                from psycopg_pool import ConnectionPool  # type: ignore

                self._pool = ConnectionPool(
                    conninfo=db_url,
                    min_size=1,
                    max_size=10,
                    kwargs={"autocommit": False},
                    check=ConnectionPool.check_connection,
                )
            except ImportError:
                import psycopg  # type: ignore

                self._conn = psycopg.connect(db_url, autocommit=False)
        else:
            path = db_url.replace("sqlite:///", "", 1)
            self._conn = sqlite3.connect(path, check_same_thread=False)

        self._init_schema()

    @contextmanager
    def _connection(self) -> Iterator[object]:
        if self._pool is not None:
            with self._pool.connection() as conn:
                try:
                    yield conn
                except Exception:
                    conn.rollback()
                    raise
        else:
            with self._lock:
                if self._conn is None:
                    path = self.db_url.replace("sqlite:///", "", 1)
                    self._conn = sqlite3.connect(path, check_same_thread=False)
                try:
                    yield self._conn
                except Exception:
                    self._conn.rollback()
                    raise

    def _init_schema(self) -> None:
        ddl = (
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                policy_pack TEXT NOT NULL,
                provider TEXT NOT NULL,
                action TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                vector TEXT,
                redactions_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
            if not self._is_postgres
            else """
            CREATE TABLE IF NOT EXISTS audit_events (
                seq_id BIGSERIAL PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                policy_pack TEXT NOT NULL,
                provider TEXT NOT NULL,
                action TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                vector TEXT,
                redactions_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                latency_ms DOUBLE PRECISION NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
        )
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(ddl)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_tenant_seq "
                "ON audit_events (tenant_id, seq_id DESC)"
            )
            conn.commit()

    def ping(self) -> bool:
        """Fast O(1) connectivity check for /readyz without scanning audit_events."""
        try:
            with self._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        except Exception:
            return False

    def record(
        self,
        *,
        tenant_id: str,
        endpoint: str,
        policy_pack: str,
        provider: str,
        action: str,
        http_status: int,
        vector: Optional[str],
        redactions: List[str],
        raw_payload_for_digest: str,
        latency_ms: float,
    ) -> AuditRecord:
        """Append a tamper-evident audit event without persisting raw prompt text."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload_sha256 = hashlib.sha256(
            raw_payload_for_digest.encode("utf-8")
        ).hexdigest()
        normalized_redactions = _normalize_redactions(redactions)
        redactions_json = json.dumps(normalized_redactions, separators=(",", ":"))
        rounded_latency = round(float(latency_ms), 3)
        normalized_vector = str(vector or "")

        with self._connection() as conn:
            cur = conn.cursor()
            if self._is_postgres:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (PG_CHAIN_LOCK_ID,))
            cur.execute(
                "SELECT entry_hash FROM audit_events ORDER BY seq_id DESC LIMIT 1"
            )
            row = cur.fetchone()
            prev_hash = str(row[0]) if row and row[0] else GENESIS_HASH
            entry_hash = _compute_entry_hash(
                prev_hash=prev_hash,
                timestamp_utc=ts,
                tenant_id=tenant_id,
                endpoint=endpoint,
                policy_pack=policy_pack,
                provider=provider,
                action=action,
                http_status=http_status,
                vector=normalized_vector,
                redactions_json=normalized_redactions,
                payload_sha256=payload_sha256,
                latency_ms=rounded_latency,
            )
            placeholder = "%s" if self._is_postgres else "?"
            placeholders = ", ".join([placeholder] * 13)
            sql = (
                f"INSERT INTO audit_events "
                f"(timestamp_utc, tenant_id, endpoint, policy_pack, provider, action, "
                f"http_status, vector, redactions_json, payload_sha256, latency_ms, "
                f"prev_hash, entry_hash) VALUES ({placeholders})"
            )
            params = (
                ts,
                tenant_id,
                endpoint,
                policy_pack,
                provider,
                action,
                int(http_status),
                normalized_vector,
                redactions_json,
                payload_sha256,
                rounded_latency,
                prev_hash,
                entry_hash,
            )
            if self._is_postgres:
                cur.execute(sql + " RETURNING seq_id", params)
                seq_id = int(cur.fetchone()[0])
                conn.commit()
            else:
                cur.execute(sql, params)
                conn.commit()
                seq_id = int(cur.lastrowid)

        return AuditRecord(
            seq_id=seq_id,
            timestamp_utc=ts,
            tenant_id=tenant_id,
            endpoint=endpoint,
            policy_pack=policy_pack,
            provider=provider,
            action=action,
            http_status=int(http_status),
            vector=normalized_vector or None,
            redactions=normalized_redactions,
            payload_sha256=payload_sha256,
            latency_ms=rounded_latency,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def verify_chain(self) -> Tuple[bool, int, Optional[int]]:
        """Verify every SHA-256 link in the ledger."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT seq_id, timestamp_utc, tenant_id, endpoint, policy_pack, "
                "provider, action, http_status, vector, redactions_json, "
                "payload_sha256, latency_ms, prev_hash, entry_hash "
                "FROM audit_events ORDER BY seq_id ASC"
            )
            rows = cur.fetchall()

        expected_prev = GENESIS_HASH
        for row in rows:
            (
                seq_id,
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
                latency_ms,
                prev_hash,
                entry_hash,
            ) = row
            if str(prev_hash) != expected_prev:
                return False, len(rows), int(seq_id)
            recomputed = _compute_entry_hash(
                prev_hash=str(prev_hash),
                timestamp_utc=str(ts),
                tenant_id=str(tenant_id),
                endpoint=str(endpoint),
                policy_pack=str(policy_pack),
                provider=str(provider),
                action=str(action),
                http_status=int(http_status),
                vector=vector,
                redactions_json=redactions_json,
                payload_sha256=str(payload_sha256),
                latency_ms=float(latency_ms),
            )
            if recomputed != str(entry_hash):
                return False, len(rows), int(seq_id)
            expected_prev = str(entry_hash)
        return True, len(rows), None

    def export_jsonl(self, tenant_id: Optional[str] = None, limit: int = 1000) -> str:
        """Export audit events in SIEM-ready JSON Lines format (Splunk/Datadog)."""
        placeholder = "%s" if self._is_postgres else "?"
        with self._connection() as conn:
            cur = conn.cursor()
            if tenant_id:
                cur.execute(
                    f"SELECT seq_id, timestamp_utc, tenant_id, endpoint, policy_pack, "
                    f"provider, action, http_status, vector, redactions_json, "
                    f"payload_sha256, latency_ms, prev_hash, entry_hash "
                    f"FROM audit_events WHERE tenant_id = {placeholder} "
                    f"ORDER BY seq_id DESC LIMIT {placeholder}",
                    (tenant_id, limit),
                )
            else:
                cur.execute(
                    f"SELECT seq_id, timestamp_utc, tenant_id, endpoint, policy_pack, "
                    f"provider, action, http_status, vector, redactions_json, "
                    f"payload_sha256, latency_ms, prev_hash, entry_hash "
                    f"FROM audit_events ORDER BY seq_id DESC LIMIT {placeholder}",
                    (limit,),
                )
            rows = cur.fetchall()

        lines: List[str] = []
        for row in rows:
            lines.append(
                json.dumps(
                    {
                        "seq_id": row[0],
                        "timestamp_utc": row[1],
                        "tenant_id": row[2],
                        "endpoint": row[3],
                        "policy_pack": row[4],
                        "provider": row[5],
                        "action": row[6],
                        "http_status": row[7],
                        "vector": row[8] or None,
                        "redactions": _normalize_redactions(row[9]),
                        "payload_sha256": row[10],
                        "latency_ms": row[11],
                        "prev_hash": row[12],
                        "entry_hash": row[13],
                    }
                )
            )
        return "\n".join(lines)

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
        elif self._conn is not None:
            with self._lock:
                try:
                    self._conn.close()
                finally:
                    self._conn = None