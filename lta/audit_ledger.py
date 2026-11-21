"""Tamper-evident SHA-256 hash-chained persistent audit ledger.

Supports SQLite out of the box (zero extra dependencies) and PostgreSQL via
`psycopg` when `LTA_AUDIT_DB_URL` starts with `postgresql://`.
Raw prompts are NEVER stored; only SHA-256 payload digests and structured verdicts
are written, satisfying EU AI Act Article 12 and ISO/IEC 42001 record-keeping.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


GENESIS_HASH = "0" * 64


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
    redactions_json: str,
    payload_sha256: str,
    latency_ms: float,
) -> str:
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "timestamp_utc": timestamp_utc,
            "tenant_id": tenant_id,
            "endpoint": endpoint,
            "policy_pack": policy_pack,
            "provider": provider,
            "action": action,
            "http_status": http_status,
            "vector": vector or "",
            "redactions": redactions_json,
            "payload_sha256": payload_sha256,
            "latency_ms": round(latency_ms, 3),
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
        if self._is_postgres:
            import psycopg  # type: ignore

            self._pg = psycopg
            self._conn = psycopg.connect(db_url, autocommit=True)
        else:
            path = db_url.replace("sqlite:///", "", 1)
            self._conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

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
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(ddl)
            if not self._is_postgres:
                self._conn.commit()

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
        redactions_json = json.dumps(redactions)
        rounded_latency = round(float(latency_ms), 3)

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT entry_hash FROM audit_events ORDER BY seq_id DESC LIMIT 1"
            )
            row = cur.fetchone()
            prev_hash = row[0] if row else GENESIS_HASH
            entry_hash = _compute_entry_hash(
                prev_hash=prev_hash,
                timestamp_utc=ts,
                tenant_id=tenant_id,
                endpoint=endpoint,
                policy_pack=policy_pack,
                provider=provider,
                action=action,
                http_status=http_status,
                vector=vector,
                redactions_json=redactions_json,
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
                http_status,
                vector or "",
                redactions_json,
                payload_sha256,
                rounded_latency,
                prev_hash,
                entry_hash,
            )
            if self._is_postgres:
                cur.execute(sql + " RETURNING seq_id", params)
                seq_id = int(cur.fetchone()[0])
            else:
                cur.execute(sql, params)
                self._conn.commit()
                seq_id = int(cur.lastrowid)

        return AuditRecord(
            seq_id=seq_id,
            timestamp_utc=ts,
            tenant_id=tenant_id,
            endpoint=endpoint,
            policy_pack=policy_pack,
            provider=provider,
            action=action,
            http_status=http_status,
            vector=vector or None,
            redactions=redactions,
            payload_sha256=payload_sha256,
            latency_ms=rounded_latency,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def verify_chain(self) -> Tuple[bool, int, Optional[int]]:
        """Verify every SHA-256 link in the ledger.

        Returns: (is_valid, total_records, first_broken_seq_id)
        """
        with self._lock:
            cur = self._conn.cursor()
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
            if prev_hash != expected_prev:
                return False, len(rows), int(seq_id)
            recomputed = _compute_entry_hash(
                prev_hash=prev_hash,
                timestamp_utc=ts,
                tenant_id=tenant_id,
                endpoint=endpoint,
                policy_pack=policy_pack,
                provider=provider,
                action=action,
                http_status=int(http_status),
                vector=vector,
                redactions_json=redactions_json,
                payload_sha256=payload_sha256,
                latency_ms=float(latency_ms),
            )
            if recomputed != entry_hash:
                return False, len(rows), int(seq_id)
            expected_prev = entry_hash
        return True, len(rows), None

    def export_jsonl(self, tenant_id: Optional[str] = None, limit: int = 1000) -> str:
        """Export audit events in SIEM-ready JSON Lines format (Splunk/Datadog)."""
        placeholder = "%s" if self._is_postgres else "?"
        with self._lock:
            cur = self._conn.cursor()
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
                        "redactions": json.loads(row[9]),
                        "payload_sha256": row[10],
                        "latency_ms": row[11],
                        "prev_hash": row[12],
                        "entry_hash": row[13],
                    }
                )
            )
        return "\n".join(lines)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
