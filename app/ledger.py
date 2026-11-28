import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATH = os.getenv("LUCID_LEDGER_DB_PATH", "lucid_audit_ledger.db")


class AuditLedger:
    """
    Append-only, SHA-256 hash-chained SQLite audit ledger (WAL mode).
    Stores ONLY sanitized metadata (never raw PII or raw blocked prompts).
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        with self._lock:
            self._init_db_locked()

    def reconfigure(self, db_path: str) -> None:
        """Re-binds ledger storage path safely (useful for isolated pytest runs)."""
        with self._lock:
            self.db_path = db_path
            self._init_db_locked()

    def _connect(self) -> sqlite3.Connection:
        if self.db_path != ":memory:":
            parent = os.path.dirname(os.path.abspath(self.db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(
            self.db_path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db_locked(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp_utc TEXT NOT NULL,
                        tenant_id TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        reference_id TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        http_status INTEGER NOT NULL,
                        redacted_types_json TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_tenant_id ON audit_events (tenant_id, id DESC)"
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _compute_hash(
        timestamp_utc: str,
        tenant_id: str,
        endpoint: str,
        reference_id: str,
        decision: str,
        http_status: int,
        redacted_types_json: str,
        summary: str,
        prev_hash: str,
    ) -> str:
        canonical = json.dumps(
            [
                timestamp_utc,
                tenant_id,
                endpoint,
                reference_id,
                decision,
                int(http_status),
                redacted_types_json,
                summary,
                prev_hash,
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get_summary_stats(self) -> Dict[str, Any]:
        """Fast O(1) read for /health probes — avoids full-table SHA-256 scan DoS."""
        with self._lock:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt, MAX(id) AS last_id FROM audit_events"
                ).fetchone()
                last = conn.execute(
                    "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
                ).fetchone()
        return {
            "ledger_records": int(row["cnt"]) if row else 0,
            "latest_hash_prefix": last["entry_hash"][:12] if last else "GENESIS",
        }

    def record_event(
        self,
        tenant_id: str,
        endpoint: str,
        reference_id: str,
        decision: str,
        http_status: int,
        redacted_types: Optional[List[str]] = None,
        summary: str = "",
    ) -> Dict[str, Any]:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sorted_redacted = sorted(redacted_types or [])
        red_json = json.dumps(sorted_redacted)
        safe_summary = summary[:300]

        with self._lock:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    row = conn.execute(
                        "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    prev_hash = row["entry_hash"] if row else "GENESIS"
                    entry_hash = self._compute_hash(
                        ts,
                        tenant_id,
                        endpoint,
                        reference_id,
                        decision,
                        http_status,
                        red_json,
                        safe_summary,
                        prev_hash,
                    )
                    cur = conn.execute(
                        """
                        INSERT INTO audit_events (
                            timestamp_utc, tenant_id, endpoint, reference_id,
                            decision, http_status, redacted_types_json, summary,
                            prev_hash, entry_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ts,
                            tenant_id,
                            endpoint,
                            reference_id,
                            decision,
                            http_status,
                            red_json,
                            safe_summary,
                            prev_hash,
                            entry_hash,
                        ),
                    )
                    conn.execute("COMMIT")
                    return {
                        "id": cur.lastrowid,
                        "timestamp_utc": ts,
                        "tenant_id": tenant_id,
                        "endpoint": endpoint,
                        "reference_id": reference_id,
                        "decision": decision,
                        "http_status": http_status,
                        "redacted_types": sorted_redacted,
                        "summary": safe_summary,
                        "entry_hash": entry_hash,
                    }
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

    def list_events(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    """
                    SELECT id, timestamp_utc, tenant_id, endpoint, reference_id,
                           decision, http_status, redacted_types_json, summary, entry_hash
                    FROM audit_events
                    WHERE tenant_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (tenant_id, limit),
                ).fetchall()
        return [
            {
                "id": r["id"],
                "timestamp_utc": r["timestamp_utc"],
                "tenant_id": r["tenant_id"],
                "endpoint": r["endpoint"],
                "reference_id": r["reference_id"],
                "decision": r["decision"],
                "http_status": r["http_status"],
                "redacted_types": json.loads(r["redacted_types_json"]),
                "summary": r["summary"],
                "entry_hash": r["entry_hash"],
            }
            for r in rows
        ]

    def verify_chain(self) -> Dict[str, Any]:
        with self._lock:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    """
                    SELECT id, timestamp_utc, tenant_id, endpoint, reference_id,
                           decision, http_status, redacted_types_json, summary,
                           prev_hash, entry_hash
                    FROM audit_events
                    ORDER BY id ASC
                    """
                ).fetchall()

        expected_prev = "GENESIS"
        for r in rows:
            if not hmac.compare_digest(r["prev_hash"], expected_prev):
                return {"chain_valid": False, "checked_records": len(rows), "broken_at_id": r["id"]}
            recomputed = self._compute_hash(
                r["timestamp_utc"],
                r["tenant_id"],
                r["endpoint"],
                r["reference_id"],
                r["decision"],
                r["http_status"],
                r["redacted_types_json"],
                r["summary"],
                r["prev_hash"],
            )
            if not hmac.compare_digest(recomputed, r["entry_hash"]):
                return {"chain_valid": False, "checked_records": len(rows), "broken_at_id": r["id"]}
            expected_prev = r["entry_hash"]

        return {"chain_valid": True, "checked_records": len(rows), "broken_at_id": None}


audit_ledger = AuditLedger()