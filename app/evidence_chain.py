
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class DuplicateEvidenceError(Exception):
    """Raised when an evidence record conflicts with a database constraint."""
    pass


class EvidenceChainStore:
    """Tenant-isolated, persistent, SHA-256 hash-chained evidence records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv(
            "LUCID_LEDGER_DB_PATH",
            "lucid_audit_ledger.db",
        )
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)

        conn = sqlite3.connect(
            self.db_path,
            timeout=15.0,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    UNIQUE(tenant_id, evidence_id)
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_evidence_tenant
                ON evidence_records(tenant_id, id DESC)
                """
            )

    @staticmethod
    def _canonical_json(value: Dict[str, Any]) -> str:
        """Serialize payload consistently for deterministic hashing."""
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def _hash_record(
        cls,
        evidence_id: str,
        tenant_id: str,
        created_at: str,
        payload_json: str,
        prev_hash: str,
    ) -> str:
        """Calculate the SHA-256 hash for one evidence-chain record."""
        envelope = {
            "schema_version": 1,
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            "created_at": created_at,
            "payload_json": payload_json,
            "prev_hash": prev_hash,
        }

        encoded = cls._canonical_json(envelope).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def add(
        self,
        tenant_id: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Append an evidence record to the tenant's hash chain."""

        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id must be a non-empty string")

        if not isinstance(payload, dict):
            raise ValueError("payload must be a dictionary")

        evidence_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        payload_json = self._canonical_json(payload)

        # Serialize concurrent writers so each tenant's chain
        # receives the correct previous hash.
        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")

                previous = conn.execute(
                    """
                    SELECT entry_hash
                    FROM evidence_records
                    WHERE tenant_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (tenant_id,),
                ).fetchone()

                prev_hash = (
                    previous["entry_hash"]
                    if previous
                    else "GENESIS"
                )

                entry_hash = self._hash_record(
                    evidence_id=evidence_id,
                    tenant_id=tenant_id,
                    created_at=created_at,
                    payload_json=payload_json,
                    prev_hash=prev_hash,
                )

                cur = conn.execute(
                    """
                    INSERT INTO evidence_records (
                        evidence_id,
                        tenant_id,
                        created_at,
                        payload_json,
                        prev_hash,
                        entry_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        tenant_id,
                        created_at,
                        payload_json,
                        prev_hash,
                        entry_hash,
                    ),
                )

                record_number = cur.lastrowid
                conn.execute("COMMIT")

            except sqlite3.IntegrityError as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise DuplicateEvidenceError(str(exc)) from exc

            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return {
            "record_number": record_number,
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            "created_at": created_at,
            "payload": payload,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }

    def list_records(
        self,
        tenant_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return records belonging only to the requested tenant."""

        limit = max(1, min(limit, 500))

        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    tenant_id,
                    created_at,
                    payload_json,
                    prev_hash,
                    entry_hash
                FROM evidence_records
                WHERE tenant_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()

        return [
            {
                "record_number": row["id"],
                "evidence_id": row["evidence_id"],
                "tenant_id": row["tenant_id"],
                "created_at": row["created_at"],
                "payload": json.loads(row["payload_json"]),
                "prev_hash": row["prev_hash"],
                "entry_hash": row["entry_hash"],
            }
            for row in rows
        ]

    def verify(self, tenant_id: str) -> Dict[str, Any]:
        """Verify the complete hash chain for one tenant."""

        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    tenant_id,
                    created_at,
                    payload_json,
                    prev_hash,
                    entry_hash
                FROM evidence_records
                WHERE tenant_id = ?
                ORDER BY id ASC
                """,
                (tenant_id,),
            ).fetchall()

        expected_prev = "GENESIS"

        for row in rows:
            # Verify that this record points to the expected
            # previous record in the tenant's chain.
            if row["prev_hash"] != expected_prev:
                return {
                    "chain_valid": False,
                    "checked_records": len(rows),
                    "broken_at_record": row["id"],
                }

            # Recalculate the record hash from stored data.
            actual_hash = self._hash_record(
                evidence_id=row["evidence_id"],
                tenant_id=row["tenant_id"],
                created_at=row["created_at"],
                payload_json=row["payload_json"],
                prev_hash=row["prev_hash"],
            )

            # Detect payload changes, metadata changes,
            # hash changes, and chain-link changes.
            if actual_hash != row["entry_hash"]:
                return {
                    "chain_valid": False,
                    "checked_records": len(rows),
                    "broken_at_record": row["id"],
                }

            expected_prev = row["entry_hash"]

        return {
            "chain_valid": True,
            "checked_records": len(rows),
            "broken_at_record": None,
        }
