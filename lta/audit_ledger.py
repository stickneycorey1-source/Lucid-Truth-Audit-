"""Tamper-evident SHA-256 hash-chained persistent audit ledger with provenance (Hardened v2.4).

Supports SQLite out of the box and PostgreSQL via `psycopg_pool.ConnectionPool`
(with fallback to `psycopg.connect`) using transactional `pg_advisory_xact_lock`,
automatic `rollback()` on errors, policy-version & config-fingerprint tracking,
an O(1) `ping()` for `/readyz` probes, and a composite `(tenant_id, seq_id DESC)`
index for fast SIEM exports.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple


GENESIS_HASH = "0" * 64
PG_CHAIN_LOCK_ID = 728391045


def canonical_json(data: Any) -> str:
    """Serialize data deterministically with sorted keys and compact separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def sha256_canonical(data: Any) -> str:
    """Compute hex SHA-256 over canonical JSON."""
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def compute_policy_digest(
    pack_obj: Any,
    fallback_name: str,
    fallback_version: str = "2.4.0",
) -> Tuple[str, str]:
    """Return (policy_version, policy_sha256) for a loaded PolicyPack or dict."""
    if pack_obj is None:
        return fallback_version, sha256_canonical({"name": fallback_name, "version": fallback_version})

    if isinstance(pack_obj, dict):
        name = str(pack_obj.get("name") or fallback_name)
        version = str(pack_obj.get("version") or fallback_version)
        payload = {k: v for k, v in pack_obj.items() if k != "runtime_cache"}
        payload.setdefault("name", name)
        payload.setdefault("version", version)
        return version, sha256_canonical(payload)

    name = str(getattr(pack_obj, "name", fallback_name))
    version = str(getattr(pack_obj, "version", fallback_version))
    raw_dict = getattr(pack_obj, "__dict__", None)
    if isinstance(raw_dict, dict):
        payload = {k: v for k, v in raw_dict.items() if not str(k).startswith("_")}
        payload.setdefault("name", name)
        payload.setdefault("version", version)
    else:
        payload = {"name": name, "version": version}
    return version, sha256_canonical(payload)


def compute_config_fingerprint(
    *,
    gateway_version: str,
    policy_name: str,
    policy_version: str,
    policy_sha256: str,
    provider: str,
    max_body_bytes: int,
    rate_limit_rpm: int,
    auth_fail_limit_rpm: int,
    extra_flags: Optional[Dict[str, Any]] = None,
) -> str:
    """Compute a non-secret SHA-256 fingerprint of active gateway & policy settings."""
    return sha256_canonical(
        {
            "gateway_version": str(gateway_version),
            "policy_name": str(policy_name),
            "policy_version": str(policy_version),
            "policy_sha256": str(policy_sha256),
            "provider": str(provider),
            "max_body_bytes": int(max_body_bytes),
            "rate_limit_rpm": int(rate_limit_rpm),
            "auth_fail_limit_rpm": int(auth_fail_limit_rpm),
            "flags": extra_flags or {},
        }
    )


def compute_provenance_hash(
    *,
    prev_hash: str,
    payload_sha256: str,
    policy_name: str,
    policy_version: str,
    policy_sha256: str,
    config_fingerprint: str,
    request_id: str = "",
) -> str:
    """Compute an independent provenance binding digest for external verification."""
    return sha256_canonical(
        {
            "prev_hash": str(prev_hash),
            "payload_sha256": str(payload_sha256),
            "policy_name": str(policy_name),
            "policy_version": str(policy_version),
            "policy_sha256": str(policy_sha256),
            "config_fingerprint": str(config_fingerprint),
            "request_id": str(request_id),
        }
    )


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
    policy_version: str = "2.4.0"
    policy_sha256: str = ""
    config_fingerprint: str = ""
    provenance_hash: str = ""
    provenance: Optional[Dict[str, Any]] = None


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


def _normalize_provenance_dict(provenance_value: Any) -> Dict[str, Any]:
    if isinstance(provenance_value, dict):
        return dict(provenance_value)
    if isinstance(provenance_value, str) and provenance_value.strip():
        try:
            parsed = json.loads(provenance_value)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    return {}


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
    policy_version: str = "2.4.0",
    policy_sha256: str = "",
    config_fingerprint: str = "",
    provenance_hash: str = "",
) -> str:
    normalized_redactions = _normalize_redactions(redactions_json)
    canonical = json.dumps(
        {
            "prev_hash": str(prev_hash),
            "timestamp_utc": str(timestamp_utc),
            "tenant_id": str(tenant_id),
            "endpoint": str(endpoint),
            "policy_pack": str(policy_pack),
            "policy_version": str(policy_version or "2.4.0"),
            "policy_sha256": str(policy_sha256 or ""),
            "config_fingerprint": str(config_fingerprint or ""),
            "provenance_hash": str(provenance_hash or ""),
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
        self._closed = False
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
        if self._closed:
            raise RuntimeError("AuditLedger is closed")
        if self._pool is not None:
            with self._pool.connection() as conn:
                try:
                    yield conn
                except Exception:
                    conn.rollback()
                    raise
        else:
            with self._lock:
                if self._closed:
                    raise RuntimeError("AuditLedger is closed")
                if self._conn is None:
                    path = self.db_url.replace("sqlite:///", "", 1)
                    self._conn = sqlite3.connect(path, check_same_thread=False)
                try:
                    yield self._conn
                except Exception:
                    if self._conn is not None:
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
                policy_version TEXT NOT NULL DEFAULT '2.4.0',
                policy_sha256 TEXT NOT NULL DEFAULT '',
                config_fingerprint TEXT NOT NULL DEFAULT '',
                provenance_hash TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
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
                policy_version TEXT NOT NULL DEFAULT '2.4.0',
                policy_sha256 TEXT NOT NULL DEFAULT '',
                config_fingerprint TEXT NOT NULL DEFAULT '',
                provenance_hash TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
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
        snapshots_ddl = (
            """
            CREATE TABLE IF NOT EXISTS policy_snapshots (
                config_fingerprint TEXT PRIMARY KEY,
                policy_name TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_sha256 TEXT NOT NULL,
                recorded_at_utc TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            )
            """
        )
        migrations = [
            "ALTER TABLE audit_events ADD COLUMN policy_version TEXT NOT NULL DEFAULT '2.4.0'",
            "ALTER TABLE audit_events ADD COLUMN policy_sha256 TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN provenance_hash TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}'",
        ]
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(ddl)
            cur.execute(snapshots_ddl)
            for stmt in migrations:
                try:
                    cur.execute(stmt)
                except Exception:
                    pass
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_tenant_seq "
                "ON audit_events (tenant_id, seq_id DESC)"
            )
            conn.commit()

    def ping(self) -> bool:
        """Fast O(1) connectivity check for /readyz without scanning audit_events."""
        if self._closed:
            return False
        try:
            with self._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        except Exception:
            return False

    def record_snapshot(
        self,
        *,
        config_fingerprint: str,
        policy_name: str,
        policy_version: str,
        policy_sha256: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist a deduplicated policy & gateway configuration snapshot."""
        if not config_fingerprint:
            return
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        snap_doc = {
            "config_fingerprint": config_fingerprint,
            "policy_name": policy_name,
            "policy_version": policy_version,
            "policy_sha256": policy_sha256,
            "recorded_at_utc": ts,
            "metadata": metadata or {},
        }
        snap_json = json.dumps(snap_doc, sort_keys=True, separators=(",", ":"))
        with self._connection() as conn:
            cur = conn.cursor()
            if self._is_postgres:
                cur.execute(
                    "INSERT INTO policy_snapshots "
                    "(config_fingerprint, policy_name, policy_version, policy_sha256, recorded_at_utc, snapshot_json) "
                    "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (config_fingerprint) DO NOTHING",
                    (config_fingerprint, policy_name, policy_version, policy_sha256, ts, snap_json),
                )
            else:
                cur.execute(
                    "INSERT OR IGNORE INTO policy_snapshots "
                    "(config_fingerprint, policy_name, policy_version, policy_sha256, recorded_at_utc, snapshot_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (config_fingerprint, policy_name, policy_version, policy_sha256, ts, snap_json),
                )
            conn.commit()

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
        policy_version: str = "2.4.0",
        policy_sha256: str = "",
        config_fingerprint: str = "",
        request_id: str = "",
        extra_provenance: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Append a tamper-evident audit event with policy & config provenance."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload_sha256 = hashlib.sha256(
            raw_payload_for_digest.encode("utf-8")
        ).hexdigest()
        normalized_redactions = _normalize_redactions(redactions)
        redactions_json = json.dumps(normalized_redactions, separators=(",", ":"))
        rounded_latency = round(float(latency_ms), 3)
        normalized_vector = str(vector or "")
        norm_policy_ver = str(policy_version or "2.4.0")
        norm_policy_sha = str(policy_sha256 or "")
        norm_cfg_fp = str(config_fingerprint or "")

        with self._connection() as conn:
            cur = conn.cursor()
            if self._is_postgres:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (PG_CHAIN_LOCK_ID,))
            cur.execute(
                "SELECT entry_hash FROM audit_events ORDER BY seq_id DESC LIMIT 1"
            )
            row = cur.fetchone()
            prev_hash = str(row[0]) if row and row[0] else GENESIS_HASH
            prov_hash = compute_provenance_hash(
                prev_hash=prev_hash,
                payload_sha256=payload_sha256,
                policy_name=policy_pack,
                policy_version=norm_policy_ver,
                policy_sha256=norm_policy_sha,
                config_fingerprint=norm_cfg_fp,
                request_id=request_id,
            )
            prov_dict: Dict[str, Any] = {
                "policy_pack": policy_pack,
                "policy_version": norm_policy_ver,
                "policy_sha256": norm_policy_sha,
                "config_fingerprint": norm_cfg_fp,
                "payload_sha256": payload_sha256,
                "prev_hash": prev_hash,
                "provenance_hash": prov_hash,
            }
            if request_id:
                prov_dict["request_id"] = request_id
            if extra_provenance:
                prov_dict.update(extra_provenance)
            provenance_json = json.dumps(prov_dict, sort_keys=True, separators=(",", ":"))

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
                policy_version=norm_policy_ver,
                policy_sha256=norm_policy_sha,
                config_fingerprint=norm_cfg_fp,
                provenance_hash=prov_hash,
            )
            placeholder = "%s" if self._is_postgres else "?"
            placeholders = ", ".join([placeholder] * 18)
            sql = (
                f"INSERT INTO audit_events "
                f"(timestamp_utc, tenant_id, endpoint, policy_pack, policy_version, "
                f"policy_sha256, config_fingerprint, provenance_hash, provenance_json, "
                f"provider, action, http_status, vector, redactions_json, payload_sha256, "
                f"latency_ms, prev_hash, entry_hash) VALUES ({placeholders})"
            )
            params = (
                ts,
                tenant_id,
                endpoint,
                policy_pack,
                norm_policy_ver,
                norm_policy_sha,
                norm_cfg_fp,
                prov_hash,
                provenance_json,
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
            policy_version=norm_policy_ver,
            policy_sha256=norm_policy_sha,
            config_fingerprint=norm_cfg_fp,
            provenance_hash=prov_hash,
            provenance=prov_dict,
        )

    def verify_ch