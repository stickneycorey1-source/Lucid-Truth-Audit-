"""Tamper-evident SHA-256 hash-chained audit ledger with cryptographic provenance."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

GENESIS_HASH = "0" * 64
_EPHEMERAL_KEYS = frozenset({"runtime_cache", "_cache", "cache"})


@dataclass
class AuditRecord:
    seq_id: int
    timestamp_utc: str
    tenant_id: str
    endpoint: str
    policy_pack: str
    policy_version: str
    policy_sha256: str
    config_fingerprint: str
    provenance_hash: str
    provenance_json: str
    provenance_json_sha256: str
    provider: str
    action: str
    http_status: int
    vector: Optional[str]
    redactions_json: str
    payload_sha256: str
    latency_ms: float
    prev_hash: str
    entry_hash: str


def _sanitize_for_digest(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {
            str(k): _sanitize_for_digest(v)
            for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))
            if not str(k).startswith("_") and str(k) not in _EPHEMERAL_KEYS
        }
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_digest(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(_sanitize_for_digest(v) for v in obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        return _sanitize_for_digest(asdict(obj))
    if hasattr(obj, "model_dump") and callable(obj.model_dump):
        return _sanitize_for_digest(obj.model_dump())
    if hasattr(obj, "__dict__"):
        return _sanitize_for_digest(vars(obj))
    return str(obj)


def compute_policy_digest(
    policy_pack: Any,
    fallback_name: str = "general_enterprise",
    fallback_version: str = "2.4.0",
) -> Tuple[str, str]:
    """Return deterministic (policy_version, policy_sha256) for a policy pack."""
    if policy_pack is None:
        canonical = json.dumps(
            {"name": str(fallback_name), "version": str(fallback_version)},
            sort_keys=True,
            separators=(",", ":"),
        )
        return str(fallback_version), hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    sanitized = _sanitize_for_digest(policy_pack)
    if isinstance(sanitized, dict):
        version = str(sanitized.get("version") or fallback_version)
        if "name" not in sanitized:
            sanitized["name"] = str(fallback_name)
    else:
        version = str(getattr(policy_pack, "version", None) or fallback_version)
        sanitized = {
            "name": str(fallback_name),
            "version": version,
            "spec": sanitized,
        }

    canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
    return version, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    """Compute a deterministic SHA-256 fingerprint of active gateway runtime posture."""
    payload = {
        "gateway_version": str(gateway_version),
        "policy_name": str(policy_name),
        "policy_version": str(policy_version),
        "policy_sha256": str(policy_sha256),
        "provider": str(provider),
        "max_body_bytes": int(max_body_bytes),
        "rate_limit_rpm": int(rate_limit_rpm),
        "auth_fail_limit_rpm": int(auth_fail_limit_rpm),
        "extra_flags": _sanitize_for_digest(extra_flags or {}),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    """Bind chain position, payload digest, policy digest, and runtime config together."""
    payload = {
        "prev_hash": str(prev_hash),
        "payload_sha256": str(payload_sha256),
        "policy_name": str(policy_name),
        "policy_version": str(policy_version),
        "policy_sha256": str(policy_sha256),
        "config_fingerprint": str(config_fingerprint),
        "request_id": str(request_id or ""),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_redactions(redactions_json: str) -> List[str]:
    if not redactions_json:
        return []
    try:
        parsed = json.loads(redactions_json)
        if isinstance(parsed, list):
            return sorted(str(item) for item in parsed)
    except (TypeError, ValueError):
        pass
    return []


def _compute_entry_hash(
    *,
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
    policy_version: str = "",
    policy_sha256: str = "",
    config_fingerprint: str = "",
    provenance_hash: str = "",
    provenance_json_sha256: str = "",
) -> str:
    normalized_redactions = _normalize_redactions(redactions_json)
    canonical_payload: Dict[str, Any] = {
        "prev_hash": str(prev_hash),
        "timestamp_utc": str(timestamp_utc),
        "tenant_id": str(tenant_id),
        "endpoint": str(endpoint),
        "policy_pack": str(policy_pack),
        "policy_version": str(policy_version),
        "policy_sha256": str(policy_sha256),
        "config_fingerprint": str(config_fingerprint),
        "provenance_hash": str(provenance_hash),
        "provider": str(provider),
        "action": str(action),
        "http_status": int(http_status),
        "vector": None if vector is None else str(vector),
        "redactions": normalized_redactions,
        "payload_sha256": str(payload_sha256),
        "latency_ms": round(float(latency_ms), 3),
    }

    # Preserve legacy hash calculations when verifying older records.
    # New records bind the exact serialized provenance JSON bytes.
    if provenance_json_sha256:
        canonical_payload["provenance_json_sha256"] = str(provenance_json_sha256)

    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLedger:
    """Persistent SHA-256 hash-chained audit ledger supporting SQLite and PostgreSQL."""

    def __init__(self, db_url: str = "sqlite:///lta_audit.db") -> None:
        self.db_url = db_url
        self._lock = threading.RLock()
        self._closed = False
        self._is_postgres = db_url.startswith(("postgresql://", "postgres://"))
        self._sqlite_conn: Optional[sqlite3.Connection] = None
        self._pg_pool: Any = None
        self._pg_conn: Any = None

        if self._is_postgres:
            self._init_postgres()
        else:
            self._init_sqlite()

        self._init_schema()

    def _init_sqlite(self) -> None:
        raw_path = self.db_url
        if raw_path.startswith("sqlite:///"):
            raw_path = raw_path[len("sqlite:///"):]
        if raw_path != ":memory:":
            parent = Path(raw_path).parent
            if str(parent) not in ("", "."):
                os.makedirs(parent, exist_ok=True)
        self._sqlite_conn = sqlite3.connect(raw_path, check_same_thread=False)

    def _init_postgres(self) -> None:
        try:
            import psycopg_pool  # type: ignore[import-not-found]

            self._pg_pool = psycopg_pool.ConnectionPool(
                self.db_url,
                min_size=1,
                max_size=10,
                check=psycopg_pool.ConnectionPool.check_connection,
            )
            return
        except ImportError:
            pass

        import psycopg  # type: ignore[import-not-found]

        self._pg_conn = psycopg.connect(self.db_url)

    def _init_schema(self) -> None:
        if self._is_postgres:
            ddl_events = """
            CREATE TABLE IF NOT EXISTS audit_events (
                seq_id BIGSERIAL PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                policy_pack TEXT NOT NULL,
                policy_version TEXT NOT NULL DEFAULT '',
                policy_sha256 TEXT NOT NULL DEFAULT '',
                config_fingerprint TEXT NOT NULL DEFAULT '',
                provenance_hash TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                provenance_json_sha256 TEXT NOT NULL DEFAULT '',
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
            ddl_snapshots = """
            CREATE TABLE IF NOT EXISTS policy_snapshots (
                config_fingerprint TEXT PRIMARY KEY,
                recorded_at_utc TEXT NOT NULL,
                policy_name TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_sha256 TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
            migrations = [
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS policy_sha256 TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS config_fingerprint TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS provenance_hash TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS provenance_json TEXT NOT NULL DEFAULT '{}'",
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS provenance_json_sha256 TEXT NOT NULL DEFAULT ''",
            ]
            with self._pg_connection() as conn:
                cur = conn.cursor()
                cur.execute(ddl_events)
                cur.execute(ddl_snapshots)
                for stmt in migrations:
                    try:
                        cur.execute(stmt)
                    except Exception:
                        conn.rollback()
                conn.commit()
            return

        assert self._sqlite_conn is not None
        ddl_events = """
        CREATE TABLE IF NOT EXISTS audit_events (
            seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            policy_pack TEXT NOT NULL,
            policy_version TEXT NOT NULL DEFAULT '',
            policy_sha256 TEXT NOT NULL DEFAULT '',
            config_fingerprint TEXT NOT NULL DEFAULT '',
            provenance_hash TEXT NOT NULL DEFAULT '',
            provenance_json TEXT NOT NULL DEFAULT '{}',
            provenance_json_sha256 TEXT NOT NULL DEFAULT '',
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
        ddl_snapshots = """
        CREATE TABLE IF NOT EXISTS policy_snapshots (
            config_fingerprint TEXT PRIMARY KEY,
            recorded_at_utc TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            policy_sha256 TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )
        """
        migrations = [
            "ALTER TABLE audit_events ADD COLUMN policy_version TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN policy_sha256 TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN provenance_hash TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE audit_events ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE audit_events ADD COLUMN provenance_json_sha256 TEXT NOT NULL DEFAULT ''",
        ]
        with self._lock:
            cur = self._sqlite_conn.cursor()
            cur.execute(ddl_events)
            cur.execute(ddl_snapshots)
            for stmt in migrations:
                try:
                    cur.execute(stmt)
                except sqlite3.OperationalError:
                    pass
            self._sqlite_conn.commit()

    def _pg_connection(self) -> Any:
        if self._pg_pool is not None:
            return self._pg_pool.connection()
        if self._pg_conn is not None:
            return _DirectConnCtx(self._pg_conn)
        raise RuntimeError("PostgreSQL connection is closed")

    def _connection(self) -> Any:
        if self._is_postgres:
            return self._pg_connection()
        if self._sqlite_conn is None:
            raise RuntimeError("SQLite connection is closed")
        return _DirectConnCtx(self._sqlite_conn)

    def ping(self) -> bool:
        if self._closed:
            return False
        try:
            with self._lock, self._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                row = cur.fetchone()
                return bool(row and row[0] == 1)
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
        if self._closed:
            raise RuntimeError("AuditLedger is closed")
        ts = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(_sanitize_for_digest(metadata or {}), sort_keys=True, separators=(",", ":"))
        if self._is_postgres:
            sql = """
            INSERT INTO policy_snapshots (
                config_fingerprint, recorded_at_utc, policy_name,
                policy_version, policy_sha256, metadata_json
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (config_fingerprint) DO NOTHING
            """
            with self._lock, self._pg_connection() as conn:
                cur = conn.cursor()
                cur.execute(sql, (config_fingerprint, ts, policy_name, policy_version, policy_sha256, meta_json))
                conn.commit()
            return

        assert self._sqlite_conn is not None
        sql = """
        INSERT OR IGNORE INTO policy_snapshots (
            config_fingerprint, recorded_at_utc, policy_name,
            policy_version, policy_sha256, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?)
        """
        with self._lock:
            self._sqlite_conn.execute(
                sql, (config_fingerprint, ts, policy_name, policy_version, policy_sha256, meta_json)
            )
            self._sqlite_conn.commit()

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
        redactions: Sequence[str],
        raw_payload_for_digest: str,
        latency_ms: float,
        policy_version: str = "2.4.0",
        policy_sha256: str = "",
        config_fingerprint: str = "",
        request_id: str = "",
        extra_provenance: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        if self._closed:
            raise RuntimeError("AuditLedger is closed")

        ts = datetime.now(timezone.utc).isoformat()
        payload_sha256 = hashlib.sha256(raw_payload_for_digest.encode("utf-8")).hexdigest()
        redactions_json = json.dumps(sorted(str(r) for r in redactions), separators=(",", ":"))
        rounded_latency = round(float(latency_ms), 3)

        with self._lock:
            prev_hash = self._get_latest_hash_locked()
            provenance_hash = compute_provenance_hash(
                prev_hash=prev_hash,
                payload_sha256=payload_sha256,
                policy_name=policy_pack,
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                config_fingerprint=config_fingerprint,
                request_id=request_id,
            )
            prov_dict: Dict[str, Any] = {
                "policy_pack": str(policy_pack),
                "policy_version": str(policy_version),
                "policy_sha256": str(policy_sha256),
                "config_fingerprint": str(config_fingerprint),
                "request_id": str(request_id or ""),
            }
            if extra_provenance:
                prov_dict.update(extra_provenance)
            provenance_json = json.dumps(prov_dict, sort_keys=True, separators=(",", ":"))
            provenance_json_sha256 = hashlib.sha256(provenance_json.encode("utf-8")).hexdigest()

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
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                config_fingerprint=config_fingerprint,
                provenance_hash=provenance_hash,
                provenance_json_sha256=provenance_json_sha256,
            )

            params = (
                ts,
                tenant_id,
                endpoint,
                policy_pack,
                policy_version,
                policy_sha256,
                config_fingerprint,
                provenance_hash,
                provenance_json,
                provenance_json_sha256,
                provider,
                action,
                int(http_status),
                vector,
                redactions_json,
                payload_sha256,
                rounded_latency,
                prev_hash,
                entry_hash,
            )

            if self._is_postgres:
                sql = """
                INSERT INTO audit_events (
                    timestamp_utc, tenant_id, endpoint, policy_pack,
                    policy_version, policy_sha256, config_fingerprint,
                    provenance_hash, provenance_json, provenance_json_sha256,
                    provider, action, http_status, vector, redactions_json,
                    payload_sha256, latency_ms, prev_hash, entry_hash
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) RETURNING seq_id
                """
                with self._pg_connection() as conn:
                    cur = conn.cursor()
                    cur.execute(sql, params)
