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

    def
