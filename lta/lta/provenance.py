"""Deterministic policy digests, configuration fingerprints, and provenance helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional, Tuple


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
        digest = sha256_canonical({"name": fallback_name, "version": fallback_version})
        return fallback_version, digest

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
    fingerprint_payload = {
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
    return sha256_canonical(fingerprint_payload)


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