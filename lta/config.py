"""Configuration and per-tenant SHA-256 hashed API key management (fail-closed)."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def hash_api_key(raw_key: str) -> str:
    """Return a SHA-256 hex digest for storing and comparing API keys safely."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _parse_positive_float(raw: str, name: str) -> float:
    try:
        val = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number > 0") from exc
    if not math.isfinite(val) or val <= 0:
        raise ValueError(f"{name} must be a finite number > 0")
    return val


def _parse_positive_int(raw: object, name: str) -> int:
    if isinstance(raw, bool):
        raise ValueError(f"{name} must be an integer >= 1")
    try:
        val = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer >= 1") from exc
    if val < 1:
        raise ValueError(f"{name} must be an integer >= 1")
    return val


@dataclass(frozen=True)
class TenantConfig:
    """Per-tenant authentication, policy pack, upstream provider, and rate limits."""

    tenant_id: str
    key_hash: str = field(repr=False)
    policy_pack: str = "general_enterprise"
    provider: str = "mock"
    upstream_model: str = "gpt-4o-mini"
    rate_limit_rpm: int = 60
    role: str = "client"  # "client" or "admin"

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.tenant_id.strip():
            raise ValueError("tenant_id must be a non-empty string")
        normalized_hash = self.key_hash.strip().lower()
        if not _SHA256_HEX_RE.match(normalized_hash):
            raise ValueError("key_hash must be a valid 64-character SHA-256 hex digest")
        object.__setattr__(self, "key_hash", normalized_hash)
        if self.rate_limit_rpm < 1:
            raise ValueError("rate_limit_rpm must be >= 1")


@dataclass
class Settings:
    """Runtime settings loaded from environment variables with safe defaults."""

    policy_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "LTA_POLICY_DIR",
                str(Path(__file__).resolve().parent.parent / "policy_packs"),
            )
        )
    )
    audit_db_url: str = field(
        default_factory=lambda: os.getenv(
            "LTA_AUDIT_DB_URL", "sqlite:///./lta_audit_ledger.db"
        )
    )
    redis_url: Optional[str] = field(
        default_factory=lambda: os.getenv("LTA_REDIS_URL") or None
    )
    default_provider: str = field(
        default_factory=lambda: os.getenv("LTA_DEFAULT_PROVIDER", "mock")
    )
    upstream_timeout_s: float = field(
        default_factory=lambda: _parse_positive_float(
            os.getenv("LTA_UPSTREAM_TIMEOUT_S", "30.0"),
            "LTA_UPSTREAM_TIMEOUT_S",
        )
    )
    tenants: Dict[str, TenantConfig] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not math.isfinite(self.upstream_timeout_s) or self.upstream_timeout_s <= 0:
            raise ValueError("upstream_timeout_s must be a finite number > 0")

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings and tenant keys from environment variables (fail-closed if unconfigured)."""
        settings = cls()
        raw_json = os.getenv("LTA_TENANTS_JSON", "").strip()
        if raw_json:
            entries = json.loads(raw_json)
            if not isinstance(entries, list):
                raise ValueError("LTA_TENANTS_JSON must be a JSON array of tenant objects")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("Each entry in LTA_TENANTS_JSON must be a JSON object")
                raw_hash = str(entry.get("key_hash") or "").strip()
                if raw_hash:
                    key_hash = raw_hash.lower()
                else:
                    raw_api_key = str(entry.get("api_key") or "").strip()
                    if not raw_api_key:
                        raise ValueError("Tenant entry must provide a non-empty 'key_hash' or 'api_key'")
                    key_hash = hash_api_key(raw_api_key)
                tenant = TenantConfig(
                    tenant_id=str(entry.get("tenant_id") or "").strip(),
                    key_hash=key_hash,
                    policy_pack=entry.get("policy_pack", "general_enterprise"),
                    provider=entry.get("provider", settings.default_provider),
                    upstream_model=entry.get("upstream_model", "gpt-4o-mini"),
                    rate_limit_rpm=_parse_positive_int(
                        entry.get("rate_limit_rpm", 60), "rate_limit_rpm"
                    ),
                    role=str(entry.get("role", "client")).strip().lower() or "client",
                )
                settings.tenants[tenant.key_hash] = tenant
        else:
            # Backward-compatible single-key mode (LTA_API_KEY)
            single_key = os.getenv("LTA_API_KEY", "").strip()
            if single_key:
                kh = hash_api_key(single_key)
                settings.tenants[kh] = TenantConfig(
                    tenant_id=os.getenv("LTA_DEFAULT_TENANT", "default").strip() or "default",
                    key_hash=kh,
                    policy_pack=os.getenv("LTA_DEFAULT_POLICY", "general_enterprise"),
                    provider=settings.default_provider,
                    upstream_model=os.getenv("LTA_UPSTREAM_MODEL", "gpt-4o-mini"),
                    rate_limit_rpm=_parse_positive_int(
                        os.getenv("LTA_RATE_LIMIT_RPM", "60"), "LTA_RATE_LIMIT_RPM"
                    ),
                    role="admin",
                )
        return settings

    def authenticate(self, raw_key: Optional[str]) -> Optional[TenantConfig]:
        """Constant-time verification of a bearer or x-api-key credential."""
        if not raw_key or not self.tenants:
            return None
        candidate = hash_api_key(raw_key)
        matched: Optional[TenantConfig] = None
        for stored_hash, tenant in self.tenants.items():
            if hmac.compare_digest(candidate, stored_hash):
                matched = tenant
        return matched