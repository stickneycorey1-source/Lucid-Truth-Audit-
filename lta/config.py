"""Configuration and per-tenant SHA-256 hashed API key management (fail-closed)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


def hash_api_key(raw_key: str) -> str:
    """Return a SHA-256 hex digest for storing and comparing API keys safely."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TenantConfig:
    """Per-tenant authentication, policy pack, upstream provider, and rate limits."""

    tenant_id: str
    key_hash: str
    policy_pack: str = "general_enterprise"
    provider: str = "mock"
    upstream_model: str = "gpt-4o-mini"
    rate_limit_rpm: int = 60
    role: str = "client"  # "client" or "admin"


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
        default_factory=lambda: float(os.getenv("LTA_UPSTREAM_TIMEOUT_S", "30.0"))
    )
    tenants: Dict[str, TenantConfig] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings and tenant keys from environment variables (fail-closed if unconfigured)."""
        settings = cls()
        raw_json = os.getenv("LTA_TENANTS_JSON", "").strip()
        if raw_json:
            entries = json.loads(raw_json)
            for entry in entries:
                key_hash = entry.get("key_hash") or hash_api_key(entry["api_key"])
                tenant = TenantConfig(
                    tenant_id=entry["tenant_id"],
                    key_hash=key_hash,
                    policy_pack=entry.get("policy_pack", "general_enterprise"),
                    provider=entry.get("provider", settings.default_provider),
                    upstream_model=entry.get("upstream_model", "gpt-4o-mini"),
                    rate_limit_rpm=int(entry.get("rate_limit_rpm", 60)),
                    role=entry.get("role", "client"),
                )
                settings.tenants[tenant.key_hash] = tenant
        else:
            # Backward-compatible single-key mode (LTA_API_KEY)
            single_key = os.getenv("LTA_API_KEY", "").strip()
            if single_key:
                kh = hash_api_key(single_key)
                settings.tenants[kh] = TenantConfig(
                    tenant_id=os.getenv("LTA_DEFAULT_TENANT", "default"),
                    key_hash=kh,
                    policy_pack=os.getenv("LTA_DEFAULT_POLICY", "general_enterprise"),
                    provider=settings.default_provider,
                    upstream_model=os.getenv("LTA_UPSTREAM_MODEL", "gpt-4o-mini"),
                    rate_limit_rpm=int(os.getenv("LTA_RATE_LIMIT_RPM", "60")),
                    role="admin",
                )
        return settings

    def authenticate(self, raw_key: Optional[str]) -> Optional[TenantConfig]:
        """Constant-time verification of a bearer or x-api-key credential."""
        if not raw_key or not self.tenants:
            return None
        candidate = hash_api_key(raw_key)
        for stored_hash, tenant in self.tenants.items():
            if hmac.compare_digest(candidate, stored_hash):
                return tenant
        return None