import os
import hmac
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import Header, HTTPException, status

logger = logging.getLogger("lucid_truth_audit")


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    expires_at: Optional[datetime] = None


def _parse_tenant_keys() -> Dict[str, TenantContext]:
    """
    Supports multi-tenant trial keys via env var LUCID_TENANT_KEYS:
      format: "tenant_id:secret_key:YYYY-MM-DD,tenant_id2:secret_key2:never"
    Also supports backward-compatible single key via LUCID_AUDIT_API_KEY.
    """
    registry: Dict[str, TenantContext] = {}

    multi_raw = os.getenv("LUCID_TENANT_KEYS", "").strip()
    if multi_raw:
        for entry in multi_raw.split(","):
            parts = [p.strip() for p in entry.split(":")]
            if len(parts) >= 2 and parts[0] and parts[1]:
                tenant_id, secret = parts[0], parts[1]
                exp_dt: Optional[datetime] = None
                if len(parts) >= 3 and parts[2].lower() not in ("", "never", "none"):
                    try:
                        exp_dt = datetime.strptime(parts[2], "%Y-%m-%d").replace(
                            hour=23, minute=59, second=59, tzinfo=timezone.utc
                        )
                    except ValueError:
                        logger.error("security.configuration_error invalid_tenant_expiry tenant=%s", tenant_id)
                        continue
                registry[secret] = TenantContext(tenant_id=tenant_id, expires_at=exp_dt)

    single_key = os.getenv("LUCID_AUDIT_API_KEY", "").strip()
    if single_key and single_key not in registry:
        registry[single_key] = TenantContext(tenant_id="default", expires_at=None)

    return registry


def resolve_valid_tenant(x_api_key: Optional[str]) -> Optional[TenantContext]:
    """
    Constant-time scan across all configured tenant keys (no early break).
    Returns TenantContext ONLY if key matches and is not expired; otherwise None.
    Used by validation exception handlers so unauthenticated traffic cannot spam SQLite.
    """
    if not x_api_key:
        return None
    registry = _parse_tenant_keys()
    matched: Optional[TenantContext] = None
    for secret, ctx in registry.items():
        if hmac.compare_digest(x_api_key, secret):
            matched = ctx
    if matched is None:
        return None
    if matched.expires_at is not None and datetime.now(timezone.utc) > matched.expires_at:
        return None
    return matched


class SlidingWindowRateLimiter:
    """
    In-memory sliding-window rate limiter with periodic stale-bucket eviction.
    For multi-worker deployments, swap backing store to Redis sorted sets.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0, max_tracked_tenants: int = 5000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tracked_tenants = max_tracked_tenants
        self._buckets: Dict[str, List[float]] = {}

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale_keys = [k for k, ts_list in self._buckets.items() if not ts_list or ts_list[-1] < cutoff]
        for k in stale_keys:
            del self._buckets[k]

    def allow(self, tenant_id: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        if len(self._buckets) > self.max_tracked_tenants:
            self._evict_stale(now)

        timestamps = [t for t in self._buckets.get(tenant_id, []) if t >= cutoff]
        if len(timestamps) >= self.max_requests:
            self._buckets[tenant_id] = timestamps
            return False
        timestamps.append(now)
        self._buckets[tenant_id] = timestamps
        return True

    def reset(self) -> None:
        self._buckets.clear()


rate_limiter = SlidingWindowRateLimiter(
    max_requests=int(os.getenv("LUCID_RATE_LIMIT_MAX", "60")),
    window_seconds=float(os.getenv("LUCID_RATE_LIMIT_WINDOW_SEC", "60")),
)


def authenticate_and_limit(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> TenantContext:
    registry = _parse_tenant_keys()
    if not registry:
        logger.error("security.configuration_error missing_api_key_configuration")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server authentication secret not configured.",
        )

    matched: Optional[TenantContext] = None
    if x_api_key:
        # Always evaluate every secret in constant time without early exit
        for secret, ctx in registry.items():
            if hmac.compare_digest(x_api_key, secret):
                matched = ctx

    if matched is None:
        logger.warning("security.authentication_rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )

    if matched.expires_at is not None and datetime.now(timezone.utc) > matched.expires_at:
        logger.warning("security.trial_expired tenant=%s", matched.tenant_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Trial API key for tenant '{matched.tenant_id}' has expired.",
        )

    if not rate_limiter.allow(matched.tenant_id):
        logger.warning("security.rate_limit_exceeded tenant=%s", matched.tenant_id)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please retry after the current window.",
        )

    return matched