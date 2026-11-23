import os
import hmac
import time
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
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


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding-window rate limiter with stale-bucket eviction.
    For multi-worker deployments, swap backing store to Redis sorted sets.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0, max_tracked_tenants: int = 5000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tracked_tenants = max_tracked_tenants
        self._buckets: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def _evict_stale_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale_keys = [k for k, ts_list in self._buckets.items() if not ts_list or ts_list[-1] < cutoff]
        for k in stale_keys:
            del self._buckets[k]

    def allow(self, tenant_id: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            if len(self._buckets) > self.max_tracked_tenants:
                self._evict_stale_locked(now)

            timestamps = [t for t in self._buckets.get(tenant_id, []) if t >= cutoff]
            if len(timestamps) >= self.max_requests:
                self._buckets[tenant_id] = timestamps
                return False
            timestamps.append(now)
            self._buckets[tenant_id] = timestamps
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


rate_limiter = SlidingWindowRateLimiter(
    max_requests=int(os.getenv("LUCID_RATE_LIMIT_MAX", "60")),
    window_seconds=float(os.getenv("LUCID_RATE_LIMIT_WINDOW_SEC", "60")),
)


def verify_key_and_limit_raw(x_api_key: Optional[str]) -> Tuple[Optional[TenantContext], int, str]:
    """
    Non-throwing constant-time auth + expiry + rate-limit verifier.
    Returns (TenantContext, 200, "") on success, or (None, http_status, detail)
    preserving exact 503 / 401 / 403 / 429 semantics for exception handlers.
    """
    registry = _parse_tenant_keys()
    if not registry:
        logger.error("security.configuration_error missing_api_key_configuration")
        return None, status.HTTP_503_SERVICE_UNAVAILABLE, "Server authentication secret not configured."

    matched: Optional[TenantContext] = None
    if x_api_key:
        for secret, ctx in registry.items():
            if hmac.compare_digest(x_api_key, secret):
                matched = ctx

    if matched is None:
        logger.warning("security.authentication_rejected")
        return None, status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key."

    if matched.expires_at is not None and datetime.now(timezone.utc) > matched.expires_at:
        logger.warning("security.trial_expired tenant=%s", matched.tenant_id)
        return None, status.HTTP_403_FORBIDDEN, f"Trial API key for tenant '{matched.tenant_id}' has expired."

    if not rate_limiter.allow(matched.tenant_id):
        logger.warning("security.rate_limit_exceeded tenant=%s", matched.tenant_id)
        return None, status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded. Please retry after the current window."

    return matched, status.HTTP_200_OK, ""


def resolve_valid_tenant(x_api_key: Optional[str]) -> Optional[TenantContext]:
    """Backward-compatible helper returning TenantContext if valid and not expired."""
    tenant, code, _ = verify_key_and_limit_raw(x_api_key)
    return tenant if code == status.HTTP_200_OK else None


def authenticate_and_limit(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> TenantContext:
    tenant, code, detail = verify_key_and_limit_raw(x_api_key)
    if tenant is None:
        raise HTTPException(status_code=code, detail=detail)
    return tenant
