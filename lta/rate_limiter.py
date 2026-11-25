"""Sliding-window per-tenant & failed-auth rate limiter (Hardened v2.4 — Redis timeouts + resilient fallback)."""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple


_REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
    return {0, 0}
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window) + 5)
return {1, limit - count - 1}
"""


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter with atomic Redis Lua backend and fallback."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        window_seconds: int = 60,
        fail_mode: Optional[str] = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.fail_mode = (
            fail_mode or os.getenv("LTA_REDIS_FAIL_MODE", "memory")
        ).lower().strip()
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}
        self._redis = None
        self._lua = None
        if redis_url:
            import redis  # type: ignore

            self._redis = redis.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
            )
            self._lua = self._redis.register_script(_REDIS_SLIDING_WINDOW_LUA)

    def _check_memory(self, bucket_key: str, limit_rpm: int, now: float) -> Tuple[bool, int]:
        with self._lock:
            bucket = self._buckets.setdefault(bucket_key, deque())
            cutoff = now - self.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit_rpm:
                return False, 0
            bucket.append(now)
            return True, max(0, limit_rpm - len(bucket))

    def check(self, tenant_id: str, limit_rpm: int) -> Tuple[bool, int]:
        """Return (allowed, remaining_requests) for the bucket key in the active window."""
        now = time.time()
        if self._lua is not None:
            try:
                key = f"lta:rl:{tenant_id}"
                allowed, remaining = self._lua(
                    keys=[key],
                    args=[
                        now,
                        self.window_seconds,
                        limit_rpm,
                        f"{now:.6f}:{time.perf_counter_ns()}",
                    ],
                )
                return bool(int(allowed)), int(remaining)
            except Exception:
                if self.fail_mode == "closed":
                    return False, 0
                return self._check_memory(tenant_id, limit_rpm, now)

        return self._check_memory(tenant_id, limit_rpm, now)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()