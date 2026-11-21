"""Sliding-window per-tenant rate limiter (Hardened v2.2 — atomic Redis Lua script)."""

from __future__ import annotations

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
    """Thread-safe sliding-window rate limiter with atomic Redis Lua backend."""

    def __init__(self, redis_url: Optional[str] = None, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}
        self._redis = None
        self._lua = None
        if redis_url:
            import redis  # type: ignore

            self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
            self._lua = self._redis.register_script(_REDIS_SLIDING_WINDOW_LUA)

    def check(self, tenant_id: str, limit_rpm: int) -> Tuple[bool, int]:
        """Return (allowed, remaining_requests) for the tenant in the active window."""
        now = time.time()
        if self._lua is not None:
            key = f"lta:rl:{tenant_id}"
            allowed, remaining = self._lua(
                keys=[key],
                args=[now, self.window_seconds, limit_rpm, f"{now:.6f}:{time.perf_counter_ns()}"],
            )
            return bool(int(allowed)), int(remaining)

        with self._lock:
            bucket = self._buckets.setdefault(tenant_id, deque())
            cutoff = now - self.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit_rpm:
                return False, 0
            bucket.append(now)
            return True, max(0, limit_rpm - len(bucket))

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
