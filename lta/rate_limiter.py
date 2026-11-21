"""Sliding-window per-tenant rate limiter (in-memory default + Redis adapter)."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter with optional Redis backend."""

    def __init__(self, redis_url: Optional[str] = None, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}
        self._redis = None
        if redis_url:
            import redis  # type: ignore

            self._redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def check(self, tenant_id: str, limit_rpm: int) -> Tuple[bool, int]:
        """Return (allowed, remaining_requests) for the tenant in the active window."""
        now = time.time()
        if self._redis is not None:
            key = f"lta:rl:{tenant_id}"
            cutoff = now - self.window_seconds
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zcard(key)
            _, current_count = pipe.execute()
            if int(current_count) >= limit_rpm:
                return False, 0
            pipe = self._redis.pipeline()
            pipe.zadd(key, {f"{now:.6f}": now})
            pipe.expire(key, self.window_seconds + 5)
            pipe.execute()
            return True, max(0, limit_rpm - int(current_count) - 1)

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
