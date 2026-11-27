"""Thread-safe, memory-bounded sliding-window rate limiter with LRU eviction."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable, Deque, Iterator, Optional, Tuple, Union


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: float

    def __iter__(self) -> Iterator[Union[bool, int]]:
        yield self.allowed
        yield self.remaining


class SlidingWindowRateLimiter:
    """Per-key sliding-window rate limiter with bounded memory (LRU + TTL pruning)."""

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        *,
        redis_url: Optional[str] = None,
        max_keys: int = 10_000,
        prune_interval_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")

        self.max_requests = int(max_requests)
        self.window_seconds = float(window_seconds)
        self.redis_url = redis_url
        self.max_keys = int(max_keys)
        self.prune_interval_seconds = float(prune_interval_seconds)
        self._clock = clock

        self._lock = threading.Lock()
        self._buckets: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._last_prune: float = self._clock()

    def _evict_expired_from_bucket(self, bucket: Deque[float], cutoff: float) -> None:
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def _prune_expired_locked(self, now: float) -> int:
        cutoff = now - self.window_seconds
        expired_keys = []
        for k, bucket in self._buckets.items():
            self._evict_expired_from_bucket(bucket, cutoff)
            if not bucket:
                expired_keys.append(k)
        for k in expired_keys:
            del self._buckets[k]
        self._last_prune = now
        return len(expired_keys)

    def _enforce_key_cap_locked(self, now: float) -> None:
        if len(self._buckets) < self.max_keys:
            return
        self._prune_expired_locked(now)
        while len(self._buckets) >= self.max_keys:
            self._buckets.popitem(last=False)

    def check(self, key: str, limit: Optional[int] = None) -> RateLimitResult:
        """Evaluate and record a request for `key` within the sliding window."""
        effective_limit = int(limit) if limit is not None else self.max_requests
        if effective_limit < 1:
            return RateLimitResult(
                allowed=False, limit=0, remaining=0, retry_after_seconds=self.window_seconds
            )

        now = self._clock()
        cutoff = now - self.window_seconds

        with self._lock:
            if (now - self._last_prune) >= self.prune_interval_seconds:
                self._prune_expired_locked(now)

            bucket = self._buckets.get(key)
            if bucket is None:
                self._enforce_key_cap_locked(now)
                bucket = deque()
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)
                self._evict_expired_from_bucket(bucket, cutoff)

            if len(bucket) >= effective_limit:
                oldest = bucket[0]
                retry_after = max(0.0, (oldest + self.window_seconds) - now)
                return RateLimitResult(
                    allowed=False,
                    limit=effective_limit,
                    remaining=0,
                    retry_after_seconds=round(retry_after, 3),
                )

            bucket.append(now)
            remaining = max(0, effective_limit - len(bucket))
            return RateLimitResult(
                allowed=True,
                limit=effective_limit,
                remaining=remaining,
                retry_after_seconds=0.0,
            )

    def allow(self, key: str, limit: Optional[int] = None) -> Tuple[bool, int, float]:
        """Compatibility helper returning (allowed, remaining, retry_after_seconds)."""
        res = self.check(key, limit=limit)
        return res.allowed, res.remaining, res.retry_after_seconds

    def is_allowed(self, key: str, limit: Optional[int] = None) -> bool:
        """Boolean convenience wrapper."""
        return self.check(key, limit=limit).allowed

    def prune_expired(self) -> int:
        """Manually prune all expired buckets and return the count removed."""
        with self._lock:
            return self._prune_expired_locked(self._clock())

    def reset(self, key: Optional[str] = None) -> None:
        """Clear a single key's bucket or reset all tracked buckets."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def tracked_keys(self) -> int:
        """Return the current number of active keys held in memory."""
        with self._lock:
            return len(self._buckets)