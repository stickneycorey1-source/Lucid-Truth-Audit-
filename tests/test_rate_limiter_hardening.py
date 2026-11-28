"""Unit tests covering hardening changes and edge branches in lta/rate_limiter.py."""

from __future__ import annotations

import logging

import pytest

from lta.rate_limiter import SlidingWindowRateLimiter


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ---------------------------------------------------------------------------
# 1. Parameter validation (including non-finite floats & <= 0 bounds)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"max_requests": 0}, "max_requests"),
        ({"max_keys": 0}, "max_keys"),
        ({"window_seconds": 0.0}, "window_seconds"),
        ({"window_seconds": -5.0}, "window_seconds"),
        ({"window_seconds": float("nan")}, "window_seconds"),
        ({"window_seconds": float("inf")}, "window_seconds"),
        ({"prune_interval_seconds": 0.0}, "prune_interval_seconds"),
        ({"prune_interval_seconds": -1.0}, "prune_interval_seconds"),
        ({"prune_interval_seconds": float("nan")}, "prune_interval_seconds"),
        ({"prune_interval_seconds": float("inf")}, "prune_interval_seconds"),
    ],
)
def test_init_rejects_invalid_and_non_finite_parameters(
    kwargs: dict, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        SlidingWindowRateLimiter(**kwargs)


# ---------------------------------------------------------------------------
# 2. Dynamic limit downgrade calculates accurate retry_after
# ---------------------------------------------------------------------------


def test_dynamic_limit_downgrade_retry_after() -> None:
    clock = _FakeClock(start=100.0)
    limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60.0, clock=clock)

    # Record 3 requests at t=100, t=110, t=120 under limit=10
    assert limiter.check("tenant-a", limit=10).allowed is True
    clock.advance(10.0)
    assert limiter.check("tenant-a", limit=10).allowed is True
    clock.advance(10.0)
    assert limiter.check("tenant-a", limit=10).allowed is True

    # At t=125, lower the tenant's limit dynamically to 2.
    # Bucket holds [100, 110, 120]. To drop below 2 entries, both 100 and 110 must expire.
    # The blocking timestamp is bucket[3 - 2] = bucket[1] = 110 -> expires at 170 -> retry_after = 45.0s.
    clock.advance(5.0)
    res = limiter.check("tenant-a", limit=2)
    assert res.allowed is False
    assert res.limit == 2
    assert res.remaining == 0
    assert res.retry_after_seconds == 45.0

    # Advancing 40s (t=165) expires t=100, leaving [110, 120] -> still blocked (2 >= 2)
    clock.advance(40.0)
    res_still_blocked = limiter.check("tenant-a", limit=2)
    assert res_still_blocked.allowed is False
    assert res_still_blocked.retry_after_seconds == 5.0

    # Advancing 5s more (t=170) expires t=110, leaving [120] -> allowed
    clock.advance(5.0)
    res_allowed = limiter.check("tenant-a", limit=2)
    assert res_allowed.allowed is True
    assert res_allowed.remaining == 0


# ---------------------------------------------------------------------------
# 3. LRU eviction, TTL pruning, and tracked_keys / reset
# ---------------------------------------------------------------------------


def test_lru_eviction_respects_max_keys_and_recency() -> None:
    clock = _FakeClock(start=500.0)
    limiter = SlidingWindowRateLimiter(
        max_requests=5,
        window_seconds=60.0,
        max_keys=2,
        prune_interval_seconds=300.0,
        clock=clock,
    )

    assert limiter.check("k1").allowed is True
    clock.advance(1.0)
    assert limiter.check("k2").allowed is True
    assert limiter.tracked_keys() == 2

    # Touch k1 so k2 becomes the least-recently-used key
    clock.advance(1.0)
    assert limiter.check("k1").allowed is True

    # Adding k3 must evict k2, keeping k1 and k3
    clock.advance(1.0)
    assert limiter.check("k3").allowed is True
    assert limiter.tracked_keys() == 2
    assert "k1" in limiter._buckets
    assert "k3" in limiter._buckets
    assert "k2" not in limiter._buckets


def test_manual_and_periodic_prune_expired() -> None:
    clock = _FakeClock(start=200.0)
    limiter = SlidingWindowRateLimiter(
        max_requests=5,
        window_seconds=10.0,
        prune_interval_seconds=15.0,
        clock=clock,
    )

    limiter.check("a")
    limiter.check("b")
    assert limiter.tracked_keys() == 2

    # Advance past window and prune manually
    clock.advance(11.0)
    removed = limiter.prune_expired()
    assert removed == 2
    assert limiter.tracked_keys() == 0

    # Repopulate and trigger automatic periodic prune inside check()
    limiter.check("old-key")
    clock.advance(16.0)
    limiter.check("new-key")
    assert limiter.tracked_keys() == 1
    assert "new-key" in limiter._buckets


# ---------------------------------------------------------------------------
# 4. redis_url warning
# ---------------------------------------------------------------------------


def test_redis_url_logs_local_memory_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="lta.rate_limiter"):
        limiter = SlidingWindowRateLimiter(redis_url="redis://localhost:6379/0")

    assert limiter.redis_url == "redis://localhost:6379/0"
    assert any(
        "local process memory" in record.getMessage() for record in caplog.records
    )


# ---------------------------------------------------------------------------
# 5. Compatibility wrappers, unpacking, reset, and limit < 1
# ---------------------------------------------------------------------------


def test_wrappers_unpacking_reset_and_zero_limit() -> None:
    clock = _FakeClock(start=10.0)
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=30.0, clock=clock)

    # Zero/negative limit immediately denies
    denied = limiter.check("t1", limit=0)
    assert denied.allowed is False
    assert denied.limit == 0
    assert denied.remaining == 0
    assert denied.retry_after_seconds == 30.0

    # RateLimitResult unpacks to (allowed, remaining)
    allowed, remaining = limiter.check("t1")
    assert allowed is True
    assert remaining == 1

    # allow() and is_allowed() wrappers
    ok, rem, retry = limiter.allow("t1")
    assert (ok, rem, retry) == (True, 0, 0.0)
    assert limiter.is_allowed("t1") is False

    # Single-key reset vs full reset
    limiter.check("t2")
    limiter.reset("t1")
    assert limiter.tracked_keys() == 1
    assert limiter.is_allowed("t1") is True

    limiter.reset()
    assert limiter.tracked_keys() == 0