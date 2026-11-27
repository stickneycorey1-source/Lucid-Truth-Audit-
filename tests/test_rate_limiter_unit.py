"""Unit tests for SlidingWindowRateLimiter isolation, rollover, reset, and OOM cap."""

from __future__ import annotations

from lta.rate_limiter import SlidingWindowRateLimiter


def test_rate_limiter_blocks_after_limit_and_isolates_tenants() -> None:
    now = [100.0]
    limiter = SlidingWindowRateLimiter(
        max_requests=2,
        window_seconds=60.0,
        clock=lambda: now[0],
    )

    r1 = limiter.check("tenant-a")
    assert r1.allowed is True
    assert r1.remaining == 1

    r2 = limiter.check("tenant-a")
    assert r2.allowed is True
    assert r2.remaining == 0

    r3 = limiter.check("tenant-a")
    assert r3.allowed is False
    assert r3.remaining == 0
    assert r3.retry_after_seconds > 0

    # Distinct tenant bucket remains unaffected
    other = limiter.check("tenant-b")
    assert other.allowed is True
    assert other.remaining == 1


def test_rate_limiter_window_rolls_over_and_reset_works() -> None:
    now = [500.0]
    limiter = SlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=10.0,
        clock=lambda: now[0],
    )

    assert limiter.is_allowed("tenant-a") is True
    assert limiter.is_allowed("tenant-a") is False

    # Advance past the sliding window
    now[0] += 11.0
    assert limiter.is_allowed("tenant-a") is True
    assert limiter.is_allowed("tenant-a") is False

    # Reset single key
    limiter.reset("tenant-a")
    assert limiter.is_allowed("tenant-a") is True

    # Reset all keys
    limiter.reset()
    assert limiter.tracked_keys() == 0


def test_rate_limiter_caps_tracked_keys_and_prunes_expired() -> None:
    now = [1000.0]
    limiter = SlidingWindowRateLimiter(
        max_requests=5,
        window_seconds=10.0,
        max_keys=50,
        prune_interval_seconds=60.0,
        clock=lambda: now[0],
    )

    for i in range(200):
        assert limiter.is_allowed(f"spoofed-ip-{i}") is True

    assert limiter.tracked_keys() <= 50

    now[0] += 15.0
    removed = limiter.prune_expired()
    assert removed > 0
    assert limiter.tracked_keys() == 0