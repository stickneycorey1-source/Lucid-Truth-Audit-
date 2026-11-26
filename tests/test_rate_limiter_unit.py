"""Unit tests for lta/rate_limiter.py sliding-window rate limiter."""

from __future__ import annotations

import inspect
import time

from lta.rate_limiter import SlidingWindowRateLimiter


def _make_limiter(limit: int = 3, window_s: float = 60.0) -> SlidingWindowRateLimiter:
    sig = inspect.signature(SlidingWindowRateLimiter.__init__)
    params = [name for name in sig.parameters if name != "self"]
    kwargs: dict[str, object] = {}

    # First parameter is typically redis_url / url
    if params and any(tok in params[0].lower() for tok in ("url", "redis")):
        kwargs[params[0]] = ""

    for name in params[1:]:
        low = name.lower()
        if "window" in low or "period" in low or "ttl" in low:
            kwargs[name] = window_s
        elif any(tok in low for tok in ("limit", "max", "rpm", "capacity", "quota")):
            kwargs[name] = limit

    if kwargs:
        try:
            return SlidingWindowRateLimiter(**kwargs)
        except TypeError:
            pass

    for fallback_kwargs in (
        {"redis_url": "", "limit": limit, "window_seconds": window_s},
        {"url": "", "limit": limit, "window_seconds": window_s},
        {"redis_url": "", "max_requests": limit, "window_seconds": window_s},
    ):
        try:
            return SlidingWindowRateLimiter(**fallback_kwargs)
        except TypeError:
            continue

    return SlidingWindowRateLimiter("")


def _is_allowed(decision: object) -> bool:
    if isinstance(decision, tuple):
        return bool(decision[0])
    if hasattr(decision, "allowed"):
        return bool(getattr(decision, "allowed"))
    return bool(decision)


def test_rate_limiter_blocks_after_limit_and_isolates_tenants():
    limiter = _make_limiter(limit=3, window_s=60.0)

    assert _is_allowed(limiter.check("p2_pilot")) is True
    assert _is_allowed(limiter.check("p2_pilot")) is True
    assert _is_allowed(limiter.check("p2_pilot")) is True
    assert _is_allowed(limiter.check("p2_pilot")) is False

    # Distinct tenant bucket remains unthrottled
    assert _is_allowed(limiter.check("other_tenant")) is True


def test_rate_limiter_window_rolls_over_and_reset_works(monkeypatch):
    base_now = 1_700_000_000.0
    current = {"t": base_now}
    monkeypatch.setattr(time, "time", lambda: current["t"])
    monkeypatch.setattr(time, "monotonic", lambda: current["t"])

    limiter = _make_limiter(limit=2, window_s=10.0)

    assert _is_allowed(limiter.check("dispatch_bot")) is True
    assert _is_allowed(limiter.check("dispatch_bot")) is True
    assert _is_allowed(limiter.check("dispatch_bot")) is False

    # Advance past the 10-second sliding window
    current["t"] = base_now + 11.0
    assert _is_allowed(limiter.check("dispatch_bot")) is True

    # Exhaust again and verify reset() clears state
    assert _is_allowed(limiter.check("dispatch_bot")) is True
    assert _is_allowed(limiter.check("dispatch_bot")) is False
    limiter.reset()
    assert _is_allowed(limiter.check("dispatch_bot")) is True