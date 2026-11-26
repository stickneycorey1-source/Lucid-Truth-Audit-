"""Unit tests for lta/rate_limiter.py sliding-window rate limiter."""

from __future__ import annotations

import inspect
import time

from lta.rate_limiter import SlidingWindowRateLimiter


def _make_limiter(window_s: float = 60.0) -> SlidingWindowRateLimiter:
    sig = inspect.signature(SlidingWindowRateLimiter.__init__)
    params = [name for name in sig.parameters if name != "self"]
    kwargs: dict[str, object] = {}

    if params and any(tok in params[0].lower() for tok in ("url", "redis")):
        kwargs[params[0]] = ""

    for name in params[1:]:
        low = name.lower()
        if "window" in low or "period" in low or "ttl" in low:
            kwargs[name] = window_s
        elif "fail" in low:
            kwargs[name] = "memory"

    if kwargs:
        try:
            return SlidingWindowRateLimiter(**kwargs)
        except TypeError:
            pass

    return SlidingWindowRateLimiter("")


def _call_check(limiter: SlidingWindowRateLimiter, key: str, limit_rpm: int) -> bool:
    sig = inspect.signature(limiter.check)
    positional = [
        p for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 2:
        res = limiter.check(key, limit_rpm)
    else:
        res = limiter.check(key)

    if isinstance(res, tuple):
        return bool(res[0])
    if hasattr(res, "allowed"):
        return bool(getattr(res, "allowed"))
    return bool(res)


def test_rate_limiter_blocks_after_limit_and_isolates_tenants():
    limiter = _make_limiter(window_s=60.0)

    assert _call_check(limiter, "p2_pilot", 3) is True
    assert _call_check(limiter, "p2_pilot", 3) is True
    assert _call_check(limiter, "p2_pilot", 3) is True
    assert _call_check(limiter, "p2_pilot", 3) is False

    # Distinct tenant bucket remains unthrottled
    assert _call_check(limiter, "other_tenant", 3) is True


def test_rate_limiter_window_rolls_over_and_reset_works(monkeypatch):
    base_now = 1_700_000_000.0
    current = {"t": base_now}
    monkeypatch.setattr(time, "time", lambda: current["t"])
    monkeypatch.setattr(time, "monotonic", lambda: current["t"])

    limiter = _make_limiter(window_s=10.0)

    assert _call_check(limiter, "dispatch_bot", 2) is True
    assert _call_check(limiter, "dispatch_bot", 2) is True
    assert _call_check(limiter, "dispatch_bot", 2) is False

    # Advance past the 10-second sliding window
    current["t"] = base_now + 11.0
    assert _call_check(limiter, "dispatch_bot", 2) is True

    # Exhaust again and verify reset() clears state
    assert _call_check(limiter, "dispatch_bot", 2) is True
    assert _call_check(limiter, "dispatch_bot", 2) is False
    limiter.reset()
    assert _call_check(limiter, "dispatch_bot", 2) is True