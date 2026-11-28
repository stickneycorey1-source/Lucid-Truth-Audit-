"""Unit tests covering hardening changes and all auth/expiry/rate-limit branches in app/security.py."""

from __future__ import annotations

import logging

import pytest
from fastapi import HTTPException

import app.security as security_mod
from app.security import (
    SlidingWindowRateLimiter,
    _env_positive_float,
    _env_positive_int,
    _parse_tenant_keys,
    authenticate_and_limit,
    resolve_valid_tenant,
    verify_key_and_limit_raw,
)


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(autouse=True)
def _clean_security_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LUCID_TENANT_KEYS", raising=False)
    monkeypatch.delenv("LUCID_AUDIT_API_KEY", raising=False)
    security_mod.rate_limiter.reset()


# ---------------------------------------------------------------------------
# 1. Env-var positive int/float parsers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["0", "-5", "abc"])
def test_env_positive_int_falls_back_on_invalid(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw: str
) -> None:
    monkeypatch.setenv("TEST_POS_INT", raw)
    with caplog.at_level(logging.WARNING, logger="lucid_truth_audit"):
        assert _env_positive_int("TEST_POS_INT", 42) == 42
    assert any("using_default=42" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("raw", ["0", "-1.5", "nan", "inf", "-inf", "not-a-float"])
def test_env_positive_float_falls_back_on_invalid(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw: str
) -> None:
    monkeypatch.setenv("TEST_POS_FLOAT", raw)
    with caplog.at_level(logging.WARNING, logger="lucid_truth_audit"):
        assert _env_positive_float("TEST_POS_FLOAT", 30.0) == 30.0
    assert any("using_default=30.0" in r.getMessage() for r in caplog.records)


def test_env_positive_parsers_return_valid_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_POS_INT", "120")
    monkeypatch.setenv("TEST_POS_FLOAT", "45.5")
    assert _env_positive_int("TEST_POS_INT", 60) == 120
    assert _env_positive_float("TEST_POS_FLOAT", 60.0) == 45.5


# ---------------------------------------------------------------------------
# 2. _parse_tenant_keys parsing, invalid expiry skip, and single-key fallback
# ---------------------------------------------------------------------------


def test_parse_tenant_keys_handles_multi_invalid_expiry_and_single_fallback(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(
        "LUCID_TENANT_KEYS",
        "acme:key-acme:2099-12-31, beta:key-beta:never, bad:key-bad:not-a-date, ,",
    )
    monkeypatch.setenv("LUCID_AUDIT_API_KEY", "legacy-default-key")

    with caplog.at_level(logging.ERROR, logger="lucid_truth_audit"):
        registry = _parse_tenant_keys()

    assert set(registry.keys()) == {"key-acme", "key-beta", "legacy-default-key"}
    assert registry["key-acme"].tenant_id == "acme"
    assert registry["key-acme"].expires_at is not None
    assert registry["key-beta"].tenant_id == "beta"
    assert registry["key-beta"].expires_at is None
    assert registry["legacy-default-key"].tenant_id == "default"
    assert any("invalid_tenant_expiry tenant=bad" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# 3. SlidingWindowRateLimiter validation, monotonic window, and LRU eviction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"max_requests": 0}, "max_requests"),
        ({"window_seconds": 0.0}, "window_seconds"),
        ({"window_seconds": float("nan")}, "window_seconds"),
        ({"window_seconds": float("inf")}, "window_seconds"),
        ({"max_tracked_tenants": 0}, "max_tracked_tenants"),
    ],
)
def test_rate_limiter_rejects_invalid_params(kwargs: dict, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        SlidingWindowRateLimiter(**kwargs)


def test_rate_limiter_enforces_lru_cap_and_sliding_window() -> None:
    clock = _FakeClock(start=500.0)
    limiter = SlidingWindowRateLimiter(
        max_requests=2,
        window_seconds=10.0,
        max_tracked_tenants=2,
        clock=clock,
    )

    assert limiter.allow("t1") is True
    clock.advance(1.0)
    assert limiter.allow("t2") is True
    # Touch t1 so t2 becomes least-recently-used
    clock.advance(1.0)
    assert limiter.allow("t1") is True
    # t1 is now at max_requests=2
    assert limiter.allow("t1") is False

    # Adding t3 must evict t2 (LRU) while staying bounded at max_tracked_tenants=2
    clock.advance(1.0)
    assert limiter.allow("t3") is True
    assert len(limiter._buckets) == 2
    assert "t1" in limiter._buckets
    assert "t3" in limiter._buckets
    assert "t2" not in limiter._buckets

    # Advance past window so t1's timestamps expire and t1 is allowed again
    clock.advance(10.0)
    assert limiter.allow("t1") is True


# ---------------------------------------------------------------------------
# 4. verify_key_and_limit_raw: 503 / 401 (including non-ASCII) / 403 / 429 / 200
# ---------------------------------------------------------------------------


def test_verify_returns_503_when_unconfigured() -> None:
    tenant, code, detail = verify_key_and_limit_raw("any-key")
    assert tenant is None
    assert code == 503
    assert "not configured" in detail


@pytest.mark.parametrize("bad_key", [None, "", "wrong-key", "k\u00e9y-non-ascii-\U0001f511"])
def test_verify_returns_401_for_missing_wrong_or_non_ascii_key(
    monkeypatch: pytest.MonkeyPatch, bad_key: str | None
) -> None:
    monkeypatch.setenv("LUCID_AUDIT_API_KEY", "valid-secret-key")
    tenant, code, detail = verify_key_and_limit_raw(bad_key)
    assert tenant is None
    assert code == 401
    assert "Invalid or missing API key" in detail


def test_verify_returns_403_for_expired_trial_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCID_TENANT_KEYS", "trial_co:expired-key:2020-01-01")
    tenant, code, detail = verify_key_and_limit_raw("expired-key")
    assert tenant is None
    assert code == 403
    assert "expired" in detail


def test_verify_returns_429_when_rate_limit_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCID_AUDIT_API_KEY", "valid-secret-key")
    tight_limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60.0)
    monkeypatch.setattr(security_mod, "rate_limiter", tight_limiter)

    t1, code1, _ = verify_key_and_limit_raw("valid-secret-key")
    assert t1 is not None
    assert code1 == 200

    t2, code2, detail2 = verify_key_and_limit_raw("valid-secret-key")
    assert t2 is None
    assert code2 == 429
    assert "Rate limit exceeded" in detail2


# ---------------------------------------------------------------------------
# 5. resolve_valid_tenant & authenticate_and_limit wrappers
# ---------------------------------------------------------------------------


def test_wrappers_success_and_http_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCID_AUDIT_API_KEY", "valid-secret-key")

    ctx = resolve_valid_tenant("valid-secret-key")
    assert ctx is not None
    assert ctx.tenant_id == "default"

    assert resolve_valid_tenant("wrong-key") is None

    auth_ctx = authenticate_and_limit(x_api_key="valid-secret-key")
    assert auth_ctx.tenant_id == "default"

    with pytest.raises(HTTPException) as exc_info:
        authenticate_and_limit(x_api_key="wrong-key")
    assert exc_info.value.status_code == 401