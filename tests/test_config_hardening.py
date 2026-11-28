"""Unit tests covering the hardening changes in lta/config.py."""

from __future__ import annotations

import json

import pytest

from lta.config import Settings, TenantConfig, hash_api_key


@pytest.fixture(autouse=True)
def _clean_lta_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "LTA_TENANTS_JSON",
        "LTA_API_KEY",
        "LTA_DEFAULT_TENANT",
        "LTA_DEFAULT_POLICY",
        "LTA_DEFAULT_PROVIDER",
        "LTA_UPSTREAM_MODEL",
        "LTA_UPSTREAM_TIMEOUT_S",
        "LTA_RATE_LIMIT_RPM",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# 1. key_hash hidden from repr() & normalized to lowercase
# ---------------------------------------------------------------------------


def test_tenant_config_hides_key_hash_from_repr_and_normalizes_case() -> None:
    raw_hash = hash_api_key("secret-token-123").upper()
    tenant = TenantConfig(tenant_id="acme", key_hash=f"  {raw_hash}  ")

    assert tenant.key_hash == raw_hash.lower()
    assert raw_hash.lower() not in repr(tenant)
    assert raw_hash not in repr(tenant)
    assert "acme" in repr(tenant)


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"tenant_id": "", "key_hash": "a" * 64}, "tenant_id"),
        ({"tenant_id": "   ", "key_hash": "a" * 64}, "tenant_id"),
        ({"tenant_id": "acme", "key_hash": "not-a-sha256"}, "key_hash"),
        ({"tenant_id": "acme", "key_hash": "g" * 64}, "key_hash"),
        ({"tenant_id": "acme", "key_hash": "a" * 63}, "key_hash"),
        ({"tenant_id": "acme", "key_hash": "a" * 64, "rate_limit_rpm": 0}, "rate_limit_rpm"),
        ({"tenant_id": "acme", "key_hash": "a" * 64, "rate_limit_rpm": -5}, "rate_limit_rpm"),
    ],
)
def test_tenant_config_rejects_invalid_fields(kwargs: dict, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        TenantConfig(**kwargs)


# ---------------------------------------------------------------------------
# 2. Uppercase key_hash in LTA_TENANTS_JSON authenticates cleanly
# ---------------------------------------------------------------------------


def test_from_env_uppercase_key_hash_authenticates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_key = "lta-live-key-999"
    entries = [
        {
            "tenant_id": "tenant-1",
            "key_hash": hash_api_key(raw_key).upper(),
            "policy_pack": "fmcsa",
            "rate_limit_rpm": 120,
            "role": "ADMIN",
        },
        {
            "tenant_id": "tenant-2",
            "api_key": "lta-other-key-888",
        },
    ]
    monkeypatch.setenv("LTA_TENANTS_JSON", json.dumps(entries))

    settings = Settings.from_env()
    matched = settings.authenticate(raw_key)
    assert matched is not None
    assert matched.tenant_id == "tenant-1"
    assert matched.role == "admin"
    assert matched.rate_limit_rpm == 120

    assert settings.authenticate("lta-other-key-888") is not None
    assert settings.authenticate("wrong-key") is None
    assert settings.authenticate("") is None
    assert settings.authenticate(None) is None


# ---------------------------------------------------------------------------
# 3. Malformed LTA_TENANTS_JSON root types and empty credentials rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload,match",
    [
        (json.dumps({"tenant_id": "not-a-list"}), "JSON array"),
        (json.dumps(["not-a-dict"]), "JSON object"),
        (json.dumps([{"tenant_id": "t1", "api_key": "   "}]), "non-empty 'key_hash' or 'api_key'"),
        (json.dumps([{"tenant_id": "t1"}]), "non-empty 'key_hash' or 'api_key'"),
        (
            json.dumps([{"tenant_id": "t1", "api_key": "k1", "rate_limit_rpm": True}]),
            "rate_limit_rpm",
        ),
        (
            json.dumps([{"tenant_id": "t1", "api_key": "k1", "rate_limit_rpm": 0}]),
            "rate_limit_rpm",
        ),
    ],
)
def test_from_env_rejects_malformed_tenants_json(
    monkeypatch: pytest.MonkeyPatch, payload: str, match: str
) -> None:
    monkeypatch.setenv("LTA_TENANTS_JSON", payload)
    with pytest.raises(ValueError, match=match):
        Settings.from_env()


# ---------------------------------------------------------------------------
# 4. upstream_timeout_s & LTA_RATE_LIMIT_RPM validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_timeout", ["0", "-10", "nan", "inf", "-inf", "abc"])
def test_from_env_rejects_invalid_upstream_timeout(
    monkeypatch: pytest.MonkeyPatch, bad_timeout: str
) -> None:
    monkeypatch.setenv("LTA_UPSTREAM_TIMEOUT_S", bad_timeout)
    with pytest.raises(ValueError, match="LTA_UPSTREAM_TIMEOUT_S"):
        Settings.from_env()


@pytest.mark.parametrize("bad_timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_settings_direct_init_rejects_invalid_timeout(bad_timeout: float) -> None:
    with pytest.raises(ValueError, match="upstream_timeout_s"):
        Settings(upstream_timeout_s=bad_timeout)


@pytest.mark.parametrize("bad_rpm", ["0", "-5", "abc"])
def test_single_key_mode_rejects_invalid_rate_limit_rpm(
    monkeypatch: pytest.MonkeyPatch, bad_rpm: str
) -> None:
    monkeypatch.setenv("LTA_API_KEY", "single-admin-key")
    monkeypatch.setenv("LTA_RATE_LIMIT_RPM", bad_rpm)
    with pytest.raises(ValueError, match="LTA_RATE_LIMIT_RPM"):
        Settings.from_env()


# ---------------------------------------------------------------------------
# 5. Fail-closed when unconfigured
# ---------------------------------------------------------------------------


def test_from_env_unconfigured_fails_closed() -> None:
    settings = Settings.from_env()
    assert settings.tenants == {}
    assert settings.authenticate("any-key") is None