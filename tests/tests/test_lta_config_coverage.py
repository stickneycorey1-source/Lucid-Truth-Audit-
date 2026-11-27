"""Unit tests covering remaining branches in lta/config.py."""

from __future__ import annotations

import pytest

from lta.config import Settings, hash_api_key


def test_settings_from_env_single_key_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LTA_TENANTS_JSON", raising=False)
    monkeypatch.setenv("LTA_API_KEY", "single-operator-key")
    monkeypatch.setenv("LTA_DEFAULT_TENANT", "p2_single")
    monkeypatch.setenv("LTA_DEFAULT_POLICY", "fmcsa")
    monkeypatch.setenv("LTA_DEFAULT_PROVIDER", "mock")
    monkeypatch.setenv("LTA_UPSTREAM_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("LTA_RATE_LIMIT_RPM", "120")

    cfg = Settings.from_env()
    expected_hash = hash_api_key("single-operator-key")
    assert expected_hash in cfg.tenants

    tenant = cfg.authenticate("single-operator-key")
    assert tenant is not None
    assert tenant.tenant_id == "p2_single"
    assert tenant.policy_pack == "fmcsa"
    assert tenant.rate_limit_rpm == 120
    assert tenant.role == "admin"


def test_authenticate_returns_none_on_empty_key_or_empty_tenants() -> None:
    empty_settings = Settings(tenants={})
    assert empty_settings.authenticate("any-key") is None
    assert empty_settings.authenticate(None) is None
    assert empty_settings.authenticate("") is None

    populated = Settings.from_env()
    populated.tenants = {
        hash_api_key("valid-key"): populated.tenants.get(hash_api_key("valid-key"))  # type: ignore[dict-item]
    }
    # Rebuild cleanly with a real TenantConfig entry
    from lta.config import TenantConfig

    kh = hash_api_key("valid-key")
    populated.tenants = {kh: TenantConfig(tenant_id="t1", key_hash=kh)}
    assert populated.authenticate(None) is None
    assert populated.authenticate("") is None