"""Exact unit tests covering 100% of lines and branches in lta/config.py."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from lta.config import Settings, TenantConfig, hash_api_key


def _clear_lta_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "LTA_POLICY_DIR",
        "LTA_AUDIT_DB_URL",
        "LTA_REDIS_URL",
        "LTA_DEFAULT_PROVIDER",
        "LTA_UPSTREAM_TIMEOUT_S",
        "LTA_TENANTS_JSON",
        "LTA_API_KEY",
        "LTA_DEFAULT_TENANT",
        "LTA_DEFAULT_POLICY",
        "LTA_UPSTREAM_MODEL",
        "LTA_RATE_LIMIT_RPM",
    ):
        monkeypatch.delenv(var, raising=False)


def test_from_env_fail_closed_when_unconfigured(monkeypatch: pytest.MonkeyPatch):
    _clear_lta_env(monkeypatch)
    cfg = Settings.from_env()

    assert cfg.tenants == {}
    assert cfg.redis_url is None
    assert cfg.default_provider == "mock"
    assert cfg.upstream_timeout_s == 30.0
    assert cfg.authenticate(None) is None
    assert cfg.authenticate("") is None
    assert cfg.authenticate("any-key") is None


def test_from_env_json_tenants_with_raw_and_prehashed_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _clear_lta_env(monkeypatch)
    policy_dir = tmp_path / "custom_policies"
    db_url = f"sqlite:///{tmp_path / 'config_test.db'}"

    monkeypatch.setenv("LTA_POLICY_DIR", str(policy_dir))
    monkeypatch.setenv("LTA_AUDIT_DB_URL", db_url)
    monkeypatch.setenv("LTA_REDIS_URL", "redis://localhost:6379/1")
    monkeypatch.setenv("LTA_DEFAULT_PROVIDER", "openai")
    monkeypatch.setenv("LTA_UPSTREAM_TIMEOUT_S", "12.5")

    prehashed = hash_api_key("admin-prehashed-secret-999")
    entries = [
        {
            "tenant_id": "p2_pilot",
            "api_key": "p2-raw-secret-001",
            "policy_pack": "fmcsa",
            "upstream_model": "gpt-4o",
            "rate_limit_rpm": 90,
            "role": "client",
        },
        {
            "tenant_id": "admin_ops",
            "key_hash": prehashed,
            "provider": "anthropic",
            "role": "admin",
        },
    ]
    monkeypatch.setenv("LTA_TENANTS_JSON", json.dumps(entries))

    cfg = Settings.from_env()
    assert cfg.policy_dir == policy_dir
    assert cfg.audit_db_url == db_url
    assert cfg.redis_url == "redis://localhost:6379/1"
    assert cfg.upstream_timeout_s == 12.5
    assert len(cfg.tenants) == 2

    t_pilot = cfg.authenticate("p2-raw-secret-001")
    assert isinstance(t_pilot, TenantConfig)
    assert t_pilot.tenant_id == "p2_pilot"
    assert t_pilot.policy_pack == "fmcsa"
    assert t_pilot.provider == "openai"  # inherited from settings.default_provider
    assert t_pilot.upstream_model == "gpt-4o"
    assert t_pilot.rate_limit_rpm == 90
    assert t_pilot.role == "client"

    t_admin = cfg.authenticate("admin-prehashed-secret-999")
    assert isinstance(t_admin, TenantConfig)
    assert t_admin.tenant_id == "admin_ops"
    assert t_admin.policy_pack == "general_enterprise"
    assert t_admin.provider == "anthropic"
    assert t_admin.upstream_model == "gpt-4o-mini"
    assert t_admin.rate_limit_rpm == 60
    assert t_admin.role == "admin"

    assert cfg.authenticate("wrong-key-value") is None


def test_from_env_single_key_backward_compatible_mode(monkeypatch: pytest.MonkeyPatch):
    _clear_lta_env(monkeypatch)
    monkeypatch.setenv("LTA_API_KEY", "single-legacy-key-777")
    monkeypatch.setenv("LTA_DEFAULT_TENANT", "p2_single")
    monkeypatch.setenv("LTA_DEFAULT_POLICY", "fmcsa")
    monkeypatch.setenv("LTA_DEFAULT_PROVIDER", "gemini")
    monkeypatch.setenv("LTA_UPSTREAM_MODEL", "gemini-2.5-flash")
    monkeypatch.setenv("LTA_RATE_LIMIT_RPM", "150")

    cfg = Settings.from_env()
    assert len(cfg.tenants) == 1

    tenant = cfg.authenticate("single-legacy-key-777")
    assert tenant is not None
    assert tenant.tenant_id == "p2_single"
    assert tenant.policy_pack == "fmcsa"
    assert tenant.provider == "gemini"
    assert tenant.upstream_model == "gemini-2.5-flash"
    assert tenant.rate_limit_rpm == 150
    assert tenant.role == "admin"

    assert cfg.authenticate("single-legacy-key-778") is None