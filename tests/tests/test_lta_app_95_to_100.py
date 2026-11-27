"""Unit tests covering the final 16 missing statements and partial branches in lta/app.py."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

import lta.app as lta_app_mod
from lta.config import Settings, TenantConfig


def _make_settings(db_file: Path, tenants: List[Dict[str, Any]]) -> Settings:
    cfg = Settings(
        audit_db_url=f"sqlite:///{db_file}",
        redis_url=None,
        default_provider="mock",
    )
    loaded: Dict[str, TenantConfig] = {}
    for entry in tenants:
        key_hash = hashlib.sha256(entry["api_key"].encode("utf-8")).hexdigest()
        loaded[key_hash] = TenantConfig(
            tenant_id=entry["tenant_id"],
            key_hash=key_hash,
            policy_pack=entry.get("policy_pack", "general_enterprise"),
            provider=entry.get("provider", "mock"),
            upstream_model=entry.get("upstream_model", "gpt-4o-mini"),
            rate_limit_rpm=entry.get("rate_limit_rpm", 200),
            role=entry.get("role", "admin"),
        )
    cfg.tenants = loaded
    return cfg


def test_finite_metadata_guard_policies_and_unknown_pack(tmp_path: Path) -> None:
    cfg = _make_settings(
        tmp_path / "guard_policies.db",
        [{"tenant_id": "admin_1", "api_key": "admin-key-1", "role": "admin"}],
    )
    app = lta_app_mod.create_app(cfg)

    with TestClient(app) as client:
        r_pol = client.get("/v1/policies", headers={"X-API-Key": "admin-key-1"})
        assert r_pol.status_code == 200
        assert r_pol.json()["tenant_id"] == "admin_1"
        assert isinstance(r_pol.json()["policies"], list)

        r_guard = client.post(
            "/api/v1/guard",
            headers={"X-API-Key": "admin-key-1"},
            json={"model_input": "Clean corridor status", "metadata": {"lane_miles": 142.5}},
        )
        assert r_guard.status_code == 200

        r_unknown = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "admin-key-1", "X-LTA-Policy": "nonexistent_pack_xyz"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]},
        )
        assert r_unknown.status_code == 400
        assert r_unknown.json()["detail"]["vector"] == "policy.unknown_pack"


def test_readyz_503_when_ledger_unhealthy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _make_settings(
        tmp_path / "readyz_503.db",
        [{"tenant_id": "admin_1", "api_key": "admin-key-1", "role": "admin"}],
    )
    app = lta_app_mod.create_app(cfg)
    monkeypatch.setattr(app.state.audit_ledger, "ping", lambda: False)

    with TestClient(app) as client:
        r = client.get("/readyz")
        assert r.status_code == 503
        assert r.json()["ready"] is False
        assert r.json()["ledger_ok"] is False


def test_shadow_missing_auth_finite_metadata_and_eval_record_fallbacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _make_settings(
        tmp_path / "shadow_fallbacks.db",
        [{"tenant_id": "admin_1", "api_key": "admin-key-1", "role": "admin"}],
    )
    app = lta_app_mod.create_app(cfg)

    with TestClient(app) as client:
        r_no_auth = client.post("/v1/shadow/ingest", json={"prompt": "No auth probe"})
        assert r_no_auth.status_code == 401

        r_valid_meta = client.post(
            "/v1/shadow/ingest",
            headers={"X-API-Key": "admin-key-1"},
            json={"prompt": "Finite metadata probe", "metadata": {"weight_lbs": 42000.0}},
        )
        assert r_valid_meta.status_code == 202

        monkeypatch.setattr(
            app.state.lta_runtime.policy_engine,
            "evaluate_input",
            lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("eval boom")),
        )
        monkeypatch.setattr(
            app.state.audit_ledger,
            "record",
            lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("ledger boom")),
        )

        r_fallback = client.post(
            "/v1/shadow/ingest",
            headers={"X-API-Key": "admin-key-1"},
            json={"prompt": "Fallback path probe"},
        )
        assert r_fallback.status_code == 202
        body = r_fallback.json()
        assert body["accepted"] is True
        assert body["would_allow"] is True
        assert body["seq_id"] is None
