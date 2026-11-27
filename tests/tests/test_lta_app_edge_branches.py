"""Targeted unit tests closing remaining edge branches in lta/app.py."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

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
            role=entry.get("role", "client"),
        )
    cfg.tenants = loaded
    return cfg


def test_metadata_validators_reject_non_finite_floats() -> None:
    for bad_val in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError, match="Non-finite float"):
            lta_app_mod.OpenAIChatCompletionRequest(
                messages=[{"role": "user", "content": "hi"}],
                metadata={"score": bad_val},
            )
        with pytest.raises(ValidationError, match="Non-finite float"):
            lta_app_mod.LegacyGuardRequest(
                model_input="hi",
                metadata={"score": bad_val},
            )
        with pytest.raises(ValidationError, match="Non-finite float"):
            lta_app_mod.ShadowIngestRequest(
                prompt="hi",
                metadata={"score": bad_val},
            )


def test_header_extractors_and_short_hash_padding() -> None:
    assert lta_app_mod._extract_api_key(None, "Basic dXNlcjpwYXNz") is None
    assert lta_app_mod._extract_api_key(None, "Bearer   ") is None
    assert lta_app_mod._extract_api_key(None, "Bearer tok-123") == "tok-123"

    req_xff = SimpleNamespace(
        headers={"x-forwarded-for": "203.0.113.10, 10.0.0.1"},
        client=SimpleNamespace(host="127.0.0.1"),
    )
    assert lta_app_mod._client_ip(req_xff) == "203.0.113.10"  # type: ignore[arg-type]

    short_hex = "a" * 32
    assert lta_app_mod._extract_entry_hash({"digest": short_hex}, "seed") == short_hex.ljust(64, "0")
    assert lta_app_mod._extract_entry_hash(SimpleNamespace(record_hash=short_hex), "seed") == short_hex.ljust(64, "0")


def test_sqlite_path_and_chain_inspection_edge_cases(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.db"
    assert lta_app_mod._resolve_sqlite_path(str(missing)) is None
    assert lta_app_mod._inspect_sqlite_chain(f"sqlite:///{missing}") == (False, None)

    # Raw existing path without sqlite:/// prefix, empty DB (no audit_events table)
    empty_db = tmp_path / "empty.db"
    sqlite3.connect(str(empty_db)).close()
    assert lta_app_mod._resolve_sqlite_path(str(empty_db)) == str(empty_db)
    assert lta_app_mod._inspect_sqlite_chain(str(empty_db)) == (False, None)

    # Table without hash column
    no_hash_db = tmp_path / "no_hash.db"
    conn = sqlite3.connect(str(no_hash_db))
    try:
        conn.execute("CREATE TABLE audit_events (id TEXT, action TEXT)")
        conn.execute("INSERT INTO audit_events VALUES ('not-an-int', 'ALLOW')")
        conn.commit()
    finally:
        conn.close()
    assert lta_app_mod._inspect_sqlite_chain(f"sqlite:///{no_hash_db}") == (False, None)

    # Valid 2-row chain
    valid_db = tmp_path / "valid_chain.db"
    conn = sqlite3.connect(str(valid_db))
    try:
        conn.execute("CREATE TABLE audit_events (seq_id INTEGER, prev_hash TEXT, entry_hash TEXT)")
        conn.execute("INSERT INTO audit_events VALUES (1, ?, ?)", ("0" * 64, "1" * 64))
        conn.execute("INSERT INTO audit_events VALUES (2, ?, ?)", ("1" * 64, "2" * 64))
        conn.commit()
    finally:
        conn.close()
    assert lta_app_mod._inspect_sqlite_chain(f"sqlite:///{valid_db}") == (False, None)

    # Corrupt file triggers sqlite3.Error
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"not a valid sqlite database header")
    assert lta_app_mod._inspect_sqlite_chain(f"sqlite:///{corrupt_db}") == (False, None)


def test_shadow_env_key_auth_and_get_pack_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LTA_SHADOW_KEY", "env-shadow-secret-999")
    cfg = _make_settings(
        tmp_path / "shadow_env.db",
        [{"tenant_id": "client_1", "api_key": "client-key-1", "role": "client"}],
    )
    app = lta_app_mod.create_app(cfg)

    with TestClient(app) as client:
        r_ok = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer env-shadow-secret-999"},
            json={"prompt": "Shadow check with env key"},
        )
        assert r_ok.status_code == 202

        r_bad = client.post(
            "/v1/shadow/ingest",
            headers={"Authorization": "Bearer wrong-env-key"},
            json={"prompt": "Shadow check wrong key"},
        )
        assert r_bad.status_code == 403

    # Trigger get_pack exception branch inside _resolve_runtime_provenance
    cfg2 = _make_settings(
        tmp_path / "pack_fallback.db",
        [{"tenant_id": "client_1", "api_key": "client-key-1", "role": "client"}],
    )
    app2 = lta_app_mod.create_app(cfg2)
    monkeypatch.setattr(
        app2.state.lta_runtime.policy_engine,
        "get_pack",
        lambda _name: (_ for _ in ()).throw(KeyError("missing pack")),
    )
    with TestClient(app2) as client:
        r_override = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "client-key-1", "X-LTA-Policy": "fmcsa"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r_override.status_code == 403