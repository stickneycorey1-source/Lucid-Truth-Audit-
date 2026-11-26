"""Dedicated unit tests for policy digests, configuration fingerprints, and provenance hashes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import pytest

from lta.audit_ledger import AuditLedger, GENESIS_HASH

try:
    from lta.provenance import (
        compute_config_fingerprint,
        compute_policy_digest,
        compute_provenance_hash,
    )
except ImportError:
    from lta.audit_ledger import (  # type: ignore[no-redef]
        compute_config_fingerprint,
        compute_policy_digest,
        compute_provenance_hash,
    )


@dataclass
class _FakePolicyPack:
    name: str
    version: str
    rules: List[str]
    _internal_state: str = "ephemeral-cache-token"


def test_compute_policy_digest_determinism_and_rule_sensitivity() -> None:
    pack_a: Dict[str, Any] = {
        "name": "fmcsa",
        "version": "2.4.0",
        "rules": ["hos_cycle_limit", "cdl_redaction"],
        "frameworks": ["DOT-1351.41", "NMFTA"],
    }
    # Reordered keys + runtime_cache noise should produce the exact same policy_sha256
    pack_reordered: Dict[str, Any] = {
        "frameworks": ["DOT-1351.41", "NMFTA"],
        "rules": ["hos_cycle_limit", "cdl_redaction"],
        "version": "2.4.0",
        "name": "fmcsa",
        "runtime_cache": {"hits": 999},
    }

    ver_a, sha_a = compute_policy_digest(pack_a, fallback_name="fmcsa")
    ver_b, sha_b = compute_policy_digest(pack_reordered, fallback_name="fmcsa")

    assert ver_a == "2.4.0"
    assert ver_b == "2.4.0"
    assert len(sha_a) == 64
    assert sha_a == sha_b

    # Mutating a rule without changing version must alter policy_sha256
    pack_mutated: Dict[str, Any] = {
        "name": "fmcsa",
        "version": "2.4.0",
        "rules": ["hos_cycle_limit", "cdl_redaction", "bol_injection_guard"],
        "frameworks": ["DOT-1351.41", "NMFTA"],
    }
    _, sha_mutated = compute_policy_digest(pack_mutated, fallback_name="fmcsa")
    assert sha_mutated != sha_a


def test_compute_policy_digest_object_and_none_fallback() -> None:
    obj_pack = _FakePolicyPack(
        name="p2_fleet_pack",
        version="2.4.0",
        rules=["weight_limit", "ssn_redaction"],
        _internal_state="changed-value",
    )
    ver, digest = compute_policy_digest(obj_pack, fallback_name="p2_fleet_pack")
    assert ver == "2.4.0"
    assert len(digest) == 64

    # Private attributes starting with '_' should not affect the digest
    obj_pack._internal_state = "different-ephemeral-value"
    _, digest_after_private_change = compute_policy_digest(obj_pack, fallback_name="p2_fleet_pack")
    assert digest_after_private_change == digest

    # None pack falls back deterministically to fallback_name + fallback_version
    fb_ver, fb_digest = compute_policy_digest(None, fallback_name="general_enterprise", fallback_version="2.4.0")
    assert fb_ver == "2.4.0"
    assert len(fb_digest) == 64


def test_compute_config_fingerprint_sensitivity_to_runtime_settings() -> None:
    base_kwargs = dict(
        gateway_version="2.4.0",
        policy_name="fmcsa",
        policy_version="2.4.0",
        policy_sha256="1" * 64,
        provider="mock",
        max_body_bytes=262144,
        rate_limit_rpm=120,
        auth_fail_limit_rpm=20,
        extra_flags={"zero_retention": True, "nfkc": True},
    )

    fp_1 = compute_config_fingerprint(**base_kwargs)
    fp_2 = compute_config_fingerprint(**base_kwargs)
    assert len(fp_1) == 64
    assert fp_1 == fp_2

    # Changing rate limit, policy digest, or flags must change the fingerprint
    fp_rate = compute_config_fingerprint(**{**base_kwargs, "rate_limit_rpm": 60})
    fp_policy = compute_config_fingerprint(**{**base_kwargs, "policy_sha256": "2" * 64})
    fp_flags = compute_config_fingerprint(
        **{**base_kwargs, "extra_flags": {"zero_retention": True, "nfkc": False}}
    )

    assert fp_rate != fp_1
    assert fp_policy != fp_1
    assert fp_flags != fp_1


def test_compute_provenance_hash_binds_chain_payload_and_config() -> None:
    kwargs = dict(
        prev_hash=GENESIS_HASH,
        payload_sha256="a" * 64,
        policy_name="fmcsa",
        policy_version="2.4.0",
        policy_sha256="b" * 64,
        config_fingerprint="c" * 64,
        request_id="req-p2-001",
    )

    h1 = compute_provenance_hash(**kwargs)
    h2 = compute_provenance_hash(**kwargs)
    assert len(h1) == 64
    assert h1 == h2

    assert compute_provenance_hash(**{**kwargs, "prev_hash": "f" * 64}) != h1
    assert compute_provenance_hash(**{**kwargs, "payload_sha256": "d" * 64}) != h1
    assert compute_provenance_hash(**{**kwargs, "policy_sha256": "e" * 64}) != h1
    assert compute_provenance_hash(**{**kwargs, "config_fingerprint": "0" * 64}) != h1
    assert compute_provenance_hash(**{**kwargs, "request_id": "req-p2-002"}) != h1


def test_ledger_records_and_verifies_provenance_chain(tmp_path: Path) -> None:
    db_path = tmp_path / "provenance_chain.db"
    ledger = AuditLedger(f"sqlite:///{db_path}")
    try:
        pol_ver, pol_sha = compute_policy_digest(
            {"name": "fmcsa", "version": "2.4.0", "rules": ["hos_check"]},
            fallback_name="fmcsa",
        )
        cfg_fp = compute_config_fingerprint(
            gateway_version="2.4.0",
            policy_name="fmcsa",
            policy_version=pol_ver,
            policy_sha256=pol_sha,
            provider="mock",
            max_body_bytes=262144,
            rate_limit_rpm=120,
            auth_fail_limit_rpm=20,
        )

        rec = ledger.record(
            tenant_id="p2_transport_pilot",
            endpoint="/v1/chat/completions",
            policy_pack="fmcsa",
            provider="mock",
            action="ALLOW",
            http_status=200,
            vector=None,
            redactions=[],
            raw_payload_for_digest="Dispatch check for P2 fleet",
            latency_ms=3.45,
            policy_version=pol_ver,
            policy_sha256=pol_sha,
            config_fingerprint=cfg_fp,
            request_id="req-nov30-prep",
        )

        assert rec.policy_version == pol_ver
        assert rec.policy_sha256 == pol_sha
        assert rec.config_fingerprint == cfg_fp
        assert len(rec.provenance_hash) == 64

        valid, total, broken = ledger.verify_chain()
        assert valid is True
        assert total == 1
        assert broken is None
    finally:
        ledger.close()