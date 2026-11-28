"""Unit tests covering hardening changes in app/evidence_chain.py."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.evidence_chain import DuplicateEvidenceError, EvidenceChainStore


def _sample_payload(idx: int = 1) -> dict:
    return {
        "claim": f"Policy rule {idx} enforced",
        "source_uri": f"https://example.com/spec/{idx}",
        "source_sha256": "a" * 64,
        "evidence_summary": f"Summary {idx}",
        "evidence_type": "automated_test",
        "rule_id": f"RULE-{idx}",
        "rule_version": "1.0.0",
        "test_results": [{"test": "test_pass", "passed": True}],
        "counterexamples": [],
    }


# ---------------------------------------------------------------------------
# 1. Empty store behavior
# ---------------------------------------------------------------------------


def test_empty_store_lists_empty_and_verifies_valid(tmp_path: Path) -> None:
    store = EvidenceChainStore(str(tmp_path / "empty_evidence.db"))

    assert store.list_records("acme") == []
    assert store.verify("acme") == {
        "chain_valid": True,
        "checked_records": 0,
        "broken_at_record": None,
    }


# ---------------------------------------------------------------------------
# 2. Tenant isolation, independent GENESIS chains, and limit clamping
# ---------------------------------------------------------------------------


def test_tenant_isolation_and_independent_chains(tmp_path: Path) -> None:
    store = EvidenceChainStore(str(tmp_path / "isolated.db"))

    a1 = store.add("acme", _sample_payload(1))
    b1 = store.add("beta", _sample_payload(2))
    a2 = store.add("acme", _sample_payload(3))

    assert a1["prev_hash"] == "GENESIS"
    assert b1["prev_hash"] == "GENESIS"
    assert a2["prev_hash"] == a1["entry_hash"]

    acme_records = store.list_records("acme", limit=10)
    beta_records = store.list_records("beta", limit=10)
    assert [r["evidence_id"] for r in acme_records] == [a2["evidence_id"], a1["evidence_id"]]
    assert [r["evidence_id"] for r in beta_records] == [b1["evidence_id"]]

    # Limit clamping: <= 0 clamps to 1
    assert len(store.list_records("acme", limit=0)) == 1

    assert store.verify("acme") == {
        "chain_valid": True,
        "checked_records": 2,
        "broken_at_record": None,
    }
    assert store.verify("beta") == {
        "chain_valid": True,
        "checked_records": 1,
        "broken_at_record": None,
    }


# ---------------------------------------------------------------------------
# 3. DuplicateEvidenceError (scoped per tenant)
# ---------------------------------------------------------------------------


def test_duplicate_evidence_id_raises_per_tenant(tmp_path: Path) -> None:
    store = EvidenceChainStore(str(tmp_path / "dupes.db"))

    store.add("acme", _sample_payload(1), evidence_id="ev-fixed-001")

    with pytest.raises(DuplicateEvidenceError):
        store.add("acme", _sample_payload(2), evidence_id="ev-fixed-001")

    # Different tenant can use the same evidence_id without collision
    other = store.add("beta", _sample_payload(2), evidence_id="ev-fixed-001")
    assert other["tenant_id"] == "beta"
    assert other["evidence_id"] == "ev-fixed-001"


# ---------------------------------------------------------------------------
# 4. Input validation: empty tenant_id & NaN/Infinity rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "   "])
def test_add_rejects_empty_tenant_id(tmp_path: Path, bad_tenant: str) -> None:
    store = EvidenceChainStore(str(tmp_path / "bad_tenant.db"))
    with pytest.raises(ValueError, match="tenant_id"):
        store.add(bad_tenant, _sample_payload(1))


@pytest.mark.parametrize("bad_float", [float("nan"), float("inf"), float("-inf")])
def test_add_rejects_non_finite_json_values(tmp_path: Path, bad_float: float) -> None:
    store = EvidenceChainStore(str(tmp_path / "nan.db"))
    payload = _sample_payload(1)
    payload["score"] = bad_float

    with pytest.raises(ValueError):
        store.add("acme", payload)


# ---------------------------------------------------------------------------
# 5. Tamper detection (payload mutation & prev_hash link break)
# ---------------------------------------------------------------------------


def test_verify_detects_payload_tampering(tmp_path: Path) -> None:
    db_path = tmp_path / "tamper_payload.db"
    store = EvidenceChainStore(str(db_path))

    store.add("acme", _sample_payload(1))
    r2 = store.add("acme", _sample_payload(2))
    store.add("acme", _sample_payload(3))

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE evidence_records SET payload_json = ? WHERE id = ?",
            ('{"tampered":true}', r2["record_number"]),
        )
        conn.commit()

    assert store.verify("acme") == {
        "chain_valid": False,
        "checked_records": 3,
        "broken_at_record": r2["record_number"],
    }


def test_verify_detects_broken_prev_hash_link(tmp_path: Path) -> None:
    db_path = tmp_path / "tamper_link.db"
    store = EvidenceChainStore(str(db_path))

    store.add("acme", _sample_payload(1))
    r2 = store.add("acme", _sample_payload(2))

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE evidence_records SET prev_hash = 'forged' WHERE id = ?",
            (r2["record_number"],),
        )
        conn.commit()

    assert store.verify("acme") == {
        "chain_valid": False,
        "checked_records": 2,
        "broken_at_record": r2["record_number"],
    }


# ---------------------------------------------------------------------------
# 6. Concurrent multi-threaded writes preserve per-tenant chains
# ---------------------------------------------------------------------------


def test_concurrent_writes_preserve_per_tenant_chains(tmp_path: Path) -> None:
    store = EvidenceChainStore(str(tmp_path / "concurrent_evidence.db"))
    total_writes = 24

    def _write(i: int) -> None:
        store.add(f"tenant-{i % 3}", _sample_payload(i))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_write, range(total_writes)))

    for idx in range(3):
        tenant_id = f"tenant-{idx}"
        assert store.verify(tenant_id) == {
            "chain_valid": True,
            "checked_records": total_writes // 3,
            "broken_at_record": None,
        }