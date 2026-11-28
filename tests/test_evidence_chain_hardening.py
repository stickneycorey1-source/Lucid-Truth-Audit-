"""Unit tests covering per-tenant evidence hash chain in app/evidence_chain.py."""

from __future__ import annotations

import inspect
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

import pytest

import app.evidence_chain as ev_mod


def _resolve_append_fn(store: Any) -> Callable[..., Any]:
    for attr in ("append_evidence", "append", "add_evidence", "create_evidence", "record_evidence", "record"):
        fn = getattr(store, attr, None)
        if callable(fn):
            return fn
    raise AttributeError("EvidenceChainStore has no recognized append method")


def _call_append(store: Any, *, tenant_id: str, evidence_id: str, evidence_type: str, payload: dict[str, Any]) -> Any:
    fn = _resolve_append_fn(store)
    params = inspect.signature(fn).parameters
    if "record" in params:
        return fn(
            tenant_id=tenant_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            record=payload,
        )
    if "data" in params:
        return fn(
            tenant_id=tenant_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            data=payload,
        )
    return fn(
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        payload=payload,
    )


def _call_list(store: Any, *, tenant_id: str, limit: int = 100) -> list[Any]:
    for attr in ("list_evidence", "list_records", "get_evidence", "records"):
        fn = getattr(store, attr, None)
        if callable(fn):
            return list(fn(tenant_id=tenant_id, limit=limit))
    raise AttributeError("EvidenceChainStore has no recognized list method")


def _call_verify(store: Any, *, tenant_id: str) -> tuple[bool, str]:
    for attr in ("verify_chain", "verify_tenant_chain", "verify"):
        fn = getattr(store, attr, None)
        if callable(fn):
            res = fn(tenant_id=tenant_id)
            if isinstance(res, tuple) and len(res) == 2:
                return bool(res[0]), str(res[1])
            if isinstance(res, bool):
                return res, ""
            if isinstance(res, dict):
                return bool(res.get("valid", False)), str(res.get("reason", ""))
    raise AttributeError("EvidenceChainStore has no recognized verify method")


@pytest.fixture
def chain_store(tmp_path: Path) -> ev_mod.EvidenceChainStore:
    return ev_mod.EvidenceChainStore(str(tmp_path / "evidence_chain_hardening.db"))


def test_evidence_append_list_and_verify_per_tenant(chain_store: ev_mod.EvidenceChainStore) -> None:
    rec1 = _call_append(
        chain_store,
        tenant_id="tenant_a",
        evidence_id="EV-001",
        evidence_type="hos_audit",
        payload={"driver": "driver_1", "drive_hours": 7.5},
    )
    rec2 = _call_append(
        chain_store,
        tenant_id="tenant_b",
        evidence_id="EV-001",
        evidence_type="hos_audit",
        payload={"driver": "driver_2", "drive_hours": 6.0},
    )
    assert rec1 != rec2

    rows_a = _call_list(chain_store, tenant_id="tenant_a", limit=10)
    assert len(rows_a) == 1

    ok_a, msg_a = _call_verify(chain_store, tenant_id="tenant_a")
    ok_b, msg_b = _call_verify(chain_store, tenant_id="tenant_b")
    assert ok_a is True, msg_a
    assert ok_b is True, msg_b


def test_evidence_duplicate_id_raises_conflict_error(chain_store: ev_mod.EvidenceChainStore) -> None:
    _call_append(
        chain_store,
        tenant_id="tenant_a",
        evidence_id="EV-DUP-1",
        evidence_type="pii_audit",
        payload={"redacted": ["SSN"]},
    )
    dup_exc = getattr(ev_mod, "DuplicateEvidenceError", ValueError)
    with pytest.raises((dup_exc, ValueError)):
        _call_append(
            chain_store,
            tenant_id="tenant_a",
            evidence_id="EV-DUP-1",
            evidence_type="pii_audit",
            payload={"redacted": ["SSN"]},
        )


@pytest.mark.parametrize("bad_val", [float("nan"), float("inf"), float("-inf")])
def test_evidence_rejects_non_finite_payload_numbers(
    chain_store: ev_mod.EvidenceChainStore, bad_val: float
) -> None:
    with pytest.raises((ValueError, TypeError)):
        _call_append(
            chain_store,
            tenant_id="tenant_a",
            evidence_id="EV-NAN",
            evidence_type="weight_check",
            payload={"weight_lbs": bad_val},
        )


def test_evidence_detects_tampering_and_supports_concurrent_writes(
    chain_store: ev_mod.EvidenceChainStore, tmp_path: Path
) -> None:
    db_path = tmp_path / "evidence_chain_hardening.db"

    def _worker(idx: int) -> None:
        _call_append(
            chain_store,
            tenant_id="tenant_conc",
            evidence_id=f"EV-CONC-{idx:03d}",
            evidence_type="telemetry",
            payload={"seq": idx},
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(_worker, range(15)))

    ok_before, _ = _call_verify(chain_store, tenant_id="tenant_conc")
    assert ok_before is True

    conn = sqlite3.connect(str(db_path))
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for tbl in tables:
            cols = [row[1] for row in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
            if "entry_hash" in cols:
                conn.execute(f"UPDATE {tbl} SET entry_hash = ?", ("f" * 64,))
                conn.commit()
                break
    finally:
        conn.close()

    ok_after, _ = _call_verify(chain_store, tenant_id="tenant_conc")
    assert ok_after is False