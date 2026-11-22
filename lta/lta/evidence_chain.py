
"""Lucid Truth Audit — Evidence Chain Engine v1.0.

Creates reproducible, hash-linked evidence chains:
claim -> source data -> scoring rule -> test -> counterexample -> conclusion.

The engine does not determine objective truth. It records and verifies
the evidentiary basis for an auditor's finding.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


GENESIS_HASH = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    record_id: str
    record_type: str
    description: str
    source: str
    content: Any
    collected_at: str
    content_sha256: str

    @classmethod
    def create(
        cls,
        record_id: str,
        record_type: str,
        description: str,
        source: str,
        content: Any,
    ) -> "EvidenceRecord":
        digest = sha256(canonical_json(content))

        return cls(
            record_id=record_id,
            record_type=record_type,
            description=description,
            source=source,
            content=content,
            collected_at=utc_now(),
            content_sha256=digest,
        )

    def verify(self) -> bool:
        return self.content_sha256 == sha256(
            canonical_json(self.content)
        )


@dataclass(frozen=True)
class ScoringCriterion:
    name: str
    weight: float
    description: str


@dataclass(frozen=True)
class ScoringRule:
    rule_id: str
    version: str
    criteria: tuple[ScoringCriterion, ...]
    created_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.criteria:
            raise ValueError("At least one scoring criterion is required.")

        names = [c.name for c in self.criteria]

        if len(names) != len(set(names)):
            raise ValueError("Scoring criterion names must be unique.")

        if any(c.weight < 0 for c in self.criteria):
            raise ValueError("Scoring weights cannot be negative.")

        if abs(sum(c.weight for c in self.criteria) - 100) > 0.001:
            raise ValueError("Scoring weights must total 100.")


@dataclass
class ChainEvent:
    sequence: int
    event_type: str
    payload: dict[str, Any]
    timestamp: str
    previous_hash: str
    event_hash: str


class EvidenceChain:
    def __init__(
        self,
        chain_id: str,
        title: str,
    ):
        self.chain_id = chain_id
        self.title = title
        self.records: dict[str, EvidenceRecord] = {}
        self.events: list[ChainEvent] = []
        self.claim: Optional[dict] = None
        self.scoring_rule: Optional[ScoringRule] = None
        self.test: Optional[dict] = None
        self.counterexamples: list[dict] = []
        self.conclusion: Optional[dict] = None

    def _append(
        self,
        event_type: str,
        payload: dict[str, Any],
    ) -> ChainEvent:
        previous_hash = (
            self.events[-1].event_hash
            if self.events
            else GENESIS_HASH
        )

        sequence = len(self.events) + 1
        timestamp = utc_now()

        canonical = {
            "chain_id": self.chain_id,
            "sequence": sequence,
            "event_type": event_type,
            "payload": payload,
            "timestamp": timestamp,
            "previous_hash": previous_hash,
        }

        event_hash = sha256(canonical_json(canonical))

        event = ChainEvent(
            sequence=sequence,
            event_type=event_type,
            payload=payload,
            timestamp=timestamp,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

        self.events.append(event)
        return event

    def add_claim(
        self,
        claim_id: str,
        statement: str,
        scope: str,
        hypothesis_type: str = "evidentiary",
    ) -> ChainEvent:
        if self.claim is not None:
            raise ValueError("A claim already exists in this chain.")

        self.claim = {
            "claim_id": claim_id,
            "statement": statement,
            "scope": scope,
            "hypothesis_type": hypothesis_type,
        }

        return self._append("CLAIM", self.claim)

    def add_evidence(
        self,
        record: EvidenceRecord,
    ) -> ChainEvent:
        if record.record_id in self.records:
            raise ValueError("Duplicate evidence record ID.")

        if not record.verify():
            raise ValueError("Evidence content hash is invalid.")

        self.records[record.record_id] = record

        return self._append(
            "SOURCE_DATA",
            asdict(record),
        )

    def add_scoring_rule(
        self,
        rule: ScoringRule,
    ) -> ChainEvent:
        if self.scoring_rule is not None:
            raise ValueError("Scoring rule already established.")

        rule.validate()
        self.scoring_rule = rule

        payload = {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "created_at": rule.created_at,
            "criteria": [
                asdict(c) for c in rule.criteria
            ],
        }

        return self._append("SCORING_RULE", payload)

    def add_test(
        self,
        test_id: str,
        procedure: str,
        expected_result: str,
        observed_result: str,
        evidence_ids: list[str],
        passed: bool,
        model_metadata: Optional[dict] = None,
    ) -> ChainEvent:
        self._require_claim()
        self._require_evidence(evidence_ids)

        if self.test is not None:
            raise ValueError("A primary test already exists.")

        if self.scoring_rule is None:
            raise ValueError("Establish scoring rule before testing.")

        self.test = {
            "test_id": test_id,
            "procedure": procedure,
            "expected_result": expected_result,
            "observed_result": observed_result,
            "evidence_ids": evidence_ids,
            "passed": passed,
            "model_metadata": model_metadata or {},
        }

        return self._append("TEST", self.test)

    def add_counterexample(
        self,
        counterexample_id: str,
        description: str,
        evidence_ids: list[str],
        effect_on_claim: str,
    ) -> ChainEvent:
        self._require_evidence(evidence_ids)

        if self.test is None:
            raise ValueError("A primary test is required first.")

        counterexample = {
            "counterexample_id": counterexample_id,
            "description": description,
            "evidence_ids": evidence_ids,
            "effect_on_claim": effect_on_claim,
        }

        self.counterexamples.append(counterexample)

        return self._append(
            "COUNTEREXAMPLE",
            counterexample,
        )

    def calculate_score(
        self,
        criterion_scores: dict[str, float],
    ) -> dict[str, Any]:
        if self.scoring_rule is None:
            raise ValueError("No scoring rule established.")

        expected = {
            c.name for c in self.scoring_rule.criteria
        }

        if set(criterion_scores) != expected:
            raise ValueError(
                "Scores must include exactly the defined criteria."
            )

        for name, score in criterion_scores.items():
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not 0 <= score <= 100
            ):
                raise ValueError(
                    f"Invalid score for criterion: {name}"
                )

        weighted_score = sum(
            criterion_scores[c.name] * c.weight / 100
            for c in self.scoring_rule.criteria
        )

        return {
            "weighted_score": round(weighted_score, 2),
            "criterion_scores": criterion_scores,
            "rule_id": self.scoring_rule.rule_id,
            "rule_version": self.scoring_rule.version,
        }

    def add_conclusion(
        self,
        finding_id: str,
        statement: str,
        criterion_scores: dict[str, float],
        classification: str,
        limitations: list[str],
        confidence_basis: str,
    ) -> ChainEvent:
        if self.test is None:
            raise ValueError("A test is required before conclusion.")

        if self.conclusion is not None:
            raise ValueError("Conclusion already exists.")

        score = self.calculate_score(criterion_scores)

        self.conclusion = {
            "finding_id": finding_id,
            "statement": statement,
            "classification": classification,
            "score": score,
            "counterexample_count": len(self.counterexamples),
            "limitations": limitations,
            "confidence_basis": confidence_basis,
        }

        return self._append("CONCLUSION", self.conclusion)

    def _require_claim(self) -> None:
        if self.claim is None:
            raise ValueError("A claim must be established first.")

    def _require_evidence(self, evidence_ids: list[str]) -> None:
        if not evidence_ids:
            raise ValueError("At least one evidence reference is required.")

        missing = set(evidence_ids) - set(self.records)

        if missing:
            raise ValueError(
                f"Unknown evidence records: {sorted(missing)}"
            )

    def verify_chain(self) -> dict[str, Any]:
        expected_previous = GENESIS_HASH
        failures = []

        for event in self.events:
            canonical = {
                "chain_id": self.chain_id,
                "sequence": event.sequence,
                "event_type": event.event_type,
                "payload": event.payload,
                "timestamp": event.timestamp,
                "previous_hash": event.previous_hash,
            }

            calculated = sha256(canonical_json(canonical))

            if event.previous_hash != expected_previous:
                failures.append({
                    "sequence": event.sequence,
                    "reason": "Previous hash mismatch",
                })

            if calculated != event.event_hash:
                failures.append({
                    "sequence": event.sequence,
                    "reason": "Event hash mismatch",
                })

            expected_previous = event.event_hash

        invalid_records = [
            record_id
            for record_id, record in self.records.items()
            if not record.verify()
        ]

        return {
            "chain_id": self.chain_id,
            "valid": not failures and not invalid_records,
            "event_count": len(self.events),
            "evidence_count": len(self.records),
            "chain_head": (
                self.events[-1].event_hash
                if self.events else GENESIS_HASH
            ),
            "failures": failures,
            "invalid_evidence_records": invalid_records,
        }

    def export(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "chain_id": self.chain_id,
            "title": self.title,
            "claim": self.claim,
            "evidence": {
                key: asdict(value)
                for key, value in self.records.items()
            },
            "scoring_rule": (
                {
                    "rule_id": self.scoring_rule.rule_id,
                    "version": self.scoring_rule.version,
                    "criteria": [
                        asdict(c)
                        for c in self.scoring_rule.criteria
                    ],
                }
                if self.scoring_rule else None
            ),
            "test": self.test,
            "counterexamples": self.counterexamples,
            "conclusion": self.conclusion,
            "events": [
                asdict(event) for event in self.events
            ],
            "integrity": self.verify_chain(),
        }
