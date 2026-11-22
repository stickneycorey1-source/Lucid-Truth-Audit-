
import pytest

from lta.evidence_chain import (
    EvidenceChain,
    EvidenceRecord,
    ScoringCriterion,
    ScoringRule,
)


def make_rule():
    return ScoringRule(
        rule_id="TEST-001",
        version="1.0",
        criteria=(
            ScoringCriterion("support", 40, "Direct support"),
            ScoringCriterion("attribution", 25, "Source attribution"),
            ScoringCriterion("logic", 20, "Logical consistency"),
            ScoringCriterion("qualification", 15, "Uncertainty"),
        ),
    )


def make_chain():
    chain = EvidenceChain("TEST-CHAIN", "Unit test")

    chain.add_claim(
        "C-001",
        "Test claim",
        "Test scope",
    )

    record = EvidenceRecord.create(
        "R001",
        "SOURCE",
        "Test evidence",
        "test.json",
        {"finding": "sample"},
    )

    chain.add_evidence(record)
    chain.add_scoring_rule(make_rule())

    chain.add_test(
        "T-001",
        "Run test",
        "Expected result",
        "Observed result",
        ["R001"],
        False,
    )

    return chain


def test_valid_chain():
    chain = make_chain()
    assert chain.verify_chain()["valid"] is True


def test_source_hash_detects_tampering():
    record = EvidenceRecord.create(
        "R001", "SOURCE", "Test", "test.json",
        {"value": "original"},
    )

    assert record.verify()

    object.__setattr__(record, "content", {"value": "changed"})

    assert not record.verify()


def test_event_tampering_detected():
    chain = make_chain()

    chain.events[0].payload["statement"] = "Altered claim"

    assert chain.verify_chain()["valid"] is False


def test_missing_evidence_rejected():
    chain = make_chain()

    with pytest.raises(ValueError):
        chain.add_counterexample(
            "CE-001",
            "Missing evidence",
            ["UNKNOWN"],
            "Challenges claim",
        )


def test_invalid_scoring_weights_rejected():
    rule = ScoringRule(
        "BAD-001",
        "1.0",
        (
            ScoringCriterion("A", 50, "A"),
            ScoringCriterion("B", 30, "B"),
        ),
    )

    with pytest.raises(ValueError):
        rule.validate()


def test_weighted_scoring():
    chain = make_chain()

    result = chain.calculate_score({
        "support": 100,
        "attribution": 80,
        "logic": 60,
        "qualification": 40,
    })

    assert result["weighted_score"] == 76.0


def test_invalid_score_rejected():
    chain = make_chain()

    with pytest.raises(ValueError):
        chain.calculate_score({
            "support": 120,
            "attribution": 80,
            "logic": 60,
            "qualification": 40,
        })


def test_duplicate_claim_rejected():
    chain = make_chain()

    with pytest.raises(ValueError):
        chain.add_claim("C-002", "Second claim", "Scope")


def test_duplicate_evidence_rejected():
    chain = make_chain()

    with pytest.raises(ValueError):
        chain.add_evidence(
            EvidenceRecord.create(
                "R001", "SOURCE", "Duplicate",
                "test.json", {"value": 2},
            )
        )


def test_conclusion_requires_test():
    chain = EvidenceChain("EMPTY", "Empty chain")

    with pytest.raises(ValueError):
        chain.add_conclusion(
            "AF-001",
            "Conclusion",
            {},
            "UNSUPPORTED",
            [],
            "Test",
        )
