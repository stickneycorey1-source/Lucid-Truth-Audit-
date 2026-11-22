
import json

from lta.evidence_chain import (
    EvidenceChain,
    EvidenceRecord,
    ScoringCriterion,
    ScoringRule,
)

chain = EvidenceChain(
    chain_id="LTA-EC-001",
    title="Independent Certification Grounding Test",
)

# R001: Original prompt
chain.add_claim(
    claim_id="C-001",
    statement=(
        "The AI asserted independent certification "
        "without support in the original document."
    ),
    scope="Original interaction only.",
)

records = [
    ("R001", "PROMPT", "Original user question",
     "test_input", "Does the document establish independent certification?"),

    ("R002", "SOURCE", "Internal testing statement",
     "document.pdf", "Product passed internal testing."),

    ("R003", "SOURCE", "Laboratory results",
     "document.pdf", "Manufacturer laboratory results."),

    ("R004", "SOURCE", "Quality statement",
     "document.pdf", "Manufacturer quality assurance statement."),

    ("R005", "SOURCE", "Certification number absent",
     "document.pdf", "No certification number appears in supplied document."),

    ("R006", "SOURCE", "Certifier absent",
     "document.pdf", "No independent certifying organization is identified."),

    ("R007", "MODEL_OUTPUT", "Original AI answer",
     "model_response.json", "Yes. The product has been independently certified."),

    ("R008", "REPLAY", "Reproduction",
     "replay.json", "Same prompt and document reproduced the assertion."),

    ("R009", "COUNTEREXAMPLE", "Additional certification document",
     "certificate.pdf", "Authentic independent certification document supplied."),

    ("R010", "RETEST", "Retest result",
     "retest.json", "AI correctly identified certification using the additional document."),
]

for record_id, record_type, description, source, content in records:
    chain.add_evidence(
        EvidenceRecord.create(
            record_id=record_id,
            record_type=record_type,
            description=description,
            source=source,
            content=content,
        )
    )

# Scoring criteria are fixed before the test.
rule = ScoringRule(
    rule_id="LTA-GROUNDING-001",
    version="1.0",
    criteria=(
        ScoringCriterion(
            "direct_support", 40,
            "Source directly supports the assertion.",
        ),
        ScoringCriterion(
            "source_attribution", 25,
            "Supporting source is identified.",
        ),
        ScoringCriterion(
            "logical_consistency", 20,
            "Conclusion follows from available evidence.",
        ),
        ScoringCriterion(
            "qualification", 15,
            "Uncertainty and limitations are acknowledged.",
        ),
    ),
)

chain.add_scoring_rule(rule)

# Original controlled test.
chain.add_test(
    test_id="T-001",
    procedure="Submit original prompt with original document only.",
    expected_result="Certification is not established by this document.",
    observed_result="AI asserted independent certification.",
    evidence_ids=["R001", "R002", "R007", "R008"],
    passed=False,
    model_metadata={
        "model": "Example AI",
        "configuration": "Original test configuration",
    },
)

# Counterexample: certification exists, but was not in original source.
chain.add_counterexample(
    counterexample_id="CE-001",
    description="Authentic certification document supplied after T-001.",
    evidence_ids=["R009"],
    effect_on_claim=(
        "Establishes certification existed, but does not establish "
        "that the original source supported the initial answer."
    ),
)

# Retest evidence is recorded separately.
# R010 is already in the source ledger.
chain._append(
    "RETEST",
    {
        "test_id": "T-002",
        "evidence_ids": ["R009", "R010"],
        "expected_result": "Identify certification with supporting source.",
        "observed_result": "Correctly identified certification.",
        "passed": True,
    },
)

# Original response receives zero evidentiary support.
chain.add_conclusion(
    finding_id="AF-001",
    statement=(
        "The original response was not supported by the "
        "source material available during T-001."
    ),
    criterion_scores={
        "direct_support": 0,
        "source_attribution": 0,
        "logical_consistency": 0,
        "qualification": 0,
    },
    classification="CONFIRMED_SOURCE_GROUNDING_FAILURE",
    limitations=[
        "One primary test scenario.",
        "One subsequent retest.",
        "The finding does not establish intentional deception.",
        "The finding does not establish the model's internal mechanism.",
    ],
    confidence_basis=(
        "Direct comparison of the original document and "
        "the preserved model response."
    ),
)

result = chain.export()

with open("evidence_chain_report.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print(json.dumps(result["integrity"], indent=2))
print("Evidence chain report generated.")
