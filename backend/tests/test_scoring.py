"""The risk formula: pure, so these are exact."""

import pytest

from app.agent.scoring import risk_score


@pytest.mark.parametrize(
    ("verdict", "confidence", "priority", "criticality", "tactics", "expected"),
    [
        ("malicious", 0.9, "P2", 3, ["Execution"], 73),
        ("malicious", 0.9, "P1", 4, ["Credential Access", "Exfiltration"], 97),
        ("suspicious", 0.5, "P3", 3, [], 37),
        ("benign", 0.9, "P3", 3, [], 16),
    ],
)
def test_worked_examples(
    verdict: str,
    confidence: float,
    priority: str,
    criticality: int,
    tactics: list[str],
    expected: int,
) -> None:
    assert risk_score(verdict, confidence, priority, criticality, tactics)["score"] == expected


def test_parts_add_up_and_are_reported() -> None:
    parts = risk_score("malicious", 1.0, "P1", 5, ["Impact"])

    assert parts["verdict_points"] == 60
    assert parts["priority_points"] == 15
    assert parts["criticality_points"] == 12
    assert parts["tactic_points"] == 8
    assert parts["high_impact_tactics"] == ["Impact"]
    assert parts["score"] == 95
    assert "verdict base" in str(parts["formula"])


def test_score_never_exceeds_100() -> None:
    tactics = ["Credential Access", "Exfiltration", "Impact", "Lateral Movement"]

    assert risk_score("malicious", 1.0, "P1", 5, tactics)["score"] == 100


def test_tactic_points_are_capped_and_counted_once() -> None:
    tactics = ["Impact", "Impact", "Exfiltration", "Lateral Movement"]

    parts = risk_score("suspicious", 0.5, "P4", 1, tactics)

    assert parts["tactic_points"] == 16 and len(parts["high_impact_tactics"]) == 3


def test_benign_is_capped_at_20_even_on_a_critical_asset() -> None:
    tactics = ["Credential Access", "Impact"]

    assert risk_score("benign", 1.0, "P1", 5, tactics)["score"] == 20


def test_missing_criticality_counts_as_3_and_is_flagged() -> None:
    parts = risk_score("suspicious", 0.5, "P3", None, [])

    assert parts["criticality"] == 3 and parts["criticality_assumed"] is True
    assert parts["criticality_points"] == 6


def test_confidence_is_clamped() -> None:
    assert risk_score("malicious", 7.0, "P4", 1, [])["score"] == 60
    assert risk_score("malicious", -1.0, "P4", 1, [])["score"] == 30


def test_more_confidence_never_lowers_the_score() -> None:
    scores = [risk_score("malicious", c / 10, "P2", 3, [])["score"] for c in range(11)]

    assert scores == sorted(scores)
