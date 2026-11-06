"""The risk score: a pure function, so it can be tested and printed in the report.

    risk = verdict base x (0.5 + 0.5 x confidence)    malicious 60, suspicious 35, benign 5
         + priority points                            P1 15, P2 10, P3 5, P4 0
         + (asset criticality - 1) x 3                criticality 1-5; missing counts as 3
         + 8 per high-impact tactic, at most 16       Credential Access, Exfiltration, Impact,
                                                      Lateral Movement
    clamped to 0-100, and at most 20 for a benign verdict.

The verdict dominates, and confidence can only scale it down. Priority, the asset and the tactics
move a case up within its verdict. The benign cap means a benign case on a critical server can
never outrank a suspicious one on the same asset.
"""

from collections.abc import Iterable

VERDICT_BASE = {"malicious": 60.0, "suspicious": 35.0, "benign": 5.0}
PRIORITY_POINTS = {"P1": 15, "P2": 10, "P3": 5, "P4": 0}
HIGH_IMPACT_TACTICS = frozenset({"Credential Access", "Exfiltration", "Impact", "Lateral Movement"})
TACTIC_POINTS = 8
MAX_TACTIC_POINTS = 16
BENIGN_CAP = 20
DEFAULT_CRITICALITY = 3
FORMULA = (
    "verdict base x (0.5 + 0.5 x confidence) + priority points + (criticality - 1) x 3 "
    "+ 8 per high-impact tactic (at most 16), clamped to 0-100, at most 20 if benign"
)


def risk_score(
    verdict: str,
    confidence: float,
    priority: str,
    criticality: int | None,
    tactics: Iterable[str],
) -> dict[str, object]:
    """The score and every part of it, for the report's formula breakdown."""
    confidence = min(max(confidence, 0.0), 1.0)
    verdict_points = VERDICT_BASE[verdict] * (0.5 + 0.5 * confidence)
    priority_points = PRIORITY_POINTS[priority]
    used_criticality = DEFAULT_CRITICALITY if criticality is None else criticality
    criticality_points = (used_criticality - 1) * 3
    high_impact = sorted(set(tactics) & HIGH_IMPACT_TACTICS)
    tactic_points = min(len(high_impact) * TACTIC_POINTS, MAX_TACTIC_POINTS)
    total = verdict_points + priority_points + criticality_points + tactic_points
    capped = min(total, BENIGN_CAP) if verdict == "benign" else total
    return {
        "score": round(min(max(capped, 0), 100)),
        "verdict": verdict,
        "confidence": confidence,
        "verdict_points": round(verdict_points, 1),
        "priority": priority,
        "priority_points": priority_points,
        "criticality": used_criticality,
        "criticality_assumed": criticality is None,
        "criticality_points": criticality_points,
        "high_impact_tactics": high_impact,
        "tactic_points": tactic_points,
        "formula": FORMULA,
    }
