"""The anomaly model on the eval week (seed 42, variant 1), against a simple rule baseline.

    uv run --project backend python evals/ml_anomaly.py

Pools, over process_start and network_conn events only (the types the model scores):
- positives: key events of malicious scenarios;
- negatives: background events (no scenario emitted them);
- benign-scenario key events (s08-s11) are reported separately, as are per-scenario
  percentiles; non-key scenario events are in neither pool.

Both detectors get ROC-AUC and precision@50 (tie-aware: the rule score is 0/1, so a tie at
the cut-off counts at its expected precision rather than in arbitrary order), and their mean
score on the benign key events. Writes evals/results/anomaly_<date>.json; prints metrics only.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from collections.abc import Callable, Sequence  # noqa: E402
from typing import Any  # noqa: E402

import numpy as np  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

from app.ml import ModelMissingError, anomaly  # noqa: E402
from evals.common import (  # noqa: E402
    EVAL_SEED,
    EVAL_VARIANT,
    eval_week,
    scenario_event_ids,
    write_result,
)
from scripts.gen.dataset import Dataset  # noqa: E402

K = 50


def rule_score(features: dict[str, float]) -> float:
    """1 if the binary is unsigned, or its parent-child (or process-destination) pair never
    occurred anywhere in the baseline; else 0."""
    unsigned = features.get("unsigned") == 1.0
    fleet_count = features.get("parent_child_count_fleet", features.get("process_dest_count_fleet"))
    return float(unsigned or fleet_count == 0)


def precision_at_k(labels: Sequence[int], scores: Sequence[float], k: int = K) -> float:
    y = np.asarray(labels, dtype=float)
    s = np.asarray(scores, dtype=float)
    cut = np.sort(s)[::-1][k - 1]
    above, tied = s > cut, s == cut
    hits = y[above].sum() + (k - above.sum()) * y[tied].mean()
    return float(hits / k)


def detector_metrics(
    score: Callable[[anomaly.EventScore], float],
    positives: list[anomaly.EventScore],
    negatives: list[anomaly.EventScore],
    benign: list[anomaly.EventScore],
) -> dict[str, Any]:
    labels = [1] * len(positives) + [0] * len(negatives)
    scores = [score(s) for s in [*positives, *negatives]]
    benign_scores = [score(s) for s in benign]
    negative_scores = scores[len(positives) :]
    return {
        "roc_auc": round(float(roc_auc_score(labels, scores)), 4),
        f"precision_at_{K}": round(precision_at_k(labels, scores), 4),
        "benign_key_mean_score": round(float(np.mean(benign_scores)), 4),
        "benign_key_roc_auc_vs_background": round(
            float(
                roc_auc_score(
                    [1] * len(benign) + [0] * len(negatives), [*benign_scores, *negative_scores]
                )
            ),
            4,
        ),
    }


def evaluate(model: anomaly.AnomalyModel, ds: Dataset) -> dict[str, Any]:
    docs = [e.model_dump() for e in ds.events if e.event_type in anomaly.FEATURES]
    scored = {s.event_id: s for s in model.score_events(docs) if s is not None}
    in_scenarios = scenario_event_ids(ds)
    key = {
        r.scenario_id: [scored[e.event_id] for e in r.key_events if e.event_id in scored]
        for r in ds.scenarios
    }
    positives = [s for r in ds.scenarios if r.verdict == "malicious" for s in key[r.scenario_id]]
    benign = [s for r in ds.scenarios if r.verdict == "benign" for s in key[r.scenario_id]]
    negatives = [s for eid, s in scored.items() if eid not in in_scenarios]

    per_scenario = {}
    for r in ds.scenarios:
        pct = [100 * s.percentile for s in key[r.scenario_id]]
        per_scenario[r.scenario_id] = {
            "verdict": r.verdict,
            "scored_key_events": len(pct),
            "mean_percentile": round(float(np.mean(pct)), 1) if pct else None,
            "min_percentile": round(min(pct), 1) if pct else None,
        }
    return {
        "eval_seed": EVAL_SEED,
        "eval_variant": EVAL_VARIANT,
        "baseline_seed": model.baseline_seed,
        "counts": {
            "malicious_key_events": len(positives),
            "background_events": len(negatives),
            "benign_key_events": len(benign),
        },
        "isolation_forest": detector_metrics(lambda s: s.score, positives, negatives, benign),
        "rule_baseline": detector_metrics(
            lambda s: rule_score(s.features), positives, negatives, benign
        ),
        "per_scenario": per_scenario,
    }


def main() -> int:
    try:
        model = anomaly.load()
    except ModelMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    result = evaluate(model, eval_week())
    path = write_result("anomaly", result)

    print(f"eval week seed {EVAL_SEED} v{EVAL_VARIANT}, baseline seed {model.baseline_seed}")
    print(f"  {result['counts']}")
    for name in ("isolation_forest", "rule_baseline"):
        print(f"  {name:<17} {result[name]}")
    print("  per scenario (key-event baseline percentile, mean / min):")
    for sid, row in result["per_scenario"].items():
        n = row["scored_key_events"]
        stats = f"{row['mean_percentile']} / {row['min_percentile']}" if n else "no scored events"
        print(f"    {sid} {row['verdict']:<9} n={n:<3} {stats}")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
