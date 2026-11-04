"""The trained models: deterministic training, anomaly scores and explanations, the anomaly
eval, and the injection classifier on s12 and on background command lines.

Both models are trained in memory (conftest) on the seed-7 baseline week; the classifier also
on the dataset's train split. s12's text is never put inside an assert expression, so a
failure can't print it.
"""

from collections import Counter
from datetime import UTC, datetime
from typing import Any

import numpy as np
import pytest

from app.ml import anomaly, injection
from evals.ml_anomaly import evaluate as evaluate_anomaly
from evals.ml_anomaly import precision_at_k, rule_score
from evals.ml_injection import EvalTexts, full_eval_texts, limited_eval_texts, trigger_texts
from evals.ml_injection import evaluate as evaluate_injection
from scripts.gen.dataset import Dataset
from scripts.train import injection_training_data
from tests.conftest import BASELINE_SEED, baseline_docs, baseline_week


def process_doc(**process: Any) -> dict[str, Any]:
    return {
        "event_id": "evt_000001",
        "event_type": "process_start",
        "host": "FIN-WS-01",
        "ts": datetime(2026, 10, 6, 3, tzinfo=UTC),
        "process": {"pid": 9, "ppid": 8, "sha256": "0" * 64} | process,
    }


# --- anomaly model -----------------------------------------------------------------------


def test_anomaly_training_is_deterministic(
    anomaly_model: anomaly.AnomalyModel, datasets: dict[int, Dataset]
) -> None:
    again = anomaly.train(baseline_docs(), BASELINE_SEED)
    docs = [e.model_dump() for e in datasets[1].events if e.event_type in anomaly.FEATURES]

    first = [s.score for s in anomaly_model.score_events(docs) if s]
    second = [s.score for s in again.score_events(docs) if s]

    assert first == second


def test_unseen_unsigned_temp_binary_stands_out(anomaly_model: anomaly.AnomalyModel) -> None:
    doc = process_doc(
        name="payload.exe",
        parent_name="WINWORD.EXE",
        cmdline=r"C:\Users\a.b\AppData\Local\Temp\payload.exe /quiet",
        signer=None,
    )

    (score,) = anomaly_model.score_events([doc])

    assert score is not None and 0 < score.score < 1
    assert score.percentile > 0.99
    assert score.features["parent_child_count_fleet"] == 0
    assert len(score.stood_out) == anomaly.TOP_FEATURES
    assert all(s.baseline_share < 0.01 for s in score.stood_out)


def test_common_signed_process_is_unremarkable(anomaly_model: anomaly.AnomalyModel) -> None:
    doc = process_doc(
        name="chrome.exe",
        parent_name="explorer.exe",
        cmdline=r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
        signer="Google LLC",
    ) | {"ts": datetime(2026, 10, 6, 9, tzinfo=UTC)}

    (score,) = anomaly_model.score_events([doc])

    assert score is not None and score.percentile < 0.9


def test_unscored_event_types_get_none(anomaly_model: anomaly.AnomalyModel) -> None:
    logon = {"event_id": "evt_000002", "event_type": "logon", "host": "DC-01"}

    assert anomaly_model.score_events([logon]) == [None]


def test_tail_share_is_the_smaller_tail() -> None:
    column = np.array([[0.0], [1.0], [2.0], [3.0]])

    shares = anomaly.tail_shares(column, np.array([[3.0], [1.0], [9.0]]))

    assert shares.ravel().tolist() == [0.25, 0.5, 0.0]


def test_precision_at_k_counts_ties_at_expected_value() -> None:
    assert precision_at_k([1, 0, 1, 0], [1, 1, 1, 0], k=2) == pytest.approx(2 / 3)


def test_rule_baseline_fires_on_unsigned_or_unseen_pairs() -> None:
    assert rule_score({"unsigned": 1.0, "parent_child_count_fleet": 40}) == 1.0
    assert rule_score({"unsigned": 0.0, "parent_child_count_fleet": 0}) == 1.0
    assert rule_score({"process_dest_count_fleet": 0, "new_destination": 1.0}) == 1.0
    assert rule_score({"unsigned": 0.0, "parent_child_count_fleet": 3}) == 0.0


def test_anomaly_roc_auc_above_0_8(
    anomaly_model: anomaly.AnomalyModel, datasets: dict[int, Dataset]
) -> None:
    result = evaluate_anomaly(anomaly_model, datasets[1])

    assert result["counts"]["malicious_key_events"] > 0
    assert result["isolation_forest"]["roc_auc"] > 0.8


# --- injection classifier ----------------------------------------------------------------


def test_injection_training_is_deterministic(injection_model: injection.InjectionModel) -> None:
    again = injection.train(*injection_training_data(baseline_week()))

    assert again.threshold == injection_model.threshold
    assert np.array_equal(again.pipeline[-1].coef_, injection_model.pipeline[-1].coef_)


def test_threshold_maximises_f1() -> None:
    labels = np.array([0, 0, 1, 1])

    assert injection.best_f1_threshold(labels, np.array([0.1, 0.4, 0.35, 0.8])) == 0.35


def test_classifier_flags_s12_trigger(
    injection_model: injection.InjectionModel, datasets: dict[int, Dataset]
) -> None:
    triggers = trigger_texts(datasets[1])
    flagged = all(any(injection_model.flag(t) for t in texts) for texts in triggers)

    assert len(triggers) > 0
    assert flagged, "s12 trigger not flagged"


@pytest.fixture(scope="module")
def injection_eval(
    injection_model: injection.InjectionModel, datasets: dict[int, Dataset]
) -> dict[str, Any]:
    def flags(texts: list[str]) -> list[bool]:
        return list(injection_model.scores(texts) >= injection_model.threshold)

    return evaluate_injection(flags, full_eval_texts(datasets[1]))


def test_classifier_false_positive_rate_on_background(injection_eval: dict[str, Any]) -> None:
    assert injection_eval["background_texts"] > 1000
    assert injection_eval["background_false_positive_rate"] < 0.02


def test_injection_eval_reports_s12_as_boolean(injection_eval: dict[str, Any]) -> None:
    assert isinstance(injection_eval["s12_trigger_flagged"], bool)


def test_limited_texts_respect_limit() -> None:
    data = EvalTexts(
        test_texts=[f"q{i}" for i in range(116)],
        test_labels=[i % 2 for i in range(116)],
        background=Counter({f"cmd{i}": 1 for i in range(500)}),
        triggers=[["a", "b"]],
    )

    limited = limited_eval_texts(data, 300)

    sent = len(limited.test_texts) + len(limited.background) + sum(map(len, limited.triggers))
    assert sent == 300 and len(limited.test_texts) == 116 and len(limited.background) == 182
    assert len(limited_eval_texts(data, 1000).background) == 200
