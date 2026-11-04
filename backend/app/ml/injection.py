"""Prompt-injection classifier: TF-IDF features + logistic regression.

Three feature sets were pre-registered as candidates: character 2-5-grams (robust to text
glued into command lines, odd casing, German), word 1-3-grams (phrases like "ignore previous"
as units), and a FeatureUnion of both. `train` picks one by 5-fold CV F1 on the training data
alone; ties go to the earlier candidate. The CV scores are kept in the model, so the choice
can be shown and explained. Only n-grams seen in training get weight, so the base64 and paths
around an injected sentence add nothing and don't dilute it.

The threshold is chosen on the train split only: 5-fold out-of-fold probabilities, then the
cut-off with the best F1 (the highest one on ties, to keep false positives down). In-sample
probabilities would be overconfident and give a threshold that means nothing on new text.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_val_score
from sklearn.pipeline import FeatureUnion, Pipeline, make_pipeline

from app.ml import MODELS_DIR, ModelMissingError

ARTIFACT = MODELS_DIR / "injection.joblib"
RANDOM_STATE = 0
FOLDS = 5

Features = Literal["char", "word", "char+word"]
# Pre-registered order: on an exact CV tie the earlier (simpler) candidate wins.
CANDIDATES: tuple[Features, ...] = ("char", "word", "char+word")


def _char() -> TfidfVectorizer:
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)


def _word() -> TfidfVectorizer:
    return TfidfVectorizer(analyzer="word", ngram_range=(1, 3), min_df=2, sublinear_tf=True)


def make_classifier(features: Features) -> Pipeline:
    vectorizer: TfidfVectorizer | FeatureUnion
    if features == "char":
        vectorizer = _char()
    elif features == "word":
        vectorizer = _word()
    else:
        vectorizer = FeatureUnion([("char", _char()), ("word", _word())])
    return make_pipeline(vectorizer, LogisticRegression(max_iter=2000, random_state=RANDOM_STATE))


def choose_features(cv_f1: dict[Features, float]) -> Features:
    best = max(cv_f1.values())
    return next(f for f in CANDIDATES if cv_f1[f] == best)


def best_f1_threshold(labels: np.ndarray, probabilities: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(labels, probabilities)
    # The last precision/recall pair has no threshold; drop it.
    p, r = precision[:-1], recall[:-1]
    f1 = np.divide(2 * p * r, p + r, out=np.zeros_like(p), where=(p + r) > 0)
    best = np.flatnonzero(f1 == f1.max())[-1]
    return float(thresholds[best])


@dataclass
class InjectionModel:
    pipeline: Pipeline
    threshold: float
    features: Features
    cv_f1: dict[Features, float] = field(default_factory=dict)

    def scores(self, texts: Sequence[str]) -> np.ndarray:
        return self.pipeline.predict_proba(list(texts))[:, 1]

    def score(self, text: str) -> float:
        return float(self.scores([text])[0])

    def flag(self, text: str) -> bool:
        return self.score(text) >= self.threshold


def train(texts: Sequence[str], labels: Sequence[int]) -> InjectionModel:
    x, y = list(texts), np.asarray(labels)
    folds = StratifiedKFold(n_splits=FOLDS, shuffle=True, random_state=RANDOM_STATE)
    cv_f1: dict[Features, float] = {
        f: float(cross_val_score(make_classifier(f), x, y, cv=folds, scoring="f1").mean())
        for f in CANDIDATES
    }
    features = choose_features(cv_f1)
    out_of_fold = cross_val_predict(
        make_classifier(features), x, y, cv=folds, method="predict_proba"
    )[:, 1]
    pipeline = make_classifier(features).fit(x, y)
    return InjectionModel(pipeline, best_f1_threshold(y, out_of_fold), features, cv_f1)


def save(model: InjectionModel, path: Path = ARTIFACT) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


@cache
def load(path: Path = ARTIFACT) -> InjectionModel:
    # A joblib file is a pickle, and loading one runs code: only the locally built artifact.
    if not path.exists():
        raise ModelMissingError("injection classifier not trained; run `python tasks.py train`")
    return joblib.load(path)


def injection_score(text: str) -> float:
    """Probability (0-1) that `text` is a prompt-injection attempt."""
    return load().score(text)


def flag(text: str) -> bool:
    return load().flag(text)
