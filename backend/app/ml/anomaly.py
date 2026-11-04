"""How unusual a process start or network connection is, compared with a baseline week.

Features, as readable raw values:
- process_start: how often this parent->child pair ran in the baseline on this host and
  fleet-wide, unsigned binary, AppData or Temp path in the command line, -EncodedCommand,
  command-line length and Shannon entropy (of the full command line, before any cap), hour.
- network_conn: how often this process->destination pair was seen on this host and
  fleet-wide, destination new to the baseline, bytes_out/bytes_in ratio, bytes_out, hour.

One IsolationForest per event type, because the two feature sets differ. The score is the
original paper's anomaly score 2^(-E[h(x)]/c(n)), which sklearn's score_samples returns
negated: 0-1, higher = more unusual. Both forests use the same max_samples, so c(n) and
therefore the scale is shared and one ranking can mix both event types.

"Stood out" is a deliberately simple explanation, not SHAP: the features whose value is
rarest in the baseline. baseline_share is the share of baseline events of the same type with
a value at least as extreme (the smaller tail).

Baseline events are featurised leave-one-out (their own occurrence removed from the counts).
Otherwise every training pair would have count >= 1 and every destination would be "seen":
an IsolationForest treats out-of-range values like the most extreme training value and never
splits on a constant feature, so it could not learn what "never seen" looks like.
"""

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.ml import MODELS_DIR, ModelMissingError
from app.telemetry.decode import decode_encoded_command

ARTIFACT = MODELS_DIR / "anomaly.joblib"
RANDOM_STATE = 0
N_ESTIMATORS = 200
MAX_SAMPLES = 256
TOP_FEATURES = 3

FEATURES: dict[str, tuple[str, ...]] = {
    "process_start": (
        "parent_child_count_host",
        "parent_child_count_fleet",
        "unsigned",
        "temp_path",
        "encoded",
        "cmdline_length",
        "cmdline_entropy",
        "hour",
    ),
    "network_conn": (
        "process_dest_count_host",
        "process_dest_count_fleet",
        "new_destination",
        "bytes_out_in_ratio",
        "bytes_out",
        "hour",
    ),
}
# IsolationForest draws split points uniformly between a feature's min and max, so heavy-tailed
# features go on a log scale; on a raw scale almost every split would land among a few huge
# values.
LOG1P = {
    "parent_child_count_host",
    "parent_child_count_fleet",
    "process_dest_count_host",
    "process_dest_count_fleet",
    "cmdline_length",
    "bytes_out",
}
LOG10 = {"bytes_out_in_ratio"}
TEMP_PATH = re.compile(r"\\(?:appdata|temp)\\", re.IGNORECASE)

Doc = Mapping[str, Any]


def shannon_entropy(text: str) -> float:
    """Bits per character. Base64 and random names score high, plain commands low."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def pair_key(doc: Doc) -> str:
    p = doc["process"]
    if doc["event_type"] == "process_start":
        return f"{(p.get('parent_name') or '').lower()}>{p['name'].lower()}"
    return f"{p['name'].lower()}>{doc['network']['dst_ip']}"


@dataclass
class Baseline:
    """Counts from the baseline week; they ship inside the artifact."""

    fleet_pairs: Counter[str]
    host_pairs: Counter[str]
    destinations: Counter[str]

    @classmethod
    def from_events(cls, docs: Iterable[Doc]) -> "Baseline":
        fleet: Counter[str] = Counter()
        host: Counter[str] = Counter()
        destinations: Counter[str] = Counter()
        for doc in docs:
            pair = pair_key(doc)
            fleet[pair] += 1
            host[f"{doc['host']}|{pair}"] += 1
            if doc["event_type"] == "network_conn":
                destinations[doc["network"]["dst_ip"]] += 1
        return cls(fleet, host, destinations)


def raw_features(doc: Doc, baseline: Baseline, *, leave_one_out: bool = False) -> list[float]:
    """Feature values in FEATURES order for one process_start or network_conn."""
    own = 1 if leave_one_out else 0
    pair = pair_key(doc)
    host_count = baseline.host_pairs[f"{doc['host']}|{pair}"] - own
    fleet_count = baseline.fleet_pairs[pair] - own
    hour = doc["ts"].hour
    if doc["event_type"] == "process_start":
        p = doc["process"]
        cmdline = p.get("cmdline") or ""
        return [
            host_count,
            fleet_count,
            float(p.get("signer") is None),
            float(TEMP_PATH.search(cmdline) is not None),
            float(decode_encoded_command(cmdline) is not None),
            len(cmdline),
            shannon_entropy(cmdline),
            hour,
        ]
    n = doc["network"]
    new_destination = baseline.destinations[n["dst_ip"]] - own == 0
    return [
        host_count,
        fleet_count,
        float(new_destination),
        (n["bytes_out"] + 1) / (n["bytes_in"] + 1),
        n["bytes_out"],
        hour,
    ]


def model_input(event_type: str, raw: np.ndarray) -> np.ndarray:
    x = raw.copy()
    for j, name in enumerate(FEATURES[event_type]):
        if name in LOG1P:
            x[:, j] = np.log1p(x[:, j])
        elif name in LOG10:
            x[:, j] = np.log10(x[:, j])
    return x


def tail_shares(sorted_columns: np.ndarray, raw: np.ndarray) -> np.ndarray:
    """Per value, the share of baseline values at least as extreme (the smaller tail)."""
    n = sorted_columns.shape[0]
    shares = np.empty_like(raw)
    for j in range(raw.shape[1]):
        column = sorted_columns[:, j]
        at_most = np.searchsorted(column, raw[:, j], side="right") / n
        at_least = (n - np.searchsorted(column, raw[:, j], side="left")) / n
        shares[:, j] = np.minimum(at_most, at_least)
    return shares


@dataclass(frozen=True)
class StoodOut:
    feature: str
    value: float
    baseline_share: float


@dataclass(frozen=True)
class EventScore:
    event_id: str
    event_type: str
    score: float
    # Share of baseline events of the same type that scored lower, 0-1.
    percentile: float
    features: dict[str, float]
    stood_out: list[StoodOut]


@dataclass
class TypeModel:
    forest: IsolationForest
    sorted_columns: np.ndarray
    sorted_scores: np.ndarray


@dataclass
class AnomalyModel:
    baseline: Baseline
    models: dict[str, TypeModel]
    baseline_seed: int

    def score_events(self, docs: Sequence[Doc]) -> list[EventScore | None]:
        """Scores in input order; None for event types the model doesn't cover."""
        out: list[EventScore | None] = [None] * len(docs)
        by_type: dict[str, list[int]] = defaultdict(list)
        for i, doc in enumerate(docs):
            if doc["event_type"] in self.models:
                by_type[doc["event_type"]].append(i)
        for event_type, indexes in by_type.items():
            tm = self.models[event_type]
            raw = np.array([raw_features(docs[i], self.baseline) for i in indexes], dtype=float)
            scores = -tm.forest.score_samples(model_input(event_type, raw))
            below = np.searchsorted(tm.sorted_scores, scores, side="left")
            percentiles = below / len(tm.sorted_scores)
            shares = tail_shares(tm.sorted_columns, raw)
            names = FEATURES[event_type]
            for row, i in enumerate(indexes):
                top = np.argsort(shares[row], kind="stable")[:TOP_FEATURES]
                out[i] = EventScore(
                    event_id=docs[i]["event_id"],
                    event_type=event_type,
                    score=float(scores[row]),
                    percentile=float(percentiles[row]),
                    features=dict(zip(names, raw[row].tolist(), strict=True)),
                    stood_out=[
                        StoodOut(names[j], float(raw[row, j]), float(shares[row, j])) for j in top
                    ],
                )
        return out


def train(docs: Iterable[Doc], baseline_seed: int) -> AnomalyModel:
    """Fit on a baseline week. Deterministic: fixed random_state, single-threaded, and rows
    in the order given (the generator's time order)."""
    rows = [d for d in docs if d["event_type"] in FEATURES]
    baseline = Baseline.from_events(rows)
    models = {}
    for event_type in FEATURES:
        raw = np.array(
            [
                raw_features(d, baseline, leave_one_out=True)
                for d in rows
                if d["event_type"] == event_type
            ],
            dtype=float,
        )
        x = model_input(event_type, raw)
        forest = IsolationForest(
            n_estimators=N_ESTIMATORS, max_samples=MAX_SAMPLES, random_state=RANDOM_STATE
        ).fit(x)
        models[event_type] = TypeModel(
            forest=forest,
            sorted_columns=np.sort(raw, axis=0),
            sorted_scores=np.sort(-forest.score_samples(x)),
        )
    return AnomalyModel(baseline, models, baseline_seed)


def save(model: AnomalyModel, path: Path = ARTIFACT) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


@cache
def load(path: Path = ARTIFACT) -> AnomalyModel:
    # A joblib file is a pickle, and loading one runs code. Only ever load the artifact that
    # `python tasks.py train` built locally from a fixed path, never a downloaded one.
    if not path.exists():
        raise ModelMissingError("anomaly model not trained; run `python tasks.py train`")
    return joblib.load(path)
