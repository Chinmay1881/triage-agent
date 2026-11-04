"""Trained models (spec: "ML and NLP components"): an IsolationForest anomaly scorer for
process and network events, and a TF-IDF + logistic-regression prompt-injection classifier.

Training code takes plain rows and texts from scripts/train.py; nothing here reads datasets,
scenarios or truth. The only files read are the artifacts in data/models/, which
`python tasks.py train` builds locally.
"""

from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parents[3] / "data" / "models"


class ModelMissingError(RuntimeError):
    """The artifact hasn't been built; the message says how to build it."""
