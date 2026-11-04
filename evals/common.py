"""Shared by the ML evals: the eval week and which of its events scenarios emitted.

evals/ is the only package allowed to know which events are scenario events. The eval week
is rebuilt in memory from the same deterministic build that `python tasks.py seed` loads.
"""

import json
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

from scripts.gen.dataset import Dataset, build_dataset

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evals" / "results"
EVAL_SEED = 42
EVAL_VARIANT = 1


@cache
def eval_week() -> Dataset:
    return build_dataset(EVAL_SEED, EVAL_VARIANT)


def scenario_event_ids(ds: Dataset) -> set[str]:
    return {e.event_id for r in ds.scenarios for e in [*r.events, *r.key_events]}


def write_result(name: str, result: dict[str, Any]) -> Path:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}_{today}.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path
