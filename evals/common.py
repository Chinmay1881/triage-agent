"""Shared by the ML evals: the eval week and which of its events scenarios emitted.

evals/ is the only package allowed to know which events are scenario events. The eval week
is rebuilt in memory from the same deterministic build that `python tasks.py seed` loads.
"""

import json
import os
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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Every whole line. A last line with no newline is a write that died halfway: it's cut off
    here, so resuming reruns that run instead of tripping over half a record."""
    if not path.exists():
        return []
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        data = data[: data.rfind(b"\n") + 1]
        path.write_bytes(data)
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line]


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    """One whole line in one write, flushed to disk before returning."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
    with path.open("ab") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def write_result(name: str, result: dict[str, Any]) -> Path:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}_{today}.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path
