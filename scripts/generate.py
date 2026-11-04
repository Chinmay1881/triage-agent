"""Generate the synthetic company, a week of telemetry, and scenarios s01-s12.

    uv run --project backend python scripts/generate.py --seed 42 --variant 1
    uv run --project backend python scripts/generate.py --seed 7 --background-only

Writes data/generated/*.jsonl (loaded into Mongo by scripts/load.py) and
scenarios/truth/sNN.yaml (read only by evals/, never loaded into Mongo).
--background-only writes a scenario-free week to data/baseline/ and no truth files; it is
the anomaly model's training data (scripts/train.py builds the same week in memory).
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKLIST = "cli_blocklist.json"
# Scripts run from the repo root but share the backend's models; make both importable.
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import yaml  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from scripts.gen.dataset import VARIANTS, Dataset, build_background, build_dataset  # noqa: E402


def write_jsonl(path: Path, rows: list[BaseModel]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(row.model_dump_json() + "\n")


def write_telemetry(dataset: Dataset, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "events.jsonl", dataset.events)
    write_jsonl(out / "hosts.jsonl", dataset.hosts)
    write_jsonl(out / "users.jsonl", dataset.users)
    write_jsonl(out / "intel.jsonl", dataset.intel)
    write_jsonl(out / "alerts.jsonl", dataset.alerts)


def write_blocklist(dataset: Dataset, out: Path) -> None:
    """Alert IDs the dev CLI must refuse: the prompt-injection scenario is run only by the eval
    harness. Just IDs, no verdict or technique; only app/cli.py reads this file."""
    blocked = sorted(r.alert.alert_id for r in dataset.scenarios if r.injection)
    text = json.dumps({"alert_ids": blocked}, indent=2) + "\n"
    (out / BLOCKLIST).write_text(text, encoding="utf-8", newline="\n")


def write_dataset(dataset: Dataset, seed: int, variant: int, out: Path, truth_dir: Path) -> None:
    write_telemetry(dataset, out)
    write_blocklist(dataset, out)
    truth_dir.mkdir(parents=True, exist_ok=True)
    for result in dataset.scenarios:
        truth = dataset.truth(result, seed, variant)
        text = yaml.safe_dump(truth, sort_keys=False, allow_unicode=True)
        (truth_dir / f"{result.scenario_id}.yaml").write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic telemetry and scenarios")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--variant", type=int, choices=VARIANTS, default=1)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--truth-dir", type=Path, default=ROOT / "scenarios" / "truth")
    parser.add_argument(
        "--background-only", action="store_true", help="no scenarios, alerts or truth files"
    )
    args = parser.parse_args()

    if args.background_only:
        out = args.out or ROOT / "data" / "baseline"
        dataset = build_background(args.seed)
        write_telemetry(dataset, out)
        print(f"seed {args.seed} background only: {len(dataset.events)} events, wrote {out}")
        return 0

    out = args.out or ROOT / "data" / "generated"
    dataset = build_dataset(args.seed, args.variant)
    write_dataset(dataset, args.seed, args.variant, out, args.truth_dir)

    counts = Counter(e.event_type for e in dataset.events)
    print(f"seed {args.seed} variant {args.variant}: {len(dataset.events)} events")
    for event_type, n in sorted(counts.items()):
        print(f"  {event_type:<15} {n:>6}")
    print(
        f"  {len(dataset.hosts)} hosts, {len(dataset.users)} users, "
        f"{len(dataset.intel)} intel entries, {len(dataset.alerts)} alerts"
    )
    print(f"wrote {out} and {len(dataset.scenarios)} truth files to {args.truth_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
