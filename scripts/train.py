"""Train the anomaly model and the injection classifier into data/models/.

    uv run --project backend python scripts/train.py [--seed 7]

Both models learn "normal" from a background-only week built in memory from --seed (no
scenarios, no truth). The eval week is seed 42, so that seed is refused: a model trained on
it would have seen the events it is scored on.

The injection classifier trains on the train split of data/datasets/prompt_injections/
(fetched first if missing) plus the baseline week's distinct command lines as benign rows.
deepset's benign rows are questions, so without them the classifier has never seen an
ordinary command line, and quotes and dashes alone push one toward "injection". Prints counts
and the chosen threshold only, never rows.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from app.ml import anomaly, injection  # noqa: E402
from app.telemetry.decode import decode_encoded_command  # noqa: E402
from scripts import fetch_datasets  # noqa: E402
from scripts.gen.dataset import Dataset, build_background  # noqa: E402

EVAL_SEED = 42
BASELINE_SEED = 7


def train_anomaly(baseline: Dataset, seed: int) -> anomaly.AnomalyModel:
    return anomaly.train([e.model_dump() for e in baseline.events], baseline_seed=seed)


def benign_cmdlines(baseline: Dataset) -> list[str]:
    """Distinct command lines and decoded -EncodedCommand texts of the baseline week, sorted
    so training sees them in a fixed order."""
    texts = set()
    for e in baseline.events:
        if e.event_type == "process_start" and e.process and e.process.cmdline:
            texts.add(e.process.cmdline)
            decoded = decode_encoded_command(e.process.cmdline)
            if decoded is not None:
                texts.add(decoded)
    return sorted(texts)


def injection_training_data(baseline: Dataset) -> tuple[list[str], list[int]]:
    if not fetch_datasets.is_fetched() and fetch_datasets.main() != 0:
        raise RuntimeError("could not fetch the prompt-injection dataset")
    texts, labels = fetch_datasets.read_split("train")
    benign = benign_cmdlines(baseline)
    return [*texts, *benign], [*labels, *[0] * len(benign)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the anomaly and injection models")
    parser.add_argument("--seed", type=int, default=BASELINE_SEED, help="baseline week seed")
    args = parser.parse_args()
    if args.seed == EVAL_SEED:
        parser.error(f"seed {EVAL_SEED} is the eval week; train on a different seed")
    baseline = build_background(args.seed)

    model = train_anomaly(baseline, args.seed)
    anomaly.save(model)
    sizes = {t: len(m.sorted_scores) for t, m in model.models.items()}
    print(f"anomaly: baseline seed {args.seed}, {sizes}, wrote {anomaly.ARTIFACT}")

    texts, labels = injection_training_data(baseline)
    classifier = injection.train(texts, labels)
    injection.save(classifier)
    print(
        f"injection: {len(texts)} training texts ({sum(labels)} injections), "
        f"threshold {classifier.threshold:.3f}, wrote {injection.ARTIFACT}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
