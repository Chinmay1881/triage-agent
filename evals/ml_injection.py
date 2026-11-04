"""The injection classifier: test-split metrics, false positives on real-looking command
lines, and whether s12's trigger is flagged.

    uv run --project backend python evals/ml_injection.py [--prompt-guard] [--limit 320]

- precision / recall / F1 on the test split of deepset/prompt-injections;
- false-positive rate over every cmdline and decoded -EncodedCommand text of the eval week's
  background process starts (each occurrence counts; distinct texts are scored once);
- s12_trigger_flagged: every trigger event of s12's alert has its command line or decoded
  text flagged. A boolean only: s12's text is never printed or written.

--prompt-guard adds the same metrics for Llama Prompt Guard 2 (86M) on Groq, on at most
--limit texts: s12's trigger texts, the full test split, then a fixed-seed sample of up to
200 distinct background command lines. Skipped without GROQ_API_KEY or with LLM_MODE=mock.
Writes evals/results/injection_<date>.json; prints metrics only.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import argparse  # noqa: E402
import random  # noqa: E402
from collections import Counter  # noqa: E402
from collections.abc import Callable, Sequence  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from typing import Any  # noqa: E402

from langchain.chat_models import init_chat_model  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from sklearn.metrics import precision_recall_fscore_support  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.ml import ModelMissingError, injection  # noqa: E402
from app.telemetry.decode import decode_encoded_command  # noqa: E402
from evals.common import eval_week, scenario_event_ids, write_result  # noqa: E402
from scripts import fetch_datasets  # noqa: E402
from scripts.gen.dataset import Dataset  # noqa: E402

INJECTION_SCENARIO = "s12"
PROMPT_GUARD = "meta-llama/llama-prompt-guard-2-86m"
PROMPT_GUARD_THRESHOLD = 0.5
# The model's context is 512 tokens; this keeps a text comfortably inside it.
PROMPT_GUARD_CHARS = 1500
BACKGROUND_SAMPLE = 200
SAMPLE_SEED = 0
DEFAULT_LIMIT = 320

Flagger = Callable[[Sequence[str]], list[bool]]


def process_texts(cmdline: str) -> list[str]:
    decoded = decode_encoded_command(cmdline)
    return [cmdline] if decoded is None else [cmdline, decoded]


def background_texts(ds: Dataset) -> Counter[str]:
    in_scenarios = scenario_event_ids(ds)
    texts: Counter[str] = Counter()
    for e in ds.events:
        if e.event_type == "process_start" and e.event_id not in in_scenarios and e.process:
            texts.update(process_texts(e.process.cmdline or ""))
    return texts


def trigger_texts(ds: Dataset) -> list[list[str]]:
    """Per trigger event of the injection scenario's alert, its texts."""
    result = next(r for r in ds.scenarios if r.scenario_id == INJECTION_SCENARIO)
    events = {e.event_id: e for e in ds.events}
    out = []
    for trigger in result.alert.triggers:
        process = events[trigger.event_id].process
        out.append(process_texts(process.cmdline) if process and process.cmdline else [])
    return out


@dataclass
class EvalTexts:
    test_texts: list[str]
    test_labels: list[int]
    background: Counter[str]
    triggers: list[list[str]]


def evaluate(flags: Flagger, data: EvalTexts) -> dict[str, Any]:
    distinct = sorted(data.background)
    all_texts = [*data.test_texts, *distinct, *(t for ts in data.triggers for t in ts)]
    flagged = dict(zip(all_texts, flags(all_texts), strict=True))

    predicted = [flagged[t] for t in data.test_texts]
    precision, recall, f1, _ = precision_recall_fscore_support(
        data.test_labels, predicted, average="binary", zero_division=0
    )
    total = sum(data.background.values())
    false_positives = sum(n for text, n in data.background.items() if flagged[text])
    return {
        "test_rows": len(data.test_texts),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "background_texts": total,
        "background_distinct": len(distinct),
        "background_false_positive_rate": round(false_positives / total, 4),
        "s12_trigger_flagged": bool(data.triggers)
        and all(any(flagged[t] for t in ts) for ts in data.triggers),
    }


def full_eval_texts(ds: Dataset) -> EvalTexts:
    texts, labels = fetch_datasets.read_split("test")
    return EvalTexts(texts, labels, background_texts(ds), trigger_texts(ds))


def limited_eval_texts(data: EvalTexts, limit: int) -> EvalTexts:
    """Trigger texts first, then the test split, then a fixed-seed background sample."""
    triggers, budget = [], limit
    for ts in data.triggers:
        triggers.append(ts[:budget])
        budget -= len(triggers[-1])
    test_n = min(len(data.test_texts), budget)
    budget -= test_n
    sample_n = min(BACKGROUND_SAMPLE, budget, len(data.background))
    sample = random.Random(SAMPLE_SEED).sample(sorted(data.background), sample_n)
    return EvalTexts(data.test_texts[:test_n], data.test_labels[:test_n], Counter(sample), triggers)


class PromptGuardError(RuntimeError):
    pass


def prompt_guard_flagger(api_key: str) -> Flagger:
    model = init_chat_model(
        PROMPT_GUARD, model_provider="groq", temperature=0, max_retries=6, api_key=api_key
    )

    def flags(texts: Sequence[str]) -> list[bool]:
        out = []
        for text in texts:
            reply = model.invoke(text[:PROMPT_GUARD_CHARS]).content
            # Groq doesn't document the reply format; it is expected to be the probability that
            # the text is malicious. Anything else stops the comparison rather than guessing.
            try:
                probability = float(str(reply).strip())
            except ValueError:
                raise PromptGuardError("reply was not a probability") from None
            out.append(probability >= PROMPT_GUARD_THRESHOLD)
        return out

    return flags


def groq_key() -> str | None:
    try:
        settings = get_settings()
    except ValidationError:
        return None
    if settings.llm_mode == "mock" or settings.groq_api_key is None:
        return None
    return settings.groq_api_key.get_secret_value() or None


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the injection classifier")
    parser.add_argument("--prompt-guard", action="store_true", help=f"also score {PROMPT_GUARD}")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="max Prompt Guard texts")
    args = parser.parse_args()

    try:
        model = injection.load()
    except ModelMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    data = full_eval_texts(eval_week())
    result: dict[str, Any] = {
        "dataset_revision": fetch_datasets.read_manifest()["revision"],
        "threshold": round(model.threshold, 4),
        "classifier": evaluate(lambda texts: list(model.scores(texts) >= model.threshold), data),
    }
    if args.prompt_guard:
        key = groq_key()
        if key is None:
            result["prompt_guard"] = {"skipped": "no GROQ_API_KEY, or LLM_MODE=mock"}
        else:
            try:
                limited = limited_eval_texts(data, args.limit)
                result["prompt_guard"] = evaluate(prompt_guard_flagger(key), limited)
            except PromptGuardError as exc:
                result["prompt_guard"] = {"skipped": str(exc)}
    path = write_result("injection", result)

    print(f"threshold {result['threshold']} (chosen on the train split)")
    for name in ("classifier", "prompt_guard"):
        if name in result:
            print(f"  {name:<11} {result[name]}")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
