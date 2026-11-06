"""The eval harness: each run goes through the API code path, is scored against truth, and is saved
as one line of evals/results/runs/<config>.jsonl.

    uv run --project backend python evals/run.py --config default --scenarios all --variants 1
    uv run --project backend python evals/run.py --config small --scenarios s01,s08 --mock

--variants N runs variants 1 to N, --repeat N runs each N times, and --mock uses the scripted model
and writes to <config>-mock.jsonl with no Groq call. EVAL_TIER=free|paid sets the limits.

Rerun the same command to resume: saved runs are skipped. A line is written only once a run has been
scored, and a batch that can't fit today stops with exit 0 and "resume after <time>". A run hit by
Groq's daily limit is thrown away rather than saved: the chain's fallbacks would otherwise pass it
off as a real result.

The injection scenario's prompts and results stay in memory. Logging is off during its run and
only metrics are printed. It needs ALLOW_BLOCKED_ALERTS, which is set on this harness's own
settings and nowhere else.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import argparse  # noqa: E402
import asyncio  # noqa: E402
import io  # noqa: E402
import logging  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
from collections.abc import Awaitable, Callable, Iterator, Sequence  # noqa: E402
from contextlib import contextmanager  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from functools import partial  # noqa: E402
from typing import Any, TypeVar  # noqa: E402

import httpx  # noqa: E402
import yaml  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from pymongo import MongoClient  # noqa: E402

from app.agent.agents.intel import MAX_TREES, extract_entities  # noqa: E402
from app.agent.case import Case  # noqa: E402
from app.agent.deps import MongoTelemetry, ToolRunner  # noqa: E402
from app.api.routes import Services  # noqa: E402
from app.api.runner import Runner  # noqa: E402
from app.api.store import InMemoryStore  # noqa: E402
from app.config import CYBERINTEL, Settings, get_settings  # noqa: E402
from app.llm import (  # noqa: E402
    LLM,
    DailyLimitError,
    InvalidToolCallError,
    UsageLog,
    get_model,
)
from app.main import create_app  # noqa: E402
from app.telemetry.db import telemetry_client, telemetry_db  # noqa: E402
from app.telemetry.models import Alert  # noqa: E402
from app.tools import call_tool  # noqa: E402
from evals.budget import SpendLog, next_run_tokens  # noqa: E402
from evals.common import EVAL_SEED, RESULTS, append_jsonl, read_jsonl  # noqa: E402
from evals.configs import CONFIGS, EvalConfig, EvalSettings, Tier  # noqa: E402
from evals.mock_model import mock_model  # noqa: E402
from evals.scoring import (  # noqa: E402
    ErrorKind,
    IntelCoverage,
    RunRecord,
    Truth,
    load_truth,
    score_run,
    tree_indicators,
)
from scripts.gen.dataset import VARIANTS, build_dataset  # noqa: E402
from scripts.load import SeederSettings, load_collections  # noqa: E402

RUNS = RESULTS / "runs"
TRUTH_DIR = ROOT / "scenarios" / "truth"
VARIANT_TRUTH = ROOT / "data" / "generated" / "truth"
HOME_VARIANT = 1
T = TypeVar("T", bound=BaseModel)
LLMFactory = Callable[[Settings, Alert], LLM]


class NoLLMCallSucceeded(RuntimeError):
    """A bad key, an outage or a spend limit: nothing was learned, and the next run would fail the
    same way, so this stops the batch instead of saving failures."""


class WatchedLLM:
    """Counts failed calls, which the chain's fallbacks otherwise hide. After a daily-limit error
    every call fails at once, so a doomed run doesn't spend more on its other model."""

    def __init__(self, inner: LLM) -> None:
        self._inner = inner
        self.usage: UsageLog = inner.usage
        self.failures = 0
        self.daily_limit: DailyLimitError | None = None

    async def _watched(self, call: Callable[[], Awaitable[Any]]) -> Any:
        if self.daily_limit is not None:
            raise self.daily_limit
        try:
            return await call()
        except InvalidToolCallError:
            # A bad tool call the investigator recovers from: the model answered.
            raise
        except DailyLimitError as exc:
            self.failures += 1
            self.daily_limit = exc
            raise
        except Exception:
            self.failures += 1
            raise

    async def invoke_tools(
        self, node: str, messages: Sequence[BaseMessage], tools: list[dict[str, Any]]
    ) -> AIMessage:
        return await self._watched(lambda: self._inner.invoke_tools(node, messages, tools))

    async def invoke_structured(
        self, node: str, messages: Sequence[BaseMessage], schema: type[T]
    ) -> T:
        return await self._watched(lambda: self._inner.invoke_structured(node, messages, schema))


@contextmanager
def quiet(on: bool) -> Iterator[None]:
    """No logging at all while `on`: log lines can quote what a run saw."""
    if on:
        logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        if on:
            logging.disable(logging.NOTSET)


@dataclass
class Environment:
    """What a batch runs against; tests swap in fakes for all of it."""

    telemetry: Any
    tool: ToolRunner
    llm_for: LLMFactory
    load_variant: Callable[[int], None]
    truth_for: Callable[[int], dict[str, Truth]]
    runs_dir: Path
    base_settings: Settings
    tier: Tier
    mock: bool
    commit: str
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    out: Callable[[str], None] = print


@dataclass
class Outcome:
    record: RunRecord | None
    usage: UsageLog
    daily_limit: DailyLimitError | None = None


ERROR_KINDS: dict[str, ErrorKind] = {
    "the run timed out": "timeout",
    "the run did not finish": "did_not_finish",
}


async def intel_coverage(
    telemetry: Any, tool: ToolRunner, alert: Alert, case: Case | None
) -> IntelCoverage:
    """How much of the trigger tree CyberIntel-Agent looked up. The harness fetches the tree and
    the reputations itself, read-only and uncharged. The extraction is the rule intel.py applies,
    so this measures what its caps and failures lost."""
    docs = await telemetry.events(alert.trigger_event_ids)
    trees = []
    for doc in docs[:MAX_TREES]:
        if doc["event_type"] == "process_start":
            tree = await tool("get_process_tree", {"event_id": doc["event_id"]})
            if isinstance(tree.get("untrusted_log_data"), dict):
                trees.append(tree["untrusted_log_data"])
    wanted = tree_indicators(extract_entities(docs, trees))
    logs = case.tool_logs.get(CYBERINTEL, []) if case else []
    looked_up = {
        str(r.args.get("indicator")).lower() for r in logs if r.name == "check_reputation" and r.ok
    }
    known_bad = 0
    found = 0
    for indicator, kind in wanted.items():
        result = await tool("check_reputation", {"indicator": indicator, "type": kind})
        data = result.get("untrusted_log_data")
        if isinstance(data, dict) and data.get("reputation") == "known_bad":
            known_bad += 1
            found += indicator in looked_up
    return IntelCoverage(
        tree_indicators=len(wanted),
        looked_up=len(looked_up & set(wanted)),
        known_bad=known_bad,
        known_bad_found=found,
    )


async def run_one(
    truth: Truth, config: EvalConfig, variant: int, repeat: int, env: Environment
) -> Outcome:
    """One run through POST /investigations, with a store that disappears when it returns."""
    settings = config.settings(env.base_settings, env.tier)
    alert = await env.telemetry.alert(truth.alert_id)
    if alert is None:
        raise ValueError(f"{truth.scenario}: alert {truth.alert_id} isn't loaded; variant mismatch")
    watched: list[WatchedLLM] = []

    def llm_for(s: Settings) -> LLM:
        watched.append(WatchedLLM(env.llm_for(s, alert)))
        return watched[-1]

    store = InMemoryStore()
    runner = Runner(store, env.telemetry, env.tool, settings, llm_for)
    services = Services(store, env.telemetry, runner, settings, RESULTS)
    started = time.monotonic()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(lambda: services)), base_url="http://eval"
    ) as api:
        response = await api.post("/investigations", json={"alert_id": truth.alert_id})
        response.raise_for_status()
        investigation_id = response.json()["investigation_id"]
        await runner.tasks[investigation_id]
    doc = await store.get_investigation(investigation_id)
    if doc is None or not watched:
        raise RuntimeError(f"{truth.scenario}: the run left no record")
    llm = watched[0]
    if llm.daily_limit is not None:
        return Outcome(None, llm.usage, llm.daily_limit)
    if llm.failures and not llm.usage.calls:
        raise NoLLMCallSucceeded(f"{truth.scenario}: every LLM call failed")
    state = doc.get("state")
    case = Case.model_validate(state) if state else None
    error_kind: ErrorKind | None = None
    if doc["status"] == "failed":
        error_kind = ERROR_KINDS.get(doc.get("error", ""), "exception")
    record = score_run(
        truth,
        case,
        config=config.name if not env.mock else f"{config.name}-mock",
        variant=variant,
        repeat=repeat,
        mock=env.mock,
        commit=env.commit,
        error_kind=error_kind,
        usage=llm.usage,
        llm_failures=llm.failures,
        seconds=doc.get("seconds") or time.monotonic() - started,
        intel=await intel_coverage(env.telemetry, env.tool, alert, case),
    )
    return Outcome(record, llm.usage)


def run_line(record: RunRecord) -> str:
    """Metrics only, for every scenario alike."""
    state = "PASS" if record.passed else "FAIL"
    tokens = sum(record.tokens_by_model.values())
    return (
        f"{record.scenario} v{record.variant} r{record.repeat}: {state} {record.status}, "
        f"verdict {record.verdict} (expected {record.expected_verdict}), risk {record.risk_score}, "
        f"{tokens} tokens, {record.llm_calls} LLM calls, {record.tool_calls} tool calls, "
        f"{record.seconds:.1f} s"
    )


def saved_runs(path: Path) -> dict[tuple[str, int, int], RunRecord]:
    """The latest record per run. read_jsonl has already removed any half-written last line."""
    records = [RunRecord.model_validate(row) for row in read_jsonl(path)]
    return {r.key: r for r in records}


def write_variant_truth(variant: int) -> None:
    """Truth for a variant other than the seeded one, in a gitignored directory."""
    dataset = build_dataset(EVAL_SEED, variant)
    directory = VARIANT_TRUTH / f"v{variant}"
    directory.mkdir(parents=True, exist_ok=True)
    for result in dataset.scenarios:
        text = yaml.safe_dump(dataset.truth(result, EVAL_SEED, variant), sort_keys=False)
        (directory / f"{result.scenario_id}.yaml").write_text(text, encoding="utf-8", newline="\n")


def truth_for(variant: int) -> dict[str, Truth]:
    if variant == HOME_VARIANT:
        return load_truth(TRUTH_DIR)
    write_variant_truth(variant)
    return load_truth(VARIANT_TRUTH / f"v{variant}")


def load_variant(variant: int) -> None:
    """Replace the telemetry db with this variant, as the seeder user."""
    uri = SeederSettings().seeder_mongo_uri.get_secret_value()
    client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=3000, tz_aware=True)
    try:
        load_collections(
            client.get_default_database(), build_dataset(EVAL_SEED, variant).collections()
        )
    finally:
        client.close()


def pending_runs(
    scenarios: list[str] | None,
    variants: list[int],
    repeats: int,
    env: Environment,
    saved: dict[tuple[str, int, int], RunRecord],
    retry_failed: bool,
) -> Iterator[tuple[int, Truth, int]]:
    """(variant, truth, repeat) for every run not saved yet."""
    for variant in variants:
        truths = env.truth_for(variant)
        for scenario in sorted(truths) if scenarios is None else scenarios:
            for repeat in range(1, repeats + 1):
                previous = saved.get((scenario, variant, repeat))
                if previous is None or (retry_failed and previous.status == "failed"):
                    yield variant, truths[scenario], repeat


async def run_batch(
    config: EvalConfig,
    scenarios: list[str] | None,
    variants: list[int],
    repeats: int,
    env: Environment,
    retry_failed: bool = False,
) -> int:
    """Runs what isn't saved yet. 0: finished or stopped cleanly to resume later. 1: can't go on."""
    name = f"{config.name}-mock" if env.mock else config.name
    path = env.runs_dir / f"{name}.jsonl"
    saved = saved_runs(path)
    spend = SpendLog(env.runs_dir / "spend.jsonl", env.tier)
    models = config.model_names(env.base_settings, env.tier)
    loaded: int | None = None
    done = 0
    try:
        for variant, truth, repeat in pending_runs(
            scenarios, variants, repeats, env, saved, retry_failed
        ):
            if not env.mock and env.tier.enforce_daily:
                needed = next_run_tokens(list(saved.values()), models)
                resume = spend.resume_time(needed, env.clock())
                if resume is not None:
                    env.out(f"Budget: next run won't fit. resume after {resume.isoformat()}")
                    return 0
            if loaded != variant:
                env.load_variant(variant)
                loaded = variant
            run = f"{name}/{truth.scenario}/v{variant}/r{repeat}"
            try:
                with quiet(truth.injection):
                    outcome = await run_one(truth, config, variant, repeat, env)
            except NoLLMCallSucceeded as exc:
                env.out(f"Stopped: {exc}. Nothing was saved for this run.")
                return 1
            except Exception:
                if truth.injection:
                    # The traceback could quote what the run saw.
                    env.out(f"Stopped: {truth.scenario} raised; details are withheld.")
                    return 1
                raise
            now = env.clock()
            if not env.mock:
                tokens = {m: r["billed_tokens"] for m, r in outcome.usage.by_model().items()}
                spend.add_run(now, run, tokens, kept=outcome.record is not None)
            if outcome.daily_limit is not None:
                limit = outcome.daily_limit
                resume = spend.add_limit_hit(now, limit.model, limit.used, limit.retry_after)
                env.out(
                    f"Daily limit on {limit.model}: {run} was thrown away. "
                    f"resume after {resume.isoformat()}"
                )
                return 0
            if outcome.record is None:
                raise RuntimeError(f"{run}: no record and no daily limit")
            append_jsonl(path, outcome.record.model_dump())
            saved[outcome.record.key] = outcome.record
            env.out(run_line(outcome.record))
            done += 1
    finally:
        if loaded not in (None, HOME_VARIANT):
            env.load_variant(HOME_VARIANT)
    env.out(f"{name}: {done} new run(s), {len(saved)} saved.")
    return 0


def commit_id() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() or "unknown"


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    mock = args.mock or settings.llm_mode == "mock"
    tier = EvalSettings().tier()
    print(f"config {args.config}, tier {tier.name}, {'scripted model' if mock else 'Groq'}")
    client = telemetry_client()
    try:
        db = telemetry_db(client)

        def llm_for(s: Settings, alert: Alert) -> LLM:
            return mock_model(alert) if mock else get_model(s)

        env = Environment(
            telemetry=MongoTelemetry(db),
            tool=partial(call_tool, db=db),
            llm_for=llm_for,
            load_variant=load_variant,
            truth_for=truth_for,
            runs_dir=RUNS,
            base_settings=settings,
            tier=tier,
            mock=mock,
            commit=commit_id(),
        )
        chosen = None if args.scenarios == "all" else args.scenarios.split(",")
        return await run_batch(
            CONFIGS[args.config],
            chosen,
            list(range(1, args.variants + 1)),
            args.repeat,
            env,
            args.retry_failed,
        )
    finally:
        await client.close()


def main() -> int:
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Run the eval harness; rerun to resume.")
    parser.add_argument("--config", required=True, choices=sorted(CONFIGS))
    parser.add_argument("--scenarios", default="all", help="'all', or a list like s01,s08")
    parser.add_argument("--variants", type=int, default=1, choices=range(1, len(VARIANTS) + 1))
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--mock", action="store_true", help="the scripted model; no Groq calls")
    parser.add_argument("--retry-failed", action="store_true", help="rerun saved failed runs")
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
