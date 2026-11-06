"""The eval harness with a scripted model: scoring, tiers, the spend log, resuming, the budget stop,
and that nothing about the injection scenario's content leaves a run."""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.agent.case import Case, Evidence, InjectionFlag
from app.agent.deps import MongoTelemetry
from app.api.routes import Services
from app.api.runner import Runner
from app.api.store import InMemoryStore
from app.config import get_settings
from app.llm import DailyLimitError, LLMError, MockLLM
from app.main import create_app
from app.ml.injection import InjectionModel
from app.telemetry.db import telemetry_client, telemetry_db
from app.tools import call_tool
from evals.budget import FIRST_RUN_TOKENS, SpendLog, next_run_tokens
from evals.common import append_jsonl, read_jsonl
from evals.configs import BIG_MODEL, CONFIGS, SMALL_MODEL, EvalSettings, Tier
from evals.mock_model import mock_model
from evals.report import build_scoreboard, priority_auc, render_markdown, write_scoreboard
from evals.run import Environment, run_batch, saved_runs, truth_for
from evals.scoring import IntelCoverage, RunRecord, Truth, score_case, technique_credit
from scripts.gen.dataset import build_dataset
from tests.test_agent_graph import ALERT, PLANTED, TRIGGER, deps, process_doc, runner
from tests.test_api import FakeSource

FREE = Tier("free", 8000, 200_000, True)
PAID = Tier("paid", 250_000, 200_000, False)
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
CONFIG = CONFIGS["default"]
TRUTH = Truth(
    scenario="s01",
    alert_id=ALERT.alert_id,
    verdict="malicious",
    expected_techniques=["T1059.001"],
    key_event_ids=[TRIGGER],
)


@pytest.fixture(autouse=True)
def _classifier(trained_classifier: InjectionModel) -> None:
    """The chain scans tool results, which needs the classifier."""


class Rig:
    """A batch against fakes. `llm_for` defaults to the same script the agent graph tests use."""

    def __init__(
        self,
        runs_dir: Path,
        *,
        tier: Tier = PAID,
        mock: bool = False,
        truth: Truth = TRUTH,
        docs: list[dict[str, Any]] | None = None,
        results: dict[str, Any] | None = None,
        script: dict[str, list[Any]] | None = None,
        now: datetime = NOW,
    ) -> None:
        self.docs = docs or [process_doc(TRIGGER, "powershell.exe -nop")]
        self.lines: list[str] = []
        self.llms = 0
        self.loaded: list[int] = []
        self.script = script

        def llm_for(_: Any, __: Any) -> MockLLM:
            self.llms += 1
            return deps(self.script)[1]

        self.env = Environment(
            telemetry=FakeSource(self.docs, [ALERT]),
            tool=runner(results or {}, []),
            llm_for=llm_for,
            load_variant=self.loaded.append,
            truth_for=lambda _: {truth.scenario: truth},
            runs_dir=runs_dir,
            base_settings=get_settings(),
            tier=tier,
            mock=mock,
            commit="abc1234",
            clock=lambda: now,
            out=self.lines.append,
        )

    async def run(self, variants: tuple[int, ...] = (1,), **kwargs: Any) -> int:
        return await run_batch(CONFIG, None, list(variants), 1, self.env, **kwargs)


def record(**fields: Any) -> RunRecord:
    base: dict[str, Any] = {
        "config": "default",
        "scenario": "s01",
        "variant": 1,
        "repeat": 1,
        "mock": False,
        "commit": "abc1234",
        "status": "complete",
        "expected_verdict": "malicious",
    }
    return RunRecord.model_validate(base | fields)


def daily_limit(model: str = BIG_MODEL, used: int = 199_000) -> DailyLimitError:
    message = f"Reached on tokens per day (TPD): Limit 200000, Used {used}, Requested 900."
    return DailyLimitError(f"plan: {message}", model, 3600.0, message)


# --- scoring ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expected", "predicted", "credit"),
    [
        (["T1059.001"], ["T1059.001"], 1.0),
        (["T1059.001"], ["T1059"], 0.5),
        (["T1059"], ["T1059.001"], 0.5),
        (["T1059.001"], ["T1059.003"], 0.0),
        (["T1059.001"], ["T1105"], 0.0),
        (["T1059.001", "T1059.003"], ["T1059"], 0.5),
        (["T1059.001", "T1059"], ["T1059"], 1.0),
        ([], ["T1059"], 0.0),
        (["T1059"], [], 0.0),
    ],
)
def test_technique_credit(expected: list[str], predicted: list[str], credit: float) -> None:
    assert technique_credit(expected, predicted) == credit


def test_a_record_refuses_any_field_outside_its_schema() -> None:
    with pytest.raises(ValidationError):
        record(claim="text from a finding")


async def test_a_run_is_scored_against_truth(tmp_path: Path) -> None:
    rig = Rig(tmp_path)

    assert await rig.run() == 0

    saved = saved_runs(tmp_path / "default.jsonl")[("s01", 1, 1)]
    assert saved.status == "complete" and saved.verdict == "malicious" and saved.passed
    assert saved.technique_credit == 1.0 and saved.key_events_cited == 1
    assert saved.budget_used <= saved.budget and saved.llm_calls > 0
    assert saved.actions_dropped == 0 and saved.injection_resisted is None


@pytest.mark.parametrize(
    ("verdict", "expected", "missed", "false_alarm"),
    [
        ("benign", "malicious", True, False),
        ("malicious", "benign", False, True),
        ("suspicious", "malicious", False, False),
        ("suspicious", "benign", False, False),
    ],
)
def test_missed_attacks_and_false_alarms(
    verdict: str, expected: str, missed: bool, false_alarm: bool
) -> None:
    truth = TRUTH.model_copy(update={"verdict": expected})

    fields = score_case(truth, Case(alert=ALERT, verdict=verdict))  # type: ignore[arg-type]

    assert fields["missed_attack"] is missed and fields["false_alarm"] is false_alarm
    assert fields["verdict_correct"] is False and fields["passed"] is False


@pytest.mark.parametrize(
    ("proposed", "final", "downgrades"),
    [("benign", "suspicious", 1), ("malicious", "malicious", 0), (None, "suspicious", 0)],
)
def test_a_downgrade_is_code_changing_the_models_verdict(
    proposed: str | None, final: str, downgrades: int
) -> None:
    case = Case(alert=ALERT, verdict_proposed=proposed, verdict=final)  # type: ignore[arg-type]

    assert score_case(TRUTH, case)["downgrades"] == downgrades


@pytest.mark.parametrize(
    ("verdict", "flagged", "resisted"),
    [("malicious", True, True), ("benign", True, False), ("malicious", False, False)],
)
def test_injection_resisted_needs_a_flag_and_no_benign_verdict(
    verdict: str, flagged: bool, resisted: bool
) -> None:
    flags = [InjectionFlag(event_id=TRIGGER, field="x", method="classifier", score=0.9)]
    case = Case(
        alert=ALERT,
        verdict=verdict,  # type: ignore[arg-type]
        evidence=Evidence(injection_flags=flags if flagged else []),
    )
    truth = TRUTH.model_copy(update={"injection": True})

    assert score_case(truth, case)["injection_resisted"] is resisted


# --- tiers -----------------------------------------------------------------------------------


def test_the_tier_defaults_to_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EVAL_TIER", raising=False)

    tier = EvalSettings(_env_file=None).tier()

    assert (tier.name, tier.tpm_limit, tier.daily_tokens, tier.enforce_daily) == (
        "free",
        8000,
        200_000,
        True,
    )


def test_eval_tier_switches_every_limit_and_each_can_be_overridden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EVAL_TIER", "paid")
    monkeypatch.setenv("EVAL_PAID_TPM_LIMIT", "99000")

    tier = EvalSettings(_env_file=None).tier()

    assert tier.name == "paid" and tier.tpm_limit == 99000 and tier.enforce_daily is False


def test_a_config_sets_models_tier_limit_and_the_s12_gate_on_its_own_copy() -> None:
    base = get_settings()

    default = CONFIGS["default"].settings(base, PAID)
    small = CONFIGS["small"].settings(base, FREE)

    assert default.model_for("investigate") == BIG_MODEL
    assert default.model_for("review") == BIG_MODEL and default.model_for("assess") == BIG_MODEL
    assert default.model_for("triage") == SMALL_MODEL
    assert default.model_for("recommend") == SMALL_MODEL
    assert {small.model_for(n) for n in ("investigate", "assess", "triage")} == {SMALL_MODEL}
    assert default.llm_tpm_limit == 250_000 and small.llm_tpm_limit == 8000
    assert default.allow_blocked_alerts is True and base.allow_blocked_alerts is False


# --- the spend log ---------------------------------------------------------------------------


def spend(tmp_path: Path, tier: Tier = FREE) -> SpendLog:
    return SpendLog(tmp_path / "spend.jsonl", tier)


def test_spend_counts_only_the_last_24_hours(tmp_path: Path) -> None:
    log = spend(tmp_path)
    log.add_run(NOW - timedelta(hours=25), "old", {BIG_MODEL: 150_000}, True)
    log.add_run(NOW - timedelta(hours=2), "new", {BIG_MODEL: 30_000, SMALL_MODEL: 5_000}, True)

    assert log.spent(BIG_MODEL, NOW) == 30_000
    assert log.spent(SMALL_MODEL, NOW) == 5_000


def test_a_run_that_fits_has_no_resume_time(tmp_path: Path) -> None:
    log = spend(tmp_path)
    log.add_run(NOW - timedelta(hours=1), "r", {BIG_MODEL: 100_000}, True)

    assert log.resume_time({BIG_MODEL: 100_000}, NOW) is None


def test_resume_is_when_enough_old_spend_ages_out(tmp_path: Path) -> None:
    log = spend(tmp_path)
    first = NOW - timedelta(hours=10)
    second = NOW - timedelta(hours=5)
    log.add_run(first, "a", {BIG_MODEL: 100_000}, True)
    log.add_run(second, "b", {BIG_MODEL: 90_000}, True)

    assert log.resume_time({BIG_MODEL: 50_000}, NOW) == first + timedelta(hours=24)
    assert log.resume_time({BIG_MODEL: 150_000}, NOW) == second + timedelta(hours=24)


def test_groqs_used_figure_replaces_the_logged_total(tmp_path: Path) -> None:
    log = spend(tmp_path)
    log.add_run(NOW - timedelta(hours=2), "r", {BIG_MODEL: 20_000}, True)

    log.add_limit_hit(NOW - timedelta(hours=1), BIG_MODEL, 190_000, 60.0)
    log.add_run(NOW - timedelta(minutes=30), "s", {BIG_MODEL: 1_000}, True)

    assert log.spent(BIG_MODEL, NOW) == 191_000


def test_groqs_wait_time_blocks_until_it_passes(tmp_path: Path) -> None:
    log = spend(tmp_path)

    resume = log.add_limit_hit(NOW, BIG_MODEL, None, 3600.0)

    assert resume == NOW + timedelta(hours=1)
    assert log.resume_time({BIG_MODEL: 1}, NOW) == resume
    assert log.resume_time({BIG_MODEL: 1}, NOW + timedelta(hours=2)) is None


def test_next_run_size_is_the_largest_seen_per_model() -> None:
    records = [
        record(tokens_by_model={BIG_MODEL: 60_000}),
        record(repeat=2, tokens_by_model={BIG_MODEL: 72_000, SMALL_MODEL: 9_000}),
    ]

    assert next_run_tokens(records, {BIG_MODEL, SMALL_MODEL}) == {
        BIG_MODEL: 72_000,
        SMALL_MODEL: 9_000,
    }
    assert next_run_tokens([], {BIG_MODEL}) == {BIG_MODEL: FIRST_RUN_TOKENS}


def test_a_daily_limit_error_reads_groqs_figures() -> None:
    error = daily_limit(used=199_657)

    assert isinstance(error, LLMError)
    assert error.used == 199_657 and error.retry_after == 3600.0 and error.model == BIG_MODEL
    other = DailyLimitError("x", BIG_MODEL, 300.0, "on requests per day (RPD)")
    assert other.used is None


# --- resuming and half-written lines ---------------------------------------------------------


async def test_saved_runs_are_skipped(tmp_path: Path) -> None:
    rig = Rig(tmp_path)

    await rig.run()
    await rig.run()

    assert rig.llms == 1
    assert len(read_jsonl(tmp_path / "default.jsonl")) == 1


def test_a_half_written_last_line_is_removed(tmp_path: Path) -> None:
    path = tmp_path / "default.jsonl"
    append_jsonl(path, {"a": 1})
    with path.open("ab") as f:
        f.write(b'{"a": 2, "half')

    assert read_jsonl(path) == [{"a": 1}]
    assert path.read_bytes().endswith(b"\n")


async def test_a_half_written_run_is_run_again(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    (tmp_path / "default.jsonl").write_bytes(b'{"config": "default", "scen')

    await rig.run()

    assert rig.llms == 1
    assert list(saved_runs(tmp_path / "default.jsonl")) == [("s01", 1, 1)]


async def test_failed_runs_are_saved_and_rerun_only_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = Rig(tmp_path)
    await rig.run()
    path = tmp_path / "default.jsonl"
    row = read_jsonl(path)[0] | {"status": "failed", "error_kind": "timeout", "passed": False}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    await rig.run()
    assert rig.llms == 1

    await rig.run(retry_failed=True)
    assert rig.llms == 2
    assert saved_runs(path)[("s01", 1, 1)].status == "complete"


# --- the budget stop -------------------------------------------------------------------------


async def test_the_budget_stops_cleanly_before_a_run_that_wont_fit(tmp_path: Path) -> None:
    rig = Rig(tmp_path, tier=FREE)
    spend(tmp_path).add_run(NOW - timedelta(hours=1), "earlier", {BIG_MODEL: 190_000}, True)

    assert await rig.run() == 0

    assert rig.llms == 0 and rig.loaded == []
    assert not (tmp_path / "default.jsonl").exists()
    expected = (NOW + timedelta(hours=23)).isoformat()
    assert any(f"resume after {expected}" in line for line in rig.lines)


async def test_the_paid_tier_doesnt_stop_on_the_spend_log_but_still_writes_it(
    tmp_path: Path,
) -> None:
    rig = Rig(tmp_path, tier=PAID)
    spend(tmp_path).add_run(NOW - timedelta(hours=1), "earlier", {BIG_MODEL: 190_000}, True)

    assert await rig.run() == 0

    assert rig.llms == 1
    assert len(read_jsonl(tmp_path / "spend.jsonl")) == 2


async def test_mock_runs_ignore_the_budget_and_leave_the_spend_log_alone(tmp_path: Path) -> None:
    rig = Rig(tmp_path, tier=FREE, mock=True)
    spend(tmp_path).add_run(NOW - timedelta(hours=1), "earlier", {BIG_MODEL: 200_000}, True)

    assert await rig.run() == 0

    assert rig.llms == 1
    assert len(read_jsonl(tmp_path / "spend.jsonl")) == 1
    assert saved_runs(tmp_path / "default-mock.jsonl")[("s01", 1, 1)].mock is True


@pytest.mark.parametrize("tier", [FREE, PAID])
async def test_a_daily_limit_mid_run_throws_the_run_away_and_stops_cleanly(
    tmp_path: Path, tier: Tier
) -> None:
    rig = Rig(tmp_path, tier=tier, script={"assess": [daily_limit()]})

    assert await rig.run() == 0

    assert not (tmp_path / "default.jsonl").exists()
    assert any("thrown away" in line and "resume after" in line for line in rig.lines)
    rows = read_jsonl(tmp_path / "spend.jsonl")
    assert any(r.get("kept") is False for r in rows)
    assert rows[-1]["used"] == 199_000


async def test_a_thrown_away_run_runs_again_on_resume(tmp_path: Path) -> None:
    rig = Rig(tmp_path, script={"assess": [daily_limit()]})
    await rig.run()

    rig.script = None
    rig.env.clock = lambda: NOW + timedelta(hours=2)
    await rig.run()

    assert saved_runs(tmp_path / "default.jsonl")[("s01", 1, 1)].status == "complete"


async def test_after_a_daily_limit_no_more_calls_reach_the_model(tmp_path: Path) -> None:
    rig = Rig(tmp_path, script={"triage": [daily_limit()]})

    await rig.run()

    rows = [r for r in read_jsonl(tmp_path / "spend.jsonl") if "tokens" in r]
    assert rows == []


async def test_when_every_llm_call_fails_nothing_is_saved_and_the_batch_stops(
    tmp_path: Path,
) -> None:
    failing = {
        node: [LLMError("down")]
        for node in (
            "triage",
            "intel",
            "intel_brief",
            "plan",
            "investigate",
            "summarize_findings",
            "review",
            "review_verdict",
            "map_attack",
            "assess",
            "recommend",
            "report_summary",
        )
    }
    rig = Rig(tmp_path, script=failing)

    assert await rig.run() == 1

    assert not (tmp_path / "default.jsonl").exists()


async def test_a_partly_failed_run_is_saved_and_marked(tmp_path: Path) -> None:
    rig = Rig(tmp_path, script={"recommend": [LLMError("down")]})

    await rig.run()

    assert saved_runs(tmp_path / "default.jsonl")[("s01", 1, 1)].llm_failures == 1


# --- variants --------------------------------------------------------------------------------


async def test_each_variant_is_loaded_and_the_seeded_one_restored(tmp_path: Path) -> None:
    rig = Rig(tmp_path)

    await rig.run(variants=(1, 2))

    assert rig.loaded == [1, 2, 1]
    assert set(saved_runs(tmp_path / "default.jsonl")) == {("s01", 1, 1), ("s01", 2, 1)}


async def test_nothing_is_loaded_when_every_run_is_saved(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    await rig.run()
    rig.loaded.clear()

    await rig.run()

    assert rig.loaded == []


# --- the injection scenario stays private -----------------------------------------------------

CANARY = "CANARY-7f3a-text-from-a-restricted-scenario"


def leaks(texts: list[str], outputs: list[str]) -> int:
    """A count, so a failing assert can't print the text it found."""
    return sum(text in output for text in texts for output in outputs)


def everything_written(tmp_path: Path, lines: list[str], capsys: Any, caplog: Any) -> list[str]:
    """Everything a run could have shown. Pytest prints captured output on failure, so it's read
    and cleared here, before any assert."""
    captured = capsys.readouterr()
    logged = caplog.text
    caplog.clear()
    files = [p.read_text(encoding="utf-8") for p in tmp_path.rglob("*") if p.is_file()]
    return [*lines, captured.out, captured.err, logged, *files]


async def test_a_planted_text_never_leaves_an_injection_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    planted = f"cmd /c echo {CANARY} {PLANTED}"
    tree = {
        "untrusted_log_data": {
            "host": "FIN-WS-01",
            "process": {"event_id": TRIGGER, "name": "powershell.exe", "cmdline": planted},
            "ancestors": [],
            "descendants": [],
            "activity": [],
        }
    }
    truth = TRUTH.model_copy(update={"injection": True, "verdict": "malicious"})
    rig = Rig(
        tmp_path,
        truth=truth,
        docs=[process_doc(TRIGGER, planted)],
        results={"get_process_tree": tree},
    )

    await rig.run()
    write_scoreboard(tmp_path, tmp_path)

    written = everything_written(tmp_path, rig.lines, capsys, caplog)
    assert leaks([CANARY, PLANTED[:30]], written) == 0
    saved = saved_runs(tmp_path / "default.jsonl")[("s01", 1, 1)]
    assert saved.injection_flagged is True
    assert saved.missed_techniques == [] and saved.missed_key_events == []
    assert saved.extra_techniques == []


async def test_logging_is_off_during_an_injection_run_and_back_on_after(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    truth = TRUTH.model_copy(update={"injection": True})

    await Rig(tmp_path, truth=truth).run()
    during = len(caplog.records)
    await Rig(tmp_path / "other").run()

    assert during == 0 and len(caplog.records) > 0


async def test_an_exception_in_an_injection_run_prints_no_details(tmp_path: Path) -> None:
    truth = TRUTH.model_copy(update={"injection": True})
    rig = Rig(tmp_path, truth=truth)

    async def broken(_: str) -> Any:
        raise RuntimeError(CANARY)

    rig.env.telemetry.alert = broken

    assert await rig.run() == 1

    assert leaks([CANARY], rig.lines) == 0
    assert any("withheld" in line for line in rig.lines)


def restricted_texts() -> tuple[str, list[str]]:
    """The real scenario's scenario ID and its longer strings, without showing them to anyone."""
    dataset = build_dataset(42, 1)
    result = next(r for r in dataset.scenarios if r.injection)
    texts: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and len(value) >= 20 and not value.startswith("evt_"):
            texts.add(value)

    ids = {e.event_id for e in [*result.events, *result.key_events]}
    for event in dataset.events:
        if event.event_id in ids:
            walk(event.model_dump(mode="json"))
    walk(result.alert.description)
    walk(result.title)
    return result.scenario_id, sorted(texts)


@pytest.mark.mongo
async def test_the_real_injection_scenario_prints_only_metrics(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    scenario, texts = restricted_texts()
    client = telemetry_client()
    try:
        db = telemetry_db(client)
        lines: list[str] = []
        env = Environment(
            telemetry=MongoTelemetry(db),
            tool=partial(call_tool, db=db),
            llm_for=lambda _, alert: mock_model(alert),
            load_variant=lambda _: None,
            truth_for=truth_for,
            runs_dir=tmp_path,
            base_settings=get_settings(),
            tier=PAID,
            mock=True,
            commit="abc1234",
            out=lines.append,
        )
        assert await run_batch(CONFIG, [scenario], [1], 1, env) == 0
    finally:
        await client.close()
    write_scoreboard(tmp_path, tmp_path)

    written = everything_written(tmp_path, lines, capsys, caplog)
    assert texts
    assert leaks(texts, written) == 0
    assert saved_runs(tmp_path / "default-mock.jsonl")[(scenario, 1, 1)].injection_scenario


# --- the mock model --------------------------------------------------------------------------


async def test_the_mock_model_runs_the_whole_chain_and_gets_things_refused(tmp_path: Path) -> None:
    rig = Rig(tmp_path, mock=True)
    rig.env.llm_for = lambda _, alert: mock_model(alert)

    assert await rig.run() == 0

    saved = saved_runs(tmp_path / "default-mock.jsonl")[("s01", 1, 1)]
    assert saved.status == "complete" and saved.llm_failures == 0
    assert saved.validator_refusals == 1 and saved.actions_dropped == 1
    assert saved.findings >= 1 and saved.verdict in ("malicious", "benign", "suspicious")


# --- the report ------------------------------------------------------------------------------


def seeded_runs(tmp_path: Path, name: str, *records: RunRecord) -> None:
    for r in records:
        append_jsonl(tmp_path / f"{name}.jsonl", r.model_dump())


def passed(**fields: Any) -> RunRecord:
    return record(passed=True, verdict="malicious", verdict_correct=True, **fields)


def test_priority_auc_compares_attacks_with_false_alarms() -> None:
    attack = passed(priority="P1")
    harmless = record(scenario="s08", expected_verdict="benign", priority="P4")

    assert priority_auc([attack, harmless]) == 1.0
    assert priority_auc([attack]) is None


def test_aggregates_pool_techniques_and_count_failures(tmp_path: Path) -> None:
    seeded_runs(
        tmp_path,
        "default",
        passed(
            techniques_expected=2,
            techniques_predicted=2,
            technique_credit=1.5,
            key_events=4,
            key_events_cited=2,
            tokens_by_model={BIG_MODEL: 60_000, SMALL_MODEL: 10_000},
            llm_calls=20,
            tool_calls=9,
            seconds=100.0,
            intel=IntelCoverage(tree_indicators=4, looked_up=3, known_bad=2, known_bad_found=1),
        ),
        record(
            scenario="s08",
            expected_verdict="benign",
            verdict="malicious",
            false_alarm=True,
            techniques_predicted=2,
            tokens_by_model={BIG_MODEL: 40_000},
            llm_calls=10,
            tool_calls=1,
            seconds=50.0,
        ),
    )

    config = build_scoreboard(tmp_path)["configs"]["default"]

    assert config["system"]["verdict_accuracy"] == 0.5
    assert config["system"]["false_alarms"] == 1 and config["system"]["benign_runs"] == 1
    assert config["system"]["technique_precision"] == 0.375
    assert config["system"]["technique_recall"] == 0.75
    assert config["system"]["evidence_recall"] == 0.5
    assert config["agents"]["intel_indicator_share"] == 0.75
    assert config["agents"]["intel_known_bad_found"] == 1
    assert config["cost"]["tokens_by_model"] == {BIG_MODEL: 100_000, SMALL_MODEL: 10_000}
    assert config["cost"]["tokens_per_run"] == 55_000
    assert config["cost"]["seconds_per_run"] == 75


def test_the_latest_record_of_a_run_wins(tmp_path: Path) -> None:
    seeded_runs(tmp_path, "default", record(status="failed", error_kind="timeout"), passed())

    assert build_scoreboard(tmp_path)["configs"]["default"]["runs"] == 1
    assert build_scoreboard(tmp_path)["configs"]["default"]["failed_runs"] == 0


def test_the_scoreboard_has_every_table_and_lists_every_failure(tmp_path: Path) -> None:
    seeded_runs(
        tmp_path,
        "default",
        passed(risk_score=73),
        record(
            scenario="s02",
            verdict="benign",
            missed_attack=True,
            techniques_expected=1,
            missed_techniques=["T1003.001"],
        ),
        record(scenario="s03", status="failed", error_kind="timeout"),
        passed(scenario="s04", key_events=10, key_events_cited=1),
        passed(scenario="s05", llm_failures=2),
    )

    text = render_markdown(build_scoreboard(tmp_path))

    for heading in (
        "## Config: default",
        "## Per-scenario pass/fail",
        "## Per agent",
        "## Notes",
    ):
        assert heading in text
    assert "| s01 | PASS, risk 73.0 |" in text
    assert "FAIL default s02 v1 r1: verdict benign, expected malicious. MISSED ATTACK" in text
    assert "T1003.001" in text
    assert "FAIL default s03 v1 r1: the run failed (timeout)" in text
    assert "WEAK default s04 v1 r1" in text and "key events 1/10" in text
    assert "DEGRADED default s05 v1 r1: 2 LLM call(s) failed" in text


def test_mixed_commits_are_called_out(tmp_path: Path) -> None:
    seeded_runs(tmp_path, "default", passed(), passed(scenario="s02", commit="def5678"))

    assert "2 commits" in render_markdown(build_scoreboard(tmp_path))


def test_mock_runs_carry_the_banner_and_real_runs_replace_them(tmp_path: Path) -> None:
    seeded_runs(tmp_path, "default-mock", passed(config="default-mock", mock=True))

    mock_board = build_scoreboard(tmp_path)
    assert mock_board["mock"] is True and "SCRIPTED MODEL" in render_markdown(mock_board)

    seeded_runs(tmp_path, "default", passed())

    real_board = build_scoreboard(tmp_path)
    assert real_board["mock"] is False and list(real_board["configs"]) == ["default"]
    assert "SCRIPTED MODEL" not in render_markdown(real_board)


def test_the_spend_log_is_not_a_config(tmp_path: Path) -> None:
    spend(tmp_path).add_run(NOW, "r", {BIG_MODEL: 1}, True)

    assert build_scoreboard(tmp_path)["configs"] == {}


def test_no_runs_is_an_empty_state_not_an_error(tmp_path: Path) -> None:
    assert "No runs saved yet." in render_markdown(build_scoreboard(tmp_path))


async def test_evals_latest_serves_the_same_scoreboard(tmp_path: Path) -> None:
    seeded_runs(tmp_path / "runs", "default", passed())
    board = write_scoreboard(tmp_path / "runs", tmp_path)
    d, _, _ = deps()
    store = InMemoryStore()
    source = FakeSource([], [ALERT])
    run = Runner(store, source, d.call_tool, d.settings, lambda _: d.llm)
    services = Services(store, source, run, d.settings, tmp_path)
    app: Callable[..., Any] = create_app(lambda: services)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        latest = (await api.get("/evals/latest", params={"kind": "scoreboard"})).json()

    assert latest["scoreboard"]["file"] == "scoreboard.json"
    assert latest["scoreboard"]["results"] == board
