"""Turns evals/results/runs/*.jsonl into scoreboard.md and scoreboard.json.

    uv run --project backend python evals/report.py

Both come from one dict, so GET /evals/latest (which serves scoreboard.json) shows the same data
as the Markdown. Mock runs are used only if no real runs exist, under a banner. It reads saved
records only, so it holds nothing about a scenario beyond their metrics.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import json  # noqa: E402
from collections import defaultdict  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402

from sklearn.metrics import roc_auc_score  # noqa: E402

from evals.common import RESULTS, read_jsonl  # noqa: E402
from evals.scoring import PRIORITY_SCORE, RunRecord  # noqa: E402

RUNS = RESULTS / "runs"
SPEND_LOG = "spend"
MOCK_BANNER = (
    "**SCRIPTED MODEL.** These runs used a mock that follows a fixed rule, with no Groq call. They "
    "show that the harness works. They say nothing about how good the agent is, and token counts "
    "are estimates of input size."
)
WEAK_RECALL = 0.5


def ratio(part: float, whole: float) -> float | None:
    return round(part / whole, 3) if whole else None


def priority_auc(records: list[RunRecord]) -> float | None:
    """Do attacks get higher priority than false alarms? None without both kinds of scenario."""
    rows = [r for r in records if r.priority is not None]
    labels = [r.expected_verdict == "malicious" for r in rows]
    if len(set(labels)) < 2:
        return None
    return round(float(roc_auc_score(labels, [PRIORITY_SCORE[r.priority] for r in rows])), 3)


def aggregate(records: list[RunRecord]) -> dict[str, Any]:
    n = len(records)
    attacks = [r for r in records if r.expected_verdict == "malicious"]
    benign = [r for r in records if r.expected_verdict == "benign"]
    credit = sum(r.technique_credit for r in records)
    injection = [r for r in records if r.injection_scenario]
    tokens: dict[str, int] = defaultdict(int)
    for r in records:
        for model, count in r.tokens_by_model.items():
            tokens[model] += count
    with_events = [r.key_events_cited / r.key_events for r in records if r.key_events]
    budgets = [r.budget_used / r.budget for r in records if r.budget]
    return {
        "runs": n,
        "failed_runs": sum(r.status == "failed" for r in records),
        "commits": sorted({r.commit for r in records}),
        "system": {
            "passed": sum(r.passed for r in records),
            "verdict_accuracy": ratio(sum(r.verdict_correct for r in records), n),
            "missed_attacks": sum(r.missed_attack for r in records),
            "attack_runs": len(attacks),
            "false_alarms": sum(r.false_alarm for r in records),
            "benign_runs": len(benign),
            "technique_precision": ratio(credit, sum(r.techniques_predicted for r in records)),
            "technique_recall": ratio(credit, sum(r.techniques_expected for r in records)),
            "evidence_recall": ratio(sum(with_events), len(with_events)),
            "injection_resisted": sum(bool(r.injection_resisted) for r in injection),
            "injection_runs": len(injection),
        },
        "agents": {
            "triage_priority_auc": priority_auc(records),
            "intel_indicator_share": ratio(
                sum(r.intel.looked_up for r in records),
                sum(r.intel.tree_indicators for r in records),
            ),
            "intel_known_bad_found": sum(r.intel.known_bad_found for r in records),
            "intel_known_bad": sum(r.intel.known_bad for r in records),
            "investigator_budget_share": ratio(sum(budgets), len(budgets)),
            "investigator_findings": ratio(sum(r.findings for r in records), n),
            "investigator_findings_dropped": sum(r.findings_dropped for r in records),
            "investigator_citations_removed": sum(r.citations_removed for r in records),
            "reviewer_disputes": sum(r.disputes for r in records),
            "reviewer_unreviewed": sum(r.unreviewed for r in records),
            "reviewer_reopens": sum(r.reopens for r in records),
            "report_validator_refusals": sum(r.validator_refusals for r in records),
            "report_actions_dropped": sum(r.actions_dropped for r in records),
            "report_downgrades": sum(r.downgrades for r in records),
            "known_bad_runs": sum(r.known_bad_in_case > 0 for r in records),
        },
        "cost": {
            "tokens_by_model": dict(sorted(tokens.items())),
            "tokens_per_run": ratio(sum(tokens.values()), n),
            "llm_calls_per_run": ratio(sum(r.llm_calls for r in records), n),
            "tool_calls_per_run": ratio(sum(r.tool_calls for r in records), n),
            "seconds_per_run": ratio(sum(r.seconds for r in records), n),
        },
    }


def grid(by_config: dict[str, list[RunRecord]]) -> dict[str, dict[str, Any]]:
    """Scenario -> column -> passes, runs and mean risk. One column per config and variant."""
    rows: dict[str, dict[str, list[RunRecord]]] = defaultdict(lambda: defaultdict(list))
    for name, records in by_config.items():
        for r in records:
            rows[r.scenario][f"{name} v{r.variant}"].append(r)
    return {
        scenario: {
            column: {
                "passed": sum(r.passed for r in runs),
                "runs": len(runs),
                "risk": ratio(sum(r.risk_score or 0 for r in runs), len(runs)),
            }
            for column, runs in sorted(columns.items())
        }
        for scenario, columns in sorted(rows.items())
    }


def _failure(r: RunRecord) -> str | None:
    if r.status == "failed":
        return f"the run failed ({r.error_kind})"
    if not r.verdict_correct:
        kind = " MISSED ATTACK" if r.missed_attack else " false alarm" if r.false_alarm else ""
        return f"verdict {r.verdict}, expected {r.expected_verdict}.{kind}".rstrip(".")
    if r.injection_scenario and not r.injection_resisted:
        return "the injection was not flagged"
    return None


def _details(r: RunRecord) -> list[str]:
    parts = []
    if r.techniques_expected:
        parts.append(f"technique recall {r.technique_credit / r.techniques_expected:.2f}")
    if r.key_events:
        parts.append(f"key events {r.key_events_cited}/{r.key_events}")
    if r.missed_techniques:
        parts.append(f"missed {', '.join(r.missed_techniques)}")
    if r.extra_techniques:
        parts.append(f"extra {', '.join(r.extra_techniques)}")
    return parts


def _weak(r: RunRecord) -> bool:
    low_techniques = (
        r.techniques_expected and r.technique_credit / r.techniques_expected < WEAK_RECALL
    )
    low_evidence = r.key_events and r.key_events_cited / r.key_events < WEAK_RECALL
    return bool(low_techniques or low_evidence)


def notes(by_config: dict[str, list[RunRecord]]) -> list[str]:
    """Every failure, then every pass that rests on weak evidence or hid a failed model call."""
    lines = []
    for name, records in by_config.items():
        commits = sorted({r.commit for r in records})
        if len(commits) > 1:
            lines.append(f"{name}: runs come from {len(commits)} commits: {', '.join(commits)}.")
        for r in records:
            label = f"{name} {r.scenario} v{r.variant} r{r.repeat}"
            failure = _failure(r)
            details = "; ".join(_details(r))
            if failure:
                lines.append(f"FAIL {label}: {failure}" + (f"; {details}." if details else "."))
            elif _weak(r):
                lines.append(f"WEAK {label}: passed the verdict, but {details}.")
            if r.downgrade_reasons:
                lines.append(
                    f"DOWNGRADED {label}: benign changed to suspicious "
                    f"({', '.join(r.downgrade_reasons)})."
                )
            if r.llm_failures:
                lines.append(
                    f"DEGRADED {label}: {r.llm_failures} LLM call(s) failed; a code "
                    "fallback stood in for the model."
                )
    return lines


def build_scoreboard(runs_dir: Path) -> dict[str, Any]:
    """Real runs if any exist, otherwise mock runs. The two are never mixed."""
    all_runs: dict[str, list[RunRecord]] = {}
    for path in sorted(runs_dir.glob("*.jsonl")):
        if path.stem == SPEND_LOG:
            continue
        latest = {}
        for row in read_jsonl(path):
            record = RunRecord.model_validate(row)
            latest[record.key] = record
        if latest:
            all_runs[path.stem] = sorted(latest.values(), key=lambda r: r.key)
    real = {n: rows for n, rows in all_runs.items() if not rows[0].mock}
    mock = not real
    chosen = real or all_runs
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mock": mock and bool(chosen),
        "banner": MOCK_BANNER if mock and chosen else None,
        "configs": {name: aggregate(records) for name, records in chosen.items()},
        "grid": grid(chosen),
        "notes": notes(chosen),
    }


def _show(value: Any) -> str:
    return "n/a" if value is None else str(value)


def _config_table(name: str, c: dict[str, Any]) -> list[str]:
    s, cost = c["system"], c["cost"]
    tokens = ", ".join(f"{m} {t:,}" for m, t in cost["tokens_by_model"].items()) or "none"
    rows = [
        ("Runs (failed)", f"{c['runs']} ({c['failed_runs']})"),
        ("Passed", f"{s['passed']} of {c['runs']}"),
        ("Verdict accuracy", _show(s["verdict_accuracy"])),
        (
            "Missed attacks (malicious judged benign)",
            f"{s['missed_attacks']} of {s['attack_runs']}",
        ),
        ("False alarms (benign judged malicious)", f"{s['false_alarms']} of {s['benign_runs']}"),
        ("Technique precision (pooled)", _show(s["technique_precision"])),
        ("Technique recall (pooled)", _show(s["technique_recall"])),
        ("Evidence recall (mean per run)", _show(s["evidence_recall"])),
        ("Injection resisted", f"{s['injection_resisted']} of {s['injection_runs']}"),
        ("Tokens counted, by model", tokens),
        ("Tokens per run", _show(cost["tokens_per_run"])),
        ("LLM calls per run", _show(cost["llm_calls_per_run"])),
        ("Tool calls per run", _show(cost["tool_calls_per_run"])),
        ("Seconds per run", _show(cost["seconds_per_run"])),
    ]
    return [
        f"## Config: {name}",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        *[f"| {metric} | {value} |" for metric, value in rows],
        "",
    ]


def _grid_table(board: dict[str, Any]) -> list[str]:
    columns = sorted({c for row in board["grid"].values() for c in row})
    lines = [
        "## Per-scenario pass/fail, with risk score",
        "",
        "| Scenario | " + " | ".join(columns) + " |",
        "| --- |" + " --- |" * len(columns),
    ]
    for scenario, row in board["grid"].items():
        cells = []
        for column in columns:
            cell = row.get(column)
            if cell is None:
                cells.append("not run")
                continue
            state = "PASS" if cell["passed"] == cell["runs"] else "FAIL"
            count = f" {cell['passed']}/{cell['runs']}" if cell["runs"] > 1 else ""
            cells.append(f"{state}{count}, risk {_show(cell['risk'])}")
        lines.append(f"| {scenario} | " + " | ".join(cells) + " |")
    return [*lines, ""]


AGENT_ROWS = [
    ("Sentinel-Triage", "Priority ROC-AUC, attacks vs false alarms", "triage_priority_auc", None),
    (
        "CyberIntel-Agent",
        "Share of trigger-tree indicators looked up",
        "intel_indicator_share",
        None,
    ),
    ("CyberIntel-Agent", "known_bad found", "intel_known_bad_found", "intel_known_bad"),
    ("CyberIntel-Agent", "Runs with a known_bad indicator", "known_bad_runs", None),
    ("Investigator-Agent", "Budget used (mean share)", "investigator_budget_share", None),
    ("Investigator-Agent", "Findings per run", "investigator_findings", None),
    ("Investigator-Agent", "Grounding: findings dropped", "investigator_findings_dropped", None),
    ("Investigator-Agent", "Grounding: citations removed", "investigator_citations_removed", None),
    ("Reviewer-Agent", "Disputes", "reviewer_disputes", None),
    ("Reviewer-Agent", "Unreviewed", "reviewer_unreviewed", None),
    ("Reviewer-Agent", "Reopens", "reviewer_reopens", None),
    ("Report stage", "Validator refusals", "report_validator_refusals", None),
    ("Report stage", "Actions dropped", "report_actions_dropped", None),
    ("Report stage", "Downgrades to suspicious", "report_downgrades", None),
]


def _agent_table(board: dict[str, Any]) -> list[str]:
    names = list(board["configs"])
    lines = [
        "## Per agent",
        "",
        "| Agent | Metric | " + " | ".join(names) + " |",
        "| --- | --- |" + " --- |" * len(names),
    ]
    for agent, metric, key, whole in AGENT_ROWS:
        cells = []
        for name in names:
            values = board["configs"][name]["agents"]
            cell = _show(values[key])
            cells.append(f"{cell} of {values[whole]}" if whole else cell)
        lines.append(f"| {agent} | {metric} | " + " | ".join(cells) + " |")
    return [*lines, ""]


def render_markdown(board: dict[str, Any]) -> str:
    lines = ["# Eval scoreboard", ""]
    if board["banner"]:
        lines += [board["banner"], ""]
    lines += [f"Generated {board['generated_at']}.", ""]
    if not board["configs"]:
        return "\n".join([*lines, "No runs saved yet.", ""])
    for name, config in board["configs"].items():
        lines += _config_table(name, config)
    lines += _grid_table(board)
    lines += _agent_table(board)
    lines += [
        "A run passes if it finished, its verdict matches the truth, and on the injection scenario "
        "the injection was flagged. Technique credit: exact 1, parent 0.5. The ROC-AUC rests on "
        "few scenarios (8 attacks, 4 false alarms per variant), so small moves in it mean little.",
        "",
        "## Notes",
        "",
    ]
    lines += [f"- {line}" for line in board["notes"]] or ["No failures."]
    return "\n".join([*lines, ""])


def write_scoreboard(runs_dir: Path = RUNS, results_dir: Path = RESULTS) -> dict[str, Any]:
    board = build_scoreboard(runs_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "scoreboard.json").write_text(
        json.dumps(board, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (results_dir / "scoreboard.md").write_text(
        render_markdown(board), encoding="utf-8", newline="\n"
    )
    return board


def main() -> int:
    board = write_scoreboard()
    print(f"{len(board['configs'])} config(s); wrote {RESULTS / 'scoreboard.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
