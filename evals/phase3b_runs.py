"""The four-agent chain on s01 and s08, saved for the comparison with the single-agent baseline
(evals/results/phase3_single_agent_baseline.json, from commit ae91d07).

    uv run --project backend python evals/phase3b_runs.py --label smoke_20b --commit <sha>

Runs only these two scenarios and writes evals/results/phase3b_<label>.json. The models come from
settings, so LLM_MODEL=openai/gpt-oss-20b gives the smoke test without touching .env.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import argparse  # noqa: E402
import asyncio  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
from dataclasses import asdict  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from functools import partial  # noqa: E402
from typing import Any  # noqa: E402

from app.agent.agents.common import INTEL_TOOLS, INVESTIGATOR_TOOLS  # noqa: E402
from app.agent.chain import RunResult, run_case  # noqa: E402
from app.agent.deps import Deps, MongoTelemetry  # noqa: E402
from app.cli import print_step, print_summary  # noqa: E402
from app.config import (  # noqa: E402
    CYBERINTEL,
    INVESTIGATOR,
    REVIEWER,
    SENTINEL_TRIAGE,
    Settings,
    get_settings,
)
from app.llm import UsageLog, get_model  # noqa: E402
from app.telemetry.db import telemetry_client, telemetry_db  # noqa: E402
from app.tools import call_tool, tool_specs  # noqa: E402
from app.tools._common import estimate_tokens  # noqa: E402
from evals.common import RESULTS, eval_week  # noqa: E402

SCENARIOS = ("s01", "s08")


def run_record(
    scenario_id: str, alert_id: str, result: RunResult, usage: UsageLog
) -> dict[str, Any]:
    state = result.state
    return {
        "scenario": scenario_id,
        "alert_id": alert_id,
        "stop_reason": state.stop_reason,
        "timed_out": result.timed_out,
        "duration_s": round(result.seconds, 1),
        "handoffs": [h.model_dump() for h in state.handoffs],
        "triage": state.triage.model_dump() if state.triage else None,
        "investigator_budget": state.investigator_budget,
        "budget_reason": state.budget_reason,
        "tool_calls_used": state.tool_calls_used,
        "review_calls_used": state.review_calls_used,
        "intel_brief": state.intel_brief.model_dump() if state.intel_brief else None,
        "tool_logs": {a: [r.model_dump() for r in rows] for a, rows in state.tool_logs.items()},
        "coverage_nudges": state.coverage_nudges,
        "reopened": state.reopened,
        "findings": [
            {
                "id": f.id,
                "claim": f.shown_claim(),
                "kind": f.kind,
                "citations": f.citations,
                "status": f.status,
                "dispute_reason": f.dispute_reason,
                "withheld_by": f.withheld_by,
            }
            for f in state.findings
        ],
        "reportable_findings": [f.id for f in state.reportable_findings()],
        "findings_dropped": state.findings_dropped,
        "citations_removed": state.citations_removed,
        "review": state.review.model_dump() if state.review else None,
        "injection_flags": [
            {"event_id": f.event_id, "method": f.method} for f in state.evidence.injection_flags
        ],
        "tokens": usage.totals(),
        "tokens_per_agent": usage.by_agent(),
        "tokens_per_node": usage.by_node(),
        "tokens_per_model": usage.by_model(),
        "llm_calls": [asdict(c) | {"agent": c.agent} for c in usage.calls],
    }


async def run_one(scenario_id: str, alert_id: str, settings: Settings) -> dict[str, Any]:
    llm = get_model(settings)
    client = telemetry_client()
    try:
        db = telemetry_db(client)
        telemetry = MongoTelemetry(db)
        alert = await telemetry.alert(alert_id)
        if alert is None:
            raise RuntimeError(f"no alert {alert_id}; run `python tasks.py seed`")
        deps = Deps(llm, telemetry, partial(call_tool, db=db), settings)
        print(f"\n=== {scenario_id} {alert_id}: {alert.rule} on {alert.host}")
        result = await run_case(deps, alert, print_step)
    finally:
        await client.close()
    print_summary(result, llm.usage)
    return run_record(scenario_id, alert_id, result, llm.usage)


async def main_async(label: str, commit: str) -> int:
    settings = get_settings()
    scenarios = {r.scenario_id: r.alert.alert_id for r in eval_week().scenarios}
    runs = [await run_one(s, scenarios[s], settings) for s in SCENARIOS]
    report = {
        "description": f"four-agent chain, {label}",
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "code_commit": commit,
        "models": {
            agent: settings.agent_models.get(agent, settings.llm_model)
            for agent in (SENTINEL_TRIAGE, CYBERINTEL, INVESTIGATOR, REVIEWER)
        },
        "reasoning_effort": settings.llm_reasoning_effort,
        "tool_schema_tokens_per_call": {
            "before_all_12": estimate_tokens(tool_specs()),
            "investigator_and_reviewer": estimate_tokens(tool_specs(INVESTIGATOR_TOOLS)),
            "cyberintel": estimate_tokens(tool_specs(INTEL_TOOLS)),
        },
        "runs": runs,
    }
    path = RESULTS / f"phase3b_{label}.json"
    text = json.dumps(report, indent=2, default=str, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"\nwrote {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="The four-agent chain on s01 and s08")
    parser.add_argument("--label", required=True, help="names the results file")
    parser.add_argument("--commit", required=True, help="commit of the code under test")
    args = parser.parse_args()
    # Model text can contain characters the Windows console code page can't encode.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return asyncio.run(main_async(args.label, args.commit))


if __name__ == "__main__":
    sys.exit(main())
