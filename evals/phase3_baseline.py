"""The single-agent Phase 3 baseline: s01 and s08 on gpt-oss-120b, the "before" in the
before/after comparison with the four-agent structure of Phase 3b.

    uv run --project backend python evals/phase3_baseline.py --commit <sha of the code under test>

Runs only these two scenarios and writes evals/results/phase3_single_agent_baseline.json: tool
calls in order, findings with event IDs (withheld claims stay withheld), injection flags as
event ID and method only, tokens per node and per call, LLM calls and duration.
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

from app.agent.graph import MongoTelemetry, RunResult, run_investigation  # noqa: E402
from app.agent.nodes import Deps  # noqa: E402
from app.cli import print_step, print_summary  # noqa: E402
from app.config import Settings, get_settings  # noqa: E402
from app.llm import UsageLog, get_model  # noqa: E402
from app.telemetry.db import telemetry_client, telemetry_db  # noqa: E402
from app.tools import call_tool  # noqa: E402
from evals.common import RESULTS, eval_week  # noqa: E402

SCENARIOS = ("s01", "s08")
MODEL = "openai/gpt-oss-120b"
OUTPUT = RESULTS / "phase3_single_agent_baseline.json"


def run_record(
    scenario_id: str, alert_id: str, result: RunResult, usage: UsageLog, budget: int
) -> dict[str, Any]:
    state = result.state
    return {
        "scenario": scenario_id,
        "alert_id": alert_id,
        "stop_reason": state.stop_reason,
        "timed_out": result.timed_out,
        "duration_s": round(result.seconds, 1),
        "tool_budget": budget,
        "tool_calls_used": state.tool_calls_used,
        "tool_calls": [r.model_dump() for r in state.tool_log],
        "coverage_nudges": state.coverage_nudges,
        "critic_reopened": state.reopened,
        "findings": [
            {
                "claim": f.shown_claim(),
                "event_ids": f.event_ids,
                "tool": f.tool,
                "withheld_by": f.withheld_by,
            }
            for f in state.findings
        ],
        "findings_dropped": state.findings_dropped,
        "injection_flags": [
            {"event_id": f.event_id, "method": f.method} for f in state.injection_flags
        ],
        "tokens": usage.totals(),
        "tokens_per_node": usage.by_node(),
        "llm_calls": [asdict(c) for c in usage.calls],
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
        seen_records = [0]
        print(f"\n=== {scenario_id} {alert_id}: {alert.rule} on {alert.host}")
        result = await run_investigation(
            deps, alert, lambda node, update: print_step(node, update, seen_records)
        )
    finally:
        await client.close()
    print_summary(result, llm.usage, settings.tool_budget)
    return run_record(scenario_id, alert_id, result, llm.usage, settings.tool_budget)


async def main_async(commit: str) -> int:
    settings = get_settings()
    if settings.llm_model != MODEL:
        print(f"error: baseline must run on {MODEL}, not {settings.llm_model}", file=sys.stderr)
        return 1
    scenarios = {r.scenario_id: r.alert.alert_id for r in eval_week().scenarios}
    runs = [await run_one(s, scenarios[s], settings) for s in SCENARIOS]
    report = {
        "description": "single-agent Phase 3 baseline, before the Phase 3b restructure",
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "code_commit": commit,
        "model": settings.llm_model,
        "reasoning_effort": settings.llm_reasoning_effort,
        "runs": runs,
    }
    text = json.dumps(report, indent=2, default=str, ensure_ascii=False) + "\n"
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"\nwrote {OUTPUT}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Single-agent baseline on s01 and s08")
    parser.add_argument("--commit", required=True, help="commit of the code under test")
    args = parser.parse_args()
    # Model text can contain characters the Windows console code page can't encode.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return asyncio.run(main_async(args.commit))


if __name__ == "__main__":
    sys.exit(main())
