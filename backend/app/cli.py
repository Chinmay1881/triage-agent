"""Run one investigation in the terminal.

    uv run python -m app.cli investigate --alert alt_0001

Prints each step as it happens, then the findings, the injection flags (event ID and method
only, never the flagged text), tool calls, LLM calls, tokens and duration.

Alerts listed in data/generated/cli_blocklist.json (the prompt-injection scenario, written by
the generator) are refused: they are run only through the eval harness, so their log text is
never printed during development. Only this module reads that file; the agent and the tools
never do (tests/test_app_isolation.py).
"""

import argparse
import asyncio
import io
import json
import logging
import re
import sys
from functools import partial
from pathlib import Path
from typing import Any

from pymongo.errors import ServerSelectionTimeoutError

from app.agent.graph import MongoTelemetry, RunResult, run_investigation
from app.agent.nodes import Deps
from app.agent.state import ToolCallRecord
from app.config import get_settings
from app.llm import LLMError, UsageLog, get_model
from app.ml import ModelMissingError
from app.telemetry.db import telemetry_client, telemetry_db
from app.tools import call_tool

BLOCKLIST = Path(__file__).resolve().parents[2] / "data" / "generated" / "cli_blocklist.json"
ALERT_ID = re.compile(r"^alt_\d{4}$")
ARGS_CHARS = 120


def blocked_alerts(path: Path) -> set[str] | None:
    """Alert IDs to refuse, or None if the blocklist hasn't been generated yet."""
    if not path.exists():
        return None
    return set(json.loads(path.read_text(encoding="utf-8"))["alert_ids"])


def refusal(alert_id: str, path: Path | None = None) -> str | None:
    path = path or BLOCKLIST
    blocked = blocked_alerts(path)
    if blocked is None:
        return f"{path} is missing; run `python tasks.py seed` first"
    if alert_id in blocked:
        return (
            f"{alert_id} is reserved for the eval harness (evals/, Phase 5); the CLI never runs "
            "or prints it during development"
        )
    return None


def short(value: Any, limit: int = ARGS_CHARS) -> str:
    text = json.dumps(value, separators=(",", ":"), default=str, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def print_step(node: str, update: dict[str, Any], seen_records: list[int]) -> None:
    if node == "ingest":
        triggers = len(update.get("trigger_events", []))
        flags = len(update.get("injection_flags", []))
        print(f"[ingest] {triggers} trigger event(s), {flags} injection flag(s)")
    elif node == "plan":
        print("[plan]")
        for h in update.get("hypotheses", []):
            print(f"  {h.kind:<9} {h.statement}")
        for check in update.get("first_checks", []):
            print(f"  check: {check}")
    elif node == "investigate":
        for message in update.get("messages", []):
            for call in message.tool_calls:
                print(f"[investigate] -> {call['name']}({short(call['args'])})")
            if not message.tool_calls:
                print("[investigate] done calling tools")
        if update.get("stop_reason") in ("budget", "llm_error"):
            print(f"[investigate] stopped: {update['stop_reason']}")
    elif node == "run_tools":
        records: list[ToolCallRecord] = update.get("tool_log", [])
        for record in records[seen_records[0] :]:
            outcome = f"{record.event_ids} event id(s)" if record.ok else f"error: {record.error}"
            print(f"[run_tools] {record.name}: {outcome}")
        seen_records[0] = len(records)
        print(f"[run_tools] {update.get('tool_calls_used')} tool call(s) used")
    elif node == "check_coverage":
        nudges = update.get("coverage_nudges")
        print(f"[check_coverage] sent back: {nudges[-1]}" if nudges else "[check_coverage] ok")
    elif node == "summarize_findings":
        if "findings" in update:
            print(f"[summarize_findings] {len(update['findings'])} finding(s) in total")
        else:
            print("[summarize_findings] no new findings")
    elif node == "critic":
        review = update.get("critic")
        if review is not None:
            action = "reopen" if update.get("reopened") else "conclude"
            print(f"[critic] {action}: {review.reason}")


def print_summary(result: RunResult, usage: UsageLog, budget: int) -> None:
    state = result.state
    print("\nTool calls in order:")
    for i, record in enumerate(state.tool_log, start=1):
        outcome = "ok" if record.ok else "error"
        print(f"  {i:>2}. {record.name}({short(record.args)}) {outcome}")
    if state.coverage_nudges:
        print(f"Coverage rules triggered: {', '.join(state.coverage_nudges)}")
    print("\nFindings:")
    for f in state.findings:
        why = f" (by {', '.join(f.withheld_by)})" if f.withheld else ""
        print(f"  - {f.shown_claim()}{why} [{', '.join(f.event_ids)}]")
    if state.findings_dropped:
        print(f"  ({state.findings_dropped} finding(s) dropped for citing unseen event IDs)")
    print("Injection flags:")
    for flag in state.injection_flags:
        print(f"  - {flag.event_id or '(no event)'} via {flag.method}")
    if not state.injection_flags:
        print("  none")
    print("\nLLM calls per node (reasoning effort):")
    for node, row in usage.by_node().items():
        print(
            f"  {node:<19} {row['effort'] or 'default':<7} {row['calls']:>2} call(s), "
            f"in {row['input_tokens']}, out {row['output_tokens']}"
        )
    totals = usage.totals()
    print(
        f"\nTool calls {state.tool_calls_used}/{budget}, LLM calls {totals['llm_calls']}, "
        f"tokens {totals['total_tokens']} (in {totals['input_tokens']}, out "
        f"{totals['output_tokens']}), {result.seconds:.0f}s, stop: {state.stop_reason}"
        + (" (timed out)" if result.timed_out else "")
    )


async def investigate(alert_id: str) -> int:
    settings = get_settings()
    llm = get_model(settings)
    client = telemetry_client()
    try:
        db = telemetry_db(client)
        telemetry = MongoTelemetry(db)
        alert = await telemetry.alert(alert_id)
        if alert is None:
            print(f"error: no alert {alert_id}", file=sys.stderr)
            return 1
        deps = Deps(llm, telemetry, partial(call_tool, db=db), settings)
        seen_records = [0]
        print(f"Investigating {alert.alert_id}: {alert.rule} on {alert.host} ({alert.severity})")
        result = await run_investigation(
            deps, alert, lambda node, update: print_step(node, update, seen_records)
        )
    finally:
        await client.close()
    print_summary(result, llm.usage, settings.tool_budget)
    return 2 if result.timed_out else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("investigate", help="run one investigation")
    run.add_argument("--alert", required=True, help="alert ID, e.g. alt_0001")
    args = parser.parse_args()
    # Model text can contain characters the Windows console code page can't encode.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")

    if not ALERT_ID.match(args.alert):
        parser.error("--alert must look like alt_0001")
    reason = refusal(args.alert)
    if reason is not None:
        print(f"refused: {reason}", file=sys.stderr)
        return 3
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        return asyncio.run(investigate(args.alert))
    except (LLMError, ModelMissingError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ServerSelectionTimeoutError:
        print("error: MongoDB not reachable; run `python tasks.py up`", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
