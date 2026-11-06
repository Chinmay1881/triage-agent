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

from app.agent.chain import RunResult, run_case
from app.agent.deps import Deps, MongoTelemetry
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


def print_step(node: str, update: dict[str, Any]) -> None:
    for h in update.get("handoffs", [])[-1:]:
        print(f"--> {h.from_agent} hands off to {h.to_agent} {h.note}".rstrip())
    if node == "sentinel_triage" and update.get("triage"):
        t = update["triage"]
        print(f"[triage] {t.priority} {t.category}: {t.reason}")
        print(f"[triage] budget: {update.get('budget_reason')}")
    elif node == "cyberintel" and update.get("intel_brief"):
        brief = update["intel_brief"]
        print(f"[intel] {len(brief.reputation)} reputation lookups: {brief.assessment}")
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
        print(f"[run_tools] {update.get('tool_calls_used')} tool call(s) used")
    elif node == "check_coverage":
        nudges = update.get("coverage_nudges")
        print(f"[check_coverage] sent back: {nudges[-1]}" if nudges else "[check_coverage] ok")
    elif node == "summarize_findings":
        print(f"[summarize_findings] {len(update.get('findings', []))} finding(s) in total")
    elif node == "reviewer" and update.get("review"):
        r = update["review"]
        print(
            f"[review] confirmed {len(r.confirmed)}, disputed {len(r.disputed)}, "
            f"unreviewed {len(r.unreviewed)}: {r.reason}"
        )


def print_summary(result: RunResult, usage: UsageLog) -> None:
    state = result.state
    print("\nHandoffs:")
    for h in state.handoffs:
        print(f"  {h.ts:%H:%M:%S} {h.from_agent} -> {h.to_agent} {h.note}".rstrip())
    print(f"\nTriage: {state.triage.priority} {state.triage.category}" if state.triage else "")
    print(f"Budget: {state.budget_reason}")
    if state.intel_brief:
        print("\nIntel brief, process chain:")
        for row in state.intel_brief.process_chain:
            print(
                f"  {row['role']:<8} {row['name']} signer={row.get('signer')} "
                f"reputation={row.get('reputation')} [{row.get('event_id')}]"
            )
    print("\nTool calls in order:")
    for agent, records in state.tool_logs.items():
        print(f"  {agent}:")
        for record in records:
            tag = "" if record.source == "llm" else f" [{record.source}]"
            tag += " [default window]" if record.defaulted_window else ""
            tag += " [repeat, from ledger]" if record.repeat_of else ""
            outcome = "ok" if record.ok else f"error: {record.error}"
            print(f"    {record.ref} {short(record.args)}{tag} {outcome}")
    if state.coverage_nudges:
        print(f"Coverage rules triggered: {', '.join(state.coverage_nudges)}")
    print("\nFindings:")
    for f in state.findings:
        why = f" (withheld by {', '.join(f.withheld_by)})" if f.withheld else ""
        dispute = f" DISPUTED: {f.dispute_reason}" if f.status == "disputed" else ""
        print(f"  {f.id} [{f.status}] {f.shown_claim()}{why} [{', '.join(f.citations)}]{dispute}")
    print(f"  ({state.findings_dropped} dropped, {state.citations_removed} citations removed)")
    print("Injection flags:")
    for flag in state.evidence.injection_flags:
        print(f"  - {flag.event_id or '(no event)'} via {flag.method}")
    if not state.evidence.injection_flags:
        print("  none")
    print("\nTokens per agent:")
    for agent, row in usage.by_agent().items():
        print(f"  {agent:<19} {_usage_row(row)}")
    print("Tokens per node (reasoning effort):")
    for node, row in usage.by_node().items():
        print(f"  {node:<19} {row['effort'] or 'default':<7} {_usage_row(row)}")
    print("Tokens per model:")
    for model, row in usage.by_model().items():
        print(f"  {model:<22} {_usage_row(row)}")
    totals = usage.totals()
    print(
        f"\nInvestigator tool calls {state.tool_calls_used}/{state.investigator_budget}, reviewer "
        f"{state.review_calls_used}, LLM calls {totals['llm_calls']}, tokens "
        f"{totals['total_tokens']}, billed against limits {totals['billed_tokens']}, "
        f"{result.seconds:.0f}s, stop: {state.stop_reason}"
        + (" (timed out)" if result.timed_out else "")
    )


def _usage_row(row: dict[str, Any]) -> str:
    rejected = f" ({row['rejected_calls']} rejected)" if row["rejected_calls"] else ""
    return (
        f"{row['calls']:>2} call(s){rejected}, in {row['input_tokens']} "
        f"(cached {row['cached_tokens']}), out {row['output_tokens']}, "
        f"billed {row['billed_tokens']}"
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
        print(f"Investigating {alert.alert_id}: {alert.rule} on {alert.host} ({alert.severity})")
        result = await run_case(deps, alert, print_step)
    finally:
        await client.close()
    print_summary(result, llm.usage)
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
