"""Sentinel-Triage: how urgent is this alert, and how much investigation does it get?

Code scores the trigger events and scans them for injection; one structured call (no data tools)
sets priority, category and a reason. The priority sets the investigator's tool budget, which is
how triage changes routing. If the call fails, the alert's severity gives the priority: a broken
triage must not stop an investigation.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from app.agent.agents.common import alert_block, handoff, to_json, with_records
from app.agent.case import Case, Category, Priority, TriageDecision, TriageDraft
from app.agent.deps import Deps
from app.agent.injection import scan
from app.agent.prompts.system import SYSTEM
from app.agent.prompts.triage import TRIAGE
from app.agent.toolrun import run_call
from app.config import CYBERINTEL, SENTINEL_TRIAGE
from app.llm import LLMError
from app.telemetry.decode import decode_encoded_command
from app.tools._common import cap_text, iso
from app.tools.process import process_row

log = logging.getLogger(__name__)

MAX_SCORED = 10
SEVERITY_PRIORITY: dict[str, Priority] = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}
EVENT_CATEGORY: dict[str, Category] = {
    "logon": "identity",
    "network_conn": "network",
    "dns_query": "network",
    "file_write": "data",
}


def trigger_row(doc: dict[str, Any]) -> dict[str, Any]:
    if doc["event_type"] == "process_start":
        return process_row(doc) | {"host": doc["host"], "event_type": "process_start"}
    row: dict[str, Any] = {
        "event_id": doc["event_id"],
        "ts": iso(doc["ts"]),
        "host": doc["host"],
        "user": doc.get("user"),
        "event_type": doc["event_type"],
    }
    for key in ("process", "network", "dns", "logon", "file", "task", "access"):
        if doc.get(key):
            row[key] = {k: cap_text(v) if isinstance(v, str) else v for k, v in doc[key].items()}
    return row


def trigger_flags(docs: list[dict[str, Any]]) -> list[Any]:
    """Scan the full command line and its decoded form, before the 300-character cap."""
    flags = []
    for doc in docs:
        cmdline = (doc.get("process") or {}).get("cmdline")
        if not cmdline:
            continue
        fields = {"cmdline": cmdline}
        decoded = decode_encoded_command(cmdline)
        if decoded is not None:
            fields["decoded_cmdline"] = decoded
        flags += [
            flag.model_copy(update={"field": f"trigger_events.{flag.field}"})
            for flag in scan(fields, event_id=doc["event_id"])
        ]
    return flags


def fallback_decision(severity: str, event_types: list[str]) -> TriageDraft:
    return TriageDraft(
        priority=SEVERITY_PRIORITY.get(severity, "P2"),
        category=next((EVENT_CATEGORY[t] for t in event_types if t in EVENT_CATEGORY), "endpoint"),
        reason="Set from the alert's severity: the triage call failed.",
    )


def anomaly_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = result.get("untrusted_log_data") or []
    return [
        {
            "event_id": r["event_id"],
            "score": r.get("score"),
            "percentile": r.get("percentile"),
            "stood_out": [s["feature"] for s in r.get("stood_out", [])],
        }
        for r in rows
        if "score" in r
    ]


def make_triage(deps: Deps) -> Callable[[Case], Awaitable[dict[str, Any]]]:
    async def triage(state: Case) -> dict[str, Any]:
        alert = state.alert
        evidence = state.evidence.model_copy(deep=True)
        docs = await deps.telemetry.events(alert.trigger_event_ids)
        for doc in docs:
            evidence.seen_event_ids.setdefault(doc["event_id"], "alert")
        evidence.injection_flags += trigger_flags(docs)
        evidence.injection_flags += scan({"description": alert.description}, "alert")

        scored, record = await run_call(
            deps,
            evidence,
            SENTINEL_TRIAGE,
            frozenset({"score_anomaly"}),
            alert,
            "score_anomaly",
            {"event_ids": alert.trigger_event_ids[:MAX_SCORED]},
            source="code",
        )
        anomaly = anomaly_rows(scored)
        rows = [trigger_row(d) for d in docs]
        flags = [{"event_id": f.event_id, "method": f.method} for f in evidence.injection_flags]
        prompt = {
            "alert": alert_block(alert),
            "injection_flags": flags,
            "untrusted_log_data": {
                "alert_description": alert.description,
                "trigger_events": rows,
                "anomaly": anomaly,
            },
        }
        messages = [SystemMessage(f"{SYSTEM}\n\n{TRIAGE}"), HumanMessage(to_json(prompt))]
        try:
            draft = await deps.llm.invoke_structured("triage", messages, TriageDraft)
        except LLMError as exc:
            log.warning("triage failed, using the alert's severity: %s", exc)
            draft = fallback_decision(alert.severity, [d["event_type"] for d in docs])

        budget = deps.settings.investigator_budgets[draft.priority]
        reason = f"{draft.priority} from {SENTINEL_TRIAGE}: {budget} tool calls"
        log.info("investigator budget: %s", reason)
        return {
            "trigger_events": rows,
            "evidence": evidence,
            "triage": TriageDecision(
                priority=draft.priority,
                category=draft.category,
                reason=draft.reason,
                anomaly=anomaly,
            ),
            "investigator_budget": budget,
            "budget_reason": reason,
            "tool_logs": with_records(state.tool_logs, SENTINEL_TRIAGE, [record]),
            "token_use": deps.llm.usage.by_agent(),
            "handoffs": [
                *state.handoffs,
                handoff("alert", SENTINEL_TRIAGE),
                handoff(SENTINEL_TRIAGE, CYBERINTEL, f"{draft.priority} {draft.category}"),
            ],
        }

    return triage
