"""Shared by the four agents: tool sets, the case context they show the model, and handoffs."""

import json
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import HumanMessage

from app.agent.case import Case, Handoff, ToolCallRecord
from app.agent.injection import screen
from app.telemetry.models import Alert
from app.tools._common import iso

INVESTIGATOR_TOOLS = frozenset(
    {
        "search_process_events",
        "get_process_tree",
        "get_network_connections",
        "get_dns_queries",
        "get_logon_history",
        "get_persistence_events",
        "score_anomaly",
    }
)
INTEL_TOOLS = frozenset(
    {
        "get_host_info",
        "get_user_info",
        "check_reputation",
        "search_attack_techniques",
        "lookup_attack_technique",
        "score_anomaly",
    }
)


def to_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)


def alert_block(alert: Alert) -> dict[str, Any]:
    """The rule's verdict-free facts. The free-text description goes under untrusted data."""
    return {
        "alert_id": alert.alert_id,
        "ts": iso(alert.ts),
        "rule": alert.rule,
        "severity": alert.severity,
        "host": alert.host,
        "user": alert.user,
        "trigger_event_ids": alert.trigger_event_ids,
    }


def handoff(from_agent: str, to_agent: str, note: str = "") -> Handoff:
    return Handoff(from_agent=from_agent, to_agent=to_agent, ts=datetime.now(UTC), note=note)


def with_records(
    logs: dict[str, list[ToolCallRecord]], agent: str, records: list[ToolCallRecord]
) -> dict[str, list[ToolCallRecord]]:
    return logs | {agent: [*logs.get(agent, []), *records]}


def case_context(state: Case, with_plan: bool) -> HumanMessage:
    """What the investigator starts from. Log-derived fields sit under untrusted_log_data, and
    anything the LLM wrote earlier is screened. Nothing here changes during an investigation, so
    the start of every investigate call stays byte-identical for Groq's prefix cache."""
    case: dict[str, Any] = {
        "alert": alert_block(state.alert),
        "untrusted_log_data": {
            "alert_description": state.alert.description,
            "trigger_events": state.trigger_events,
            "intel_facts": state.intel_brief.facts() if state.intel_brief else {},
        },
    }
    if state.triage:
        (reason,) = screen([state.triage.reason])
        case["triage"] = {
            "priority": state.triage.priority,
            "category": state.triage.category,
            "reason": reason,
        }
    if state.intel_brief:
        case["intel"] = {
            "assessment": screen([state.intel_brief.assessment])[0],
            "notable": screen(state.intel_brief.notable),
        }
    if with_plan:
        statements = screen([h.statement for h in state.hypotheses])
        case["plan"] = {
            "hypotheses": [
                {"kind": h.kind, "statement": s}
                for h, s in zip(state.hypotheses, statements, strict=True)
            ],
            "first_checks": screen(state.first_checks),
        }
    return HumanMessage(to_json(case))
