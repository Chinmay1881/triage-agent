"""A scripted model for offline evals of all 12 scenarios: it tests the plumbing, not the agent.

It knows only what a model would be shown, never the truth. Its rule is deliberately simple: any
known_bad indicator means malicious, otherwise benign. So some scenarios fail, which exercises the
pass/fail grid and the notes. It always proposes one invented technique and one target outside the
case, so the validator and the recommendation check have something to refuse.

Its claims hold only an entity found in its prompt (a process, file, domain or IP) and the host, and
stay in memory: a saved eval record has no field for them.
"""

import json
import re
from collections.abc import Sequence
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from app.agent.grounding import text_entities
from app.llm import MockLLM
from app.telemetry.models import Alert

EVENT_ID_SPLIT = re.compile(r"(evt_\d{6})")
FINDING_ID = re.compile(r"\bF\d+\b")
SEVERITY_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
MAX_CITED = 10
MAX_ENTITIES = 6


def _call(tool: str, **args: Any) -> AIMessage:
    return AIMessage("", tool_calls=[{"name": tool, "args": args, "id": "x", "type": "tool_call"}])


def _prompt(messages: Sequence[BaseMessage]) -> dict[str, Any]:
    return json.loads(str(messages[-1].content))


def entity_events(text: str) -> dict[str, list[str]]:
    """Entity -> the events it appears with. A tool row starts with its event_id, so what follows
    an ID, up to the next one, is that event's row."""
    parts = EVENT_ID_SPLIT.split(text)
    found: dict[str, list[str]] = {}
    for event_id, row in zip(parts[1::2], parts[2::2], strict=True):
        for entity in text_entities(row):
            events = found.setdefault(entity, [])
            if event_id not in events:
                events.append(event_id)
    return found


def mock_model(alert: Alert) -> MockLLM:
    host = alert.host
    around = alert.ts.isoformat().replace("+00:00", "Z")
    checks = [
        _call("search_process_events", host=host, around=around),
        _call("get_network_connections", host=host, around=around),
    ]
    if alert.user:
        checks.append(_call("get_logon_history", user=alert.user, around=around))

    def findings(messages: Sequence[BaseMessage]) -> dict[str, Any]:
        """One claim per entity in the prompt, entities around the trigger first. Grounding still
        checks each pairing, so a wrong guess here is dropped like a real model's would be."""
        seen = entity_events(" ".join(str(m.content) for m in messages[-2:]))
        triggers = set(alert.trigger_event_ids)
        named = sorted(seen, key=lambda e: (not triggers & set(seen[e]), -len(seen[e]), e))
        rows = [(entity, seen[entity][:MAX_CITED]) for entity in named[:MAX_ENTITIES]]
        return {
            "findings": [
                {
                    "claim": f"{entity} appears in the activity on {host}",
                    "kind": "observation",
                    "citations": cited,
                }
                for entity, cited in rows or [(host, alert.trigger_event_ids[:MAX_CITED])]
            ]
        }

    def verdict(messages: Sequence[BaseMessage]) -> dict[str, Any]:
        ids = sorted(set(FINDING_ID.findall(str(messages[-1].content))))
        return {
            "confirmed": [{"finding": f, "verified_by": ""} for f in ids],
            "disputed": [],
            "reopen": False,
            "missing_checks": [],
            "reason": "Scripted.",
        }

    def mappings(messages: Sequence[BaseMessage]) -> dict[str, Any]:
        prompt = _prompt(messages)
        events = [e for f in prompt["findings"] for e in f["event_ids"]][:MAX_CITED]
        rows = [
            {"technique_id": "T1059.001", "event_ids": events, "rationale": "Scripted."},
            {"technique_id": "T1204", "event_ids": events, "rationale": "Scripted."},
        ]
        if not prompt["errors"]:
            rows.append({"technique_id": "T1999", "event_ids": events, "rationale": "Scripted."})
        return {"mappings": rows}

    def assess(messages: Sequence[BaseMessage]) -> dict[str, Any]:
        prompt = _prompt(messages)
        ids = [f["id"] for f in prompt["findings"]]
        bad = prompt["untrusted_log_data"]["known_bad_indicators"]
        if bad:
            return _assessed("malicious", 0.8, [])
        return _assessed("benign", 0.6, ids[:1])

    def recommend(messages: Sequence[BaseMessage]) -> dict[str, Any]:
        verdict_now = _prompt(messages)["verdict"]
        rows = [_action("isolate_host", "OUTSIDE-THE-CASE")]
        if verdict_now == "malicious":
            rows += [_action("isolate_host", host), _action("escalate", "SOC analyst")]
        elif verdict_now == "benign":
            rows.append(_action("close_as_benign", alert.alert_id))
        else:
            rows.append(_action("collect_forensics", host))
        return {"recommendations": rows}

    return MockLLM(
        {
            "triage": [
                {
                    "priority": SEVERITY_PRIORITY.get(alert.severity, "P2"),
                    "category": "endpoint",
                    "reason": "Scripted from the alert's severity.",
                }
            ],
            "intel": [AIMessage("Nothing to add.")],
            "intel_brief": [{"assessment": "Scripted.", "notable": []}],
            "plan": [
                {
                    "hypotheses": [
                        {"kind": "malicious", "statement": "Scripted malicious hypothesis."},
                        {"kind": "benign", "statement": "Scripted harmless hypothesis."},
                    ],
                    "first_checks": [],
                }
            ],
            "investigate": [*checks, AIMessage("Done.")],
            "summarize_findings": [findings],
            "review": [AIMessage("Nothing to verify.")],
            "review_verdict": [verdict],
            "map_attack": [mappings],
            "assess": [assess],
            "recommend": [recommend],
            "report_summary": [{"summary": f"Scripted summary of {alert.alert_id}."}],
        }
    )


def _assessed(verdict: str, confidence: float, support: list[str]) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": "Scripted.",
        "supporting_benign": support,
    }


def _action(action: str, target: str) -> dict[str, Any]:
    return {"action": action, "target": target, "reason": "Scripted."}
