"""Renders the Markdown report from the Case: a pure function of the Case and the decisions, so it
can be rebuilt whenever the analyst records a decision. Only the Summary is LLM-written, and
report_summary (closure.py) has checked it before it gets here.
"""

import re
from collections import Counter
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.agent.case import Case, Evidence, Handoff
from app.config import CYBERINTEL, INVESTIGATOR, REPORT_AND_REVIEW, REVIEWER, SENTINEL_TRIAGE
from app.tools._common import iso

STAGES = [SENTINEL_TRIAGE, CYBERINTEL, INVESTIGATOR, REVIEWER, REPORT_AND_REVIEW]
TEMPLATES = Path(__file__).resolve().parent / "templates"
ATTACK_URL = "https://attack.mitre.org/techniques/"
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
CELL_CHARS = 160
STANDING_LIMITATIONS = [
    "The agent recommends and a human decides; nothing in this report was executed.",
    "Code refuses a benign verdict if any indicator in the case is known_bad or any log text has "
    "an injection flag, and requires a confirmed finding tied to the trigger, its parent or "
    "children, or an entity in the intel brief. It cannot check that the finding really supports "
    "the harmless explanation: the model picks which finding counts.",
    "Citation checks confirm that an event involves the entity named and that the acting process "
    "matches. They cannot confirm every other detail of a claim.",
]


def cell(value: Any, limit: int = CELL_CHARS) -> str:
    """Log-derived text inside Markdown: on one line, no table breaks or code spans."""
    text = " ".join(str(value).split()).replace("|", "\\|").replace("`", "'")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def attack_url(technique_id: str) -> str:
    if not TECHNIQUE.match(technique_id):
        raise ValueError(f"not a technique ID: {technique_id}")
    return ATTACK_URL + technique_id.replace(".", "/") + "/"


# Autoescape would mangle Markdown: this isn't HTML, and every log-derived value goes through
# `cell`. Values are only ever data here; no template text comes from the model or the logs.
_ENV = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=False,  # noqa: S701
    trim_blocks=True,
    lstrip_blocks=True,
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)
_ENV.filters["cell"] = cell
_ENV.filters["attack_url"] = attack_url


def limitations(case: Case) -> list[str]:
    notes = list(STANDING_LIMITATIONS)
    unreviewed = [f.id for f in case.findings if f.status == "unreviewed"]
    if unreviewed:
        notes.append(f"Not ruled on by the reviewer: {', '.join(unreviewed)}.")
    if case.findings_dropped or case.citations_removed:
        notes.append(
            f"Citation checks dropped {case.findings_dropped} finding(s) and removed "
            f"{case.citations_removed} citation(s)."
        )
    if case.stop_reason == "budget":
        notes.append("The investigator used its whole tool budget, so some checks may be missing.")
    if case.stop_reason == "llm_error":
        notes.append("The investigation stopped early because a model call failed.")
    if case.mapping_rejections:
        notes.append(
            f"The ATT&CK validator refused {len(case.mapping_rejections)} proposal(s): "
            + "; ".join(case.mapping_rejections)
        )
    return notes + case.closure_notes


def stamp(value: Any) -> str:
    """Stored decisions hold a datetime, or an ISO string once they have been through JSON."""
    return iso(value) if isinstance(value, datetime) else str(value)


def action_rows(case: Case, decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_action = {d["action_id"]: d for d in decisions if d["kind"] == "action"}
    rows = []
    for r in case.recommendations:
        decided = by_action.get(r.id)
        status = "pending"
        if decided is not None:
            status = {"approve": "approved", "reject": "rejected"}[decided["decision"]]
            if decided.get("note"):
                status += f": {decided['note']}"
        rows.append(
            {
                "id": r.id,
                "action": r.action,
                "target": r.target,
                "reason": r.reason,
                "status": status,
            }
        )
    return rows


def listed_indicators(case: Case) -> list[dict[str, Any]]:
    rows = case.intel_brief.reputation if case.intel_brief else []
    return [row for row in rows if row.get("reputation") != "unknown"]


def counted(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def stage_seconds(handoffs: list[Handoff]) -> dict[str, float]:
    """Each stage's time from being handed the case to handing it on. A reopen gives the
    investigator and reviewer a second span, so spans add up; the wait for the analyst isn't one."""
    seconds: dict[str, float] = {}
    for received, passed_on in pairwise(handoffs):
        spent = (passed_on.ts - received.ts).total_seconds()
        seconds[received.to_agent] = seconds.get(received.to_agent, 0.0) + spent
    return seconds


def stage_outputs(case: Case) -> dict[str, str]:
    indicators = listed_indicators(case)
    known_bad = sum(row.get("reputation") == "known_bad" for row in indicators)
    statuses = Counter(f.status for f in case.findings)
    reviewed = f"{statuses['confirmed']} confirmed, {statuses['disputed']} disputed"
    if statuses["unreviewed"]:
        reviewed += f", {statuses['unreviewed']} unreviewed"
    if case.reopened:
        reviewed += ", reopened once"
    closed = (
        f"{case.verdict}, risk {case.risk_score}, "
        f"{counted(len(case.attack_mappings), 'technique')}, "
        f"{counted(len(case.recommendations), 'action')}"
    )
    return {
        SENTINEL_TRIAGE: f"{case.triage.priority} {case.triage.category}"
        if case.triage
        else "no decision",
        CYBERINTEL: f"{counted(len(indicators), 'indicator')}, {known_bad} known_bad"
        if case.intel_brief
        else "no brief",
        INVESTIGATOR: counted(len(case.findings), "finding"),
        REVIEWER: reviewed if case.review else "no review",
        REPORT_AND_REVIEW: closed if case.verdict else "no verdict",
    }


def agent_trail(case: Case) -> list[dict[str, Any]]:
    seconds = stage_seconds(case.handoffs)
    outputs = stage_outputs(case)
    return [
        {
            "stage": stage,
            "models": ", ".join(case.models_used.get(stage, [])) or "none",
            "llm_calls": case.token_use.get(stage, {}).get("calls", 0),
            "tool_calls": sum(r.repeat_of is None for r in case.tool_logs.get(stage, [])),
            "duration": f"{seconds[stage]:.1f} s" if stage in seconds else "not run",
            "output": outputs[stage],
        }
        for stage in STAGES
    ]


def injection_line(evidence: Evidence) -> str:
    """Counts, event IDs and methods only: flagged text never reaches the report."""
    methods: dict[str, list[str]] = {}
    for flag in evidence.injection_flags:
        found = methods.setdefault(flag.event_id or "no event ID", [])
        if flag.method not in found:
            found.append(flag.method)
    line = (
        f"Injection scan: {counted(len(evidence.injection_flags), 'flag')} across "
        f"{counted(evidence.texts_scanned, 'text')} (regex + classifier)."
    )
    if methods:
        flagged = [f"{cell(event)} ({', '.join(found)})" for event, found in methods.items()]
        line += f" Flagged: {', '.join(flagged)}."
    return line


def render_report(case: Case, decisions: list[dict[str, Any]]) -> str:
    """The whole report. `decisions` are the stored analyst decisions, oldest first."""
    verdict_decisions = [d for d in decisions if d["kind"] == "verdict"]
    verdict_decision = None
    if verdict_decisions:
        verdict_decision = verdict_decisions[-1] | {"ts": stamp(verdict_decisions[-1]["ts"])}
    return _ENV.get_template("report.md.j2").render(
        alert=case.alert,
        alert_ts=iso(case.alert.ts),
        summary=case.report_summary,
        triage=case.triage,
        budget_reason=case.budget_reason,
        tool_calls_used=case.tool_calls_used,
        trail=agent_trail(case),
        brief=case.intel_brief,
        indicators=listed_indicators(case),
        injection_line=injection_line(case.evidence),
        timeline=case.timeline,
        findings=case.reportable_findings(),
        disputed_count=sum(f.status == "disputed" for f in case.findings),
        mappings=case.attack_mappings,
        verdict=case.verdict,
        confidence=case.confidence,
        reasoning=case.verdict_reasoning,
        verdict_notes=case.verdict_notes,
        risk=case.risk_factors or None,
        actions=action_rows(case, decisions),
        verdict_decision=verdict_decision,
        limitations=limitations(case),
    )
