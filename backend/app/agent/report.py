"""Renders the Markdown report from the Case: a pure function of the Case and the decisions, so it
can be rebuilt whenever the analyst records a decision. Only the Summary is LLM-written, and
report_summary (closure.py) has checked it before it gets here.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.agent.case import Case
from app.tools._common import iso

TEMPLATES = Path(__file__).resolve().parent / "templates"
ATTACK_URL = "https://attack.mitre.org/techniques/"
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
CELL_CHARS = 160
STANDING_LIMITATIONS = [
    "The agent recommends and a human decides; nothing in this report was executed.",
    "Code checks that a benign verdict rests on a confirmed finding tied to the trigger, its "
    "parent or children, or an entity in the intel brief. It cannot check that the finding really "
    "supports the harmless explanation: the model picks which finding counts.",
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
        brief=case.intel_brief,
        indicators=[
            row
            for row in (case.intel_brief.reputation if case.intel_brief else [])
            if row.get("reputation") != "unknown"
        ],
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
