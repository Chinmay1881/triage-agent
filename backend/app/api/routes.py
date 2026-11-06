"""The HTTP API (spec: "API and dashboard"). The analyst's decision is the human step of the flow:
it is stored and shown in the report, and nothing is ever executed because of it.
"""

import asyncio
import json
import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, Self

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, model_validator
from sse_starlette.sse import EventSourceResponse

from app.agent.case import Case, Verdict
from app.agent.report import render_report
from app.api.runner import TERMINAL_EVENT, Runner
from app.api.store import Doc, Store, now
from app.blocklist import refusal
from app.config import Settings
from app.telemetry.models import Alert

router = APIRouter()

POLL_SECONDS = 0.5
FINISHED = ("awaiting_decision", "decided")
RESULT_FILE = re.compile(r"^(?P<kind>[a-z0-9_]+?)(?:_\d{4}-\d{2}-\d{2})?\.json$")


class AlertSource(Protocol):
    """What the routes need from telemetry beyond the agents' Telemetry protocol."""

    async def alert(self, alert_id: str) -> Alert | None: ...

    async def alerts(self) -> list[Alert]: ...


@dataclass
class Services:
    store: Store
    alerts: AlertSource
    runner: Runner
    settings: Settings
    results_dir: Path


def get_services(request: Request) -> Services:
    return request.app.state.services()


ServicesDep = Annotated[Services, Depends(get_services)]


async def require_investigation(investigation_id: str, services: ServicesDep) -> Doc:
    doc = await services.store.get_investigation(investigation_id)
    if doc is None:
        raise HTTPException(404, f"no investigation {investigation_id}")
    return doc


InvestigationDep = Annotated[Doc, Depends(require_investigation)]


# --- alerts ----------------------------------------------------------------------------------


def alert_row(alert: Alert, status: str) -> Doc:
    return alert.model_dump(mode="json") | {"status": status}


@router.get("/alerts")
async def list_alerts(
    services: ServicesDep, severity: str | None = None, status: str | None = None
) -> list[Doc]:
    statuses = await services.store.latest_status_by_alert()
    rows = [
        alert_row(a, statuses.get(a.alert_id, "new"))
        for a in await services.alerts.alerts()
        if severity is None or a.severity == severity
    ]
    return [r for r in rows if status is None or r["status"] == status]


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, services: ServicesDep) -> Doc:
    alert = await services.alerts.alert(alert_id)
    if alert is None:
        raise HTTPException(404, f"no alert {alert_id}")
    statuses = await services.store.latest_status_by_alert()
    call_tool = services.runner.call_tool
    host = await call_tool("get_host_info", {"host": alert.host})
    user = await call_tool("get_user_info", {"user": alert.user}) if alert.user else None
    return alert_row(alert, statuses.get(alert_id, "new")) | {
        "host_info": host.get("untrusted_log_data"),
        "user_info": user.get("untrusted_log_data") if user else None,
    }


# --- investigations --------------------------------------------------------------------------


class StartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    model: str | None = None


@router.post("/investigations", status_code=202)
async def start_investigation(body: StartRequest, services: ServicesDep) -> Doc:
    settings = services.settings
    if body.model is not None and body.model not in settings.api_models:
        raise HTTPException(422, f"model must be one of {settings.api_models}")
    if not settings.allow_blocked_alerts:
        reason = refusal(body.alert_id)
        if reason is not None:
            raise HTTPException(403, reason)
    alert = await services.alerts.alert(body.alert_id)
    if alert is None:
        raise HTTPException(404, f"no alert {body.alert_id}")
    investigation_id = uuid.uuid4().hex
    await services.store.create_investigation(
        {
            "investigation_id": investigation_id,
            "alert_id": alert.alert_id,
            "status": "queued",
            "model": body.model or settings.llm_model,
            "created_at": now(),
        }
    )
    services.runner.start(investigation_id, alert, body.model)
    return {"investigation_id": investigation_id, "status": "queued"}


def public_view(doc: Doc, decisions: list[Doc]) -> Doc:
    """A run for the dashboard: no raw trigger events, and withheld claims stay withheld."""
    view = {
        k: doc.get(k)
        for k in (
            "investigation_id",
            "alert_id",
            "status",
            "model",
            "error",
            "created_at",
            "finished_at",
            "seconds",
            "token_totals",
            "tokens_by_model",
        )
    }
    view["decisions"] = decisions
    state = doc.get("state")
    if state is None:
        return view
    case = Case.model_validate(state)
    return view | {
        "alert": case.alert.model_dump(mode="json"),
        "triage": case.triage.model_dump() if case.triage else None,
        "investigator_budget": case.investigator_budget,
        "budget_reason": case.budget_reason,
        "intel_brief": case.intel_brief.model_dump() if case.intel_brief else None,
        "findings": [
            {
                "id": f.id,
                "claim": f.shown_claim(),
                "kind": f.kind,
                "status": f.status,
                "dispute_reason": f.dispute_reason,
                "citations": f.citations,
                "reportable": f in case.reportable_findings(),
            }
            for f in case.findings
        ],
        "review": case.review.model_dump() if case.review else None,
        "handoffs": [h.model_dump(mode="json") for h in case.handoffs],
        "tool_logs": {
            agent: [r.model_dump() for r in rows] for agent, rows in case.tool_logs.items()
        },
        "token_use": case.token_use,
        "injection_flags": [
            {"event_id": f.event_id, "method": f.method} for f in case.evidence.injection_flags
        ],
        "attack_mappings": [m.model_dump() for m in case.attack_mappings],
        "verdict_proposed": case.verdict_proposed,
        "verdict": case.verdict,
        "confidence": case.confidence,
        "verdict_reasoning": case.verdict_reasoning,
        "verdict_notes": case.verdict_notes,
        "risk_score": case.risk_score,
        "risk_factors": case.risk_factors,
        "recommendations": [r.model_dump() for r in case.recommendations],
        "timeline": case.timeline,
    }


@router.get("/investigations/{investigation_id}")
async def get_investigation(doc: InvestigationDep, services: ServicesDep) -> Doc:
    return public_view(doc, await services.store.decisions(doc["investigation_id"]))


@router.get("/investigations/{investigation_id}/report.md", response_class=PlainTextResponse)
async def get_report(doc: InvestigationDep, services: ServicesDep) -> PlainTextResponse:
    if doc["status"] not in FINISHED:
        raise HTTPException(409, f"no report yet: the run is {doc['status']}")
    decisions = await services.store.decisions(doc["investigation_id"])
    # Rendered on request, so the report always shows the decisions recorded so far.
    report = render_report(Case.model_validate(doc["state"]), decisions)
    return PlainTextResponse(report, media_type="text/markdown; charset=utf-8")


# --- SSE -------------------------------------------------------------------------------------


async def event_stream(
    store: Store, investigation_id: str, after: int, poll_seconds: float = POLL_SECONDS
) -> AsyncIterator[Doc]:
    """Stored events first, then new ones as they arrive, ending with the terminal event. Polled
    because change streams need a replica set, and this is one standalone Mongo."""
    while True:
        for event in await store.events_after(investigation_id, after):
            after = event["seq"]
            yield {
                "id": str(event["seq"]),
                "event": event["kind"],
                "data": json.dumps(event["data"], default=str),
            }
            if event["kind"] == TERMINAL_EVENT:
                return
        await asyncio.sleep(poll_seconds)


@router.get("/investigations/{investigation_id}/events")
async def stream_events(
    doc: InvestigationDep,
    services: ServicesDep,
    last_event_id: Annotated[str | None, Header()] = None,
) -> EventSourceResponse:
    # EventSource sends Last-Event-ID when it reconnects, so a dropped stream resumes in place.
    after = int(last_event_id) if last_event_id and last_event_id.isdigit() else 0
    return EventSourceResponse(event_stream(services.store, doc["investigation_id"], after))


# --- the analyst's decision ------------------------------------------------------------------


class DecisionRequest(BaseModel):
    """A decision on one action, on the case verdict, or both in one request."""

    model_config = ConfigDict(extra="forbid")

    action_id: str | None = None
    decision: Literal["approve", "reject"] | None = None
    verdict_decision: Literal["agree", "override"] | None = None
    override_verdict: Verdict | None = None
    note: str = ""

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        if (self.action_id is None) != (self.decision is None):
            raise ValueError("give action_id and decision together")
        if self.action_id is None and self.verdict_decision is None:
            raise ValueError("give action_id and decision, or verdict_decision")
        if (self.verdict_decision == "override") != (self.override_verdict is not None):
            raise ValueError("override_verdict goes with verdict_decision override, and only then")
        return self


def base_record(doc: Doc, case: Case, kind: str, note: str) -> Doc:
    return {
        "decision_id": uuid.uuid4().hex,
        "investigation_id": doc["investigation_id"],
        "alert_id": doc["alert_id"],
        "model": doc.get("model"),
        "kind": kind,
        "note": note,
        "ts": now(),
    }


def action_record(doc: Doc, case: Case, body: DecisionRequest, decided: list[Doc]) -> Doc:
    action = next((r for r in case.recommendations if r.id == body.action_id), None)
    if action is None:
        raise HTTPException(404, f"no recommended action {body.action_id}")
    if any(d["kind"] == "action" and d["action_id"] == body.action_id for d in decided):
        raise HTTPException(409, f"action {body.action_id} already has a decision")
    return base_record(doc, case, "action", body.note) | {
        "action_id": action.id,
        "action": action.action,
        "target": action.target,
        "decision": body.decision,
    }


def verdict_record(doc: Doc, case: Case, body: DecisionRequest, decided: list[Doc]) -> Doc:
    if any(d["kind"] == "verdict" for d in decided):
        raise HTTPException(409, "the case verdict already has a decision")
    if body.verdict_decision == "override" and body.override_verdict == case.verdict:
        raise HTTPException(422, f"the agent's verdict is already {case.verdict}: use agree")
    agreed = body.verdict_decision == "agree"
    return base_record(doc, case, "verdict", body.note) | {
        "verdict_decision": body.verdict_decision,
        # Flat on purpose: the agreement metric in Phase 5 counts these directly.
        "agent_verdict": case.verdict,
        "agent_confidence": case.confidence,
        "analyst_verdict": case.verdict if agreed else body.override_verdict,
        "agreed": agreed,
    }


def status_after(case: Case, decisions: list[Doc]) -> str:
    """ "decided" once the case verdict and every recommended action have a decision."""
    has_verdict = any(d["kind"] == "verdict" for d in decisions)
    done = {d["action_id"] for d in decisions if d["kind"] == "action"}
    all_actions = all(r.id in done for r in case.recommendations)
    return "decided" if has_verdict and all_actions else "awaiting_decision"


@router.post("/investigations/{investigation_id}/decision", status_code=201)
async def record_decision(
    body: DecisionRequest, doc: InvestigationDep, services: ServicesDep
) -> Doc:
    if doc["status"] not in FINISHED:
        raise HTTPException(409, f"nothing to decide yet: the run is {doc['status']}")
    case = Case.model_validate(doc["state"])
    store = services.store
    investigation_id = doc["investigation_id"]
    decided = await store.decisions(investigation_id)
    # Built before any is stored, so a request that is half invalid records nothing.
    records = []
    if body.action_id is not None:
        records.append(action_record(doc, case, body, decided))
    if body.verdict_decision is not None:
        records.append(verdict_record(doc, case, body, decided))
    for record in records:
        await store.add_decision(record)
    status = status_after(case, [*decided, *records])
    await store.update_investigation(investigation_id, {"status": status})
    return {"status": status, "recorded": records}


# --- evals -----------------------------------------------------------------------------------


@router.get("/evals/latest")
async def latest_evals(
    services: ServicesDep, kind: Annotated[str | None, Query()] = None
) -> dict[str, Any]:
    """The newest results file per kind. Phase 5 adds the per-model scoreboard format."""
    latest: dict[str, Path] = {}
    if services.results_dir.exists():
        for path in sorted(services.results_dir.glob("*.json")):
            match = RESULT_FILE.match(path.name)
            if match and (kind is None or match["kind"] == kind):
                latest[match["kind"]] = path
    return {
        name: {"file": path.name, "results": json.loads(path.read_text(encoding="utf-8"))}
        for name, path in latest.items()
    }
