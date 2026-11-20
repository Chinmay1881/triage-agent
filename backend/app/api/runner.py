"""Runs investigations in the background, one at a time, and stores every step as an event.

One at a time because Groq's per-minute limit is shared: two runs would only slow each other down
and collect 429s, so a second one waits as "queued". Every step goes to the store first and the SSE
endpoint reads from there, which is why refreshing the page replays the whole run.

Events carry no raw log content: tool events have the tool, its status, a row count and a ref, and
findings are shown as prompts would show them.
"""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.agent.case import Case
from app.agent.chain import run_case
from app.agent.deps import Deps, Telemetry, ToolRunner
from app.agent.report import STAGES, agent_trail
from app.api.store import Doc, Store, now
from app.config import Settings
from app.llm import LLM
from app.telemetry.models import Alert

log = logging.getLogger(__name__)

TERMINAL_EVENT = "done"
# What a stage's trail row is built from; messages and working state aren't needed.
TRAIL_FIELDS = (
    "triage",
    "intel_brief",
    "findings",
    "review",
    "reopened",
    "verdict",
    "risk_score",
    "attack_mappings",
    "recommendations",
    "token_use",
    "tool_logs",
    "handoffs",
)


def dump_case(case: Case) -> Doc:
    """The Case as stored: without the tool conversation, and without the ledger's raw results."""
    doc = case.model_dump(mode="json", exclude={"messages"})
    doc["evidence"].pop("answers", None)
    return doc


class StepRecorder:
    """Turns graph steps into stored events: handoffs, tools, findings, mappings, the verdict."""

    def __init__(self, store: Store, investigation_id: str, alert: Alert) -> None:
        self._store = store
        self._id = investigation_id
        self._alert = alert
        self._trail: dict[str, Any] = {}
        self._seq = 0
        self._handoffs = 0
        self._findings: set[str] = set()
        self._tools: dict[str, int] = {}

    async def emit(self, kind: str, data: Doc) -> None:
        self._seq += 1
        await self._store.append_event(self._id, self._seq, kind, data)

    def _stage_row(self, stage: str) -> Doc:
        """The stage's Agent trail row so far: counts and its one-line output, no log content. A
        reopen sends a second row for the same stage, which replaces the first."""
        case = Case(alert=self._alert, **self._trail)
        return next(row for row in agent_trail(case) if row["stage"] == stage)

    async def step(self, node: str, update: dict[str, Any]) -> None:
        await self.emit("node_step", {"node": node})
        self._trail |= {k: update[k] for k in TRAIL_FIELDS if k in update}
        if update.get("triage") is not None:
            # Stored now, not at the end: the alert queue shows it while the run is going.
            await self._store.update_investigation(
                self._id, {"priority": update["triage"].priority}
            )
        handoffs = update.get("handoffs") or []
        for h in handoffs[self._handoffs :]:
            await self.emit(
                "handoff",
                {
                    "from": h.from_agent,
                    "to": h.to_agent,
                    "ts": h.ts.isoformat(),
                    "note": h.note,
                },
            )
            if h.from_agent in STAGES:
                await self.emit("stage_done", self._stage_row(h.from_agent))
        self._handoffs = max(self._handoffs, len(handoffs))
        for message in update.get("messages") or []:
            for call in getattr(message, "tool_calls", None) or []:
                await self.emit("tool_called", {"tool": call["name"]})
        for agent, records in (update.get("tool_logs") or {}).items():
            for record in records[self._tools.get(agent, 0) :]:
                await self.emit(
                    "tool_result",
                    {
                        "agent": agent,
                        "tool": record.name,
                        "ok": record.ok,
                        "event_ids": record.event_ids,
                        "ref": record.ref,
                        "source": record.source,
                    },
                )
            self._tools[agent] = len(records)
        for finding in update.get("findings") or []:
            if finding.id not in self._findings:
                self._findings.add(finding.id)
                await self.emit(
                    "finding_added",
                    {
                        "id": finding.id,
                        "claim": finding.shown_claim(),
                        "kind": finding.kind,
                        "citations": finding.citations,
                    },
                )
        if node == "validate_mapping":
            await self.emit(
                "mapping_checked",
                {
                    "techniques": [m.technique_id for m in update.get("attack_mappings") or []],
                    "errors": len(update.get("mapping_errors") or []),
                },
            )
        if node == "assess":
            await self.emit(
                "verdict",
                {
                    "verdict": update.get("verdict"),
                    "confidence": update.get("confidence"),
                    "notes": update.get("verdict_notes") or [],
                },
            )
        if node == "report":
            await self.emit("report_ready", {})


@dataclass
class Runner:
    store: Store
    telemetry: Telemetry
    call_tool: ToolRunner
    settings: Settings
    llm_for: Callable[[Settings, Alert], LLM]
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    tasks: dict[str, asyncio.Task[None]] = field(default_factory=dict)

    def start(self, investigation_id: str, alert: Alert, model: str | None) -> None:
        self.tasks[investigation_id] = asyncio.create_task(
            self._run(investigation_id, alert, model)
        )

    async def _run(self, investigation_id: str, alert: Alert, model: str | None) -> None:
        recorder = StepRecorder(self.store, investigation_id, alert)
        async with self._lock:
            await self.store.update_investigation(
                investigation_id, {"status": "running", "started_at": now()}
            )
            settings = self.settings
            if model:
                settings = settings.model_copy(update={"llm_model": model})
            try:
                llm = self.llm_for(settings, alert)
                deps = Deps(llm, self.telemetry, self.call_tool, settings)
                result = await run_case(deps, alert, recorder.step)
            except Exception as exc:
                # A run that dies must end as failed, not stay "running" forever.
                log.exception("investigation %s failed", investigation_id)
                await self._finish_failed(investigation_id, recorder, str(exc))
                return
            if result.timed_out or result.state.report_md is None:
                reason = "the run timed out" if result.timed_out else "the run did not finish"
                await self.store.update_investigation(
                    investigation_id, {"state": dump_case(result.state)}
                )
                await self._finish_failed(investigation_id, recorder, reason)
                return
            await self.store.update_investigation(
                investigation_id,
                {
                    "status": "awaiting_decision",
                    "finished_at": now(),
                    "seconds": round(result.seconds, 1),
                    "state": dump_case(result.state),
                    "verdict": result.state.verdict,
                    "risk_score": result.state.risk_score,
                    "token_use": llm.usage.by_agent(),
                    "token_totals": llm.usage.totals(),
                    "tokens_by_model": llm.usage.by_model(),
                },
            )
            await recorder.emit(TERMINAL_EVENT, {"status": "awaiting_decision"})

    async def _finish_failed(
        self, investigation_id: str, recorder: StepRecorder, reason: str
    ) -> None:
        await self.store.update_investigation(
            investigation_id, {"status": "failed", "error": reason, "finished_at": now()}
        )
        await recorder.emit("error", {"message": reason})
        await recorder.emit(TERMINAL_EVENT, {"status": "failed"})
