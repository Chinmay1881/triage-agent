"""The Phase 3 nodes: ingest, plan, investigate, run_tools, check_coverage,
summarize_findings, critic.

LLM nodes reason; code nodes do everything that must be exactly right: the tool budget,
argument validation (call_tool), the minimum investigation, which event IDs a finding may
cite, injection flags.

Anything the LLM wrote that goes back into a later prompt (hypotheses, the agent's closing
note, findings, the critic's checks) is checked with detect() first. If it matches, the
prompt gets WITHHELD instead, so log text can't leave untrusted_log_data by being echoed.
"""

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

from app.agent.context import event_ids_in, render_history, transcript
from app.agent.injection import detect_many, scan
from app.agent.prompts.coverage import TOO_FEW_CALLS, UNCHECKED_PLAN
from app.agent.prompts.critic import CRITIC, REOPEN
from app.agent.prompts.investigate import INVESTIGATE, REJECTED_CALL
from app.agent.prompts.plan import PLAN
from app.agent.prompts.summarize import ALREADY_RECORDED, SUMMARIZE
from app.agent.prompts.system import SYSTEM
from app.agent.state import (
    MAX_FINDINGS,
    WITHHELD,
    AgentState,
    CriticReview,
    Finding,
    FindingsDraft,
    InjectionFlag,
    PlanDraft,
    ToolCallRecord,
)
from app.config import Settings
from app.llm import LLM, InvalidToolCallError, LLMError
from app.telemetry.decode import decode_encoded_command
from app.tools import TOOLS, tool_specs
from app.tools._common import cap_text, iso
from app.tools.process import process_row

log = logging.getLogger(__name__)

# Token budget for the summarize/critic transcript of tool calls (Groq: ~8,000 tokens/min).
TRANSCRIPT_TOKENS = 3500
BUDGET_EXHAUSTED = "tool budget exhausted; conclude with the evidence you have"
# Named in the plan and critic prompts, so their checks are ones the agent can actually do.
TOOL_NAMES = ", ".join(TOOLS)
# Tools that read telemetry; the two ATT&CK lookups don't count towards the minimum.
DATA_TOOLS = frozenset(TOOLS) - {"search_attack_techniques", "lookup_attack_technique"}
MIN_DATA_CALLS = 3


@dataclass(frozen=True)
class CoverageGap:
    rule: Literal["first_checks", "min_data_calls"]
    message: str


def tools_named(text: str) -> list[str]:
    return [name for name in TOOLS if name in text]


def coverage_gap(state: AgentState, budget: int) -> CoverageGap | None:
    """The first unmet minimum-investigation rule that hasn't been used yet, or None.

    1. first_checks: every planned check that names a tool must have had that tool attempted
       (a check naming no tool can't be verified and is skipped).
    2. min_data_calls: at least 3 successful data-tool calls, or the whole budget if smaller.

    Each rule sends the run back at most once and only with budget left (hard rule 8)."""
    if state.tool_calls_used >= budget:
        return None
    attempted = {r.name for r in state.tool_log}
    if "first_checks" not in state.coverage_nudges:
        unchecked = [
            (names, check)
            for check in state.first_checks
            if (names := tools_named(check)) and not attempted & set(names)
        ]
        if unchecked:
            listed = "; ".join(
                f"{', '.join(names)} ({text})"
                for (names, _), text in zip(
                    unchecked, shown([c for _, c in unchecked]), strict=True
                )
            )
            return CoverageGap("first_checks", UNCHECKED_PLAN.format(checks=listed))
    if "min_data_calls" not in state.coverage_nudges:
        done = sum(1 for r in state.tool_log if r.ok and r.name in DATA_TOOLS)
        required = min(MIN_DATA_CALLS, budget)
        if done < required:
            message = TOO_FEW_CALLS.format(done=done, required=required)
            return CoverageGap("min_data_calls", message)
    return None


class Telemetry(Protocol):
    async def events(self, event_ids: list[str]) -> list[dict[str, Any]]: ...


ToolRunner = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass
class Deps:
    llm: LLM
    telemetry: Telemetry
    call_tool: ToolRunner
    settings: Settings


def _json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)


def shown(texts: list[str]) -> list[str]:
    """LLM-written texts as later prompts may show them."""
    return [WITHHELD if hits else t for t, hits in zip(texts, detect_many(texts), strict=True)]


def unwrap(result: dict[str, Any] | None) -> Any:
    if result is None:
        return None
    return result.get("untrusted_log_data", result)


def case_context(state: AgentState, with_plan: bool) -> HumanMessage:
    """The alert and what ingest attached. Log-derived fields, the alert description
    included, sit under untrusted_log_data."""
    a = state.alert
    case: dict[str, Any] = {
        "alert": {
            "alert_id": a.alert_id,
            "ts": iso(a.ts),
            "rule": a.rule,
            "severity": a.severity,
            "host": a.host,
            "user": a.user,
            "trigger_event_ids": a.trigger_event_ids,
        },
        "untrusted_log_data": {
            "alert_description": a.description,
            "host_info": unwrap(state.host_info),
            "user_info": unwrap(state.user_info),
            "trigger_events": state.trigger_events,
        },
    }
    if with_plan:
        statements = shown([h.statement for h in state.hypotheses])
        case["plan"] = {
            "hypotheses": [
                {"kind": h.kind, "statement": s}
                for h, s in zip(state.hypotheses, statements, strict=True)
            ],
            "first_checks": shown(state.first_checks),
        }
    return HumanMessage(_json(case))


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


def trigger_flags(docs: list[dict[str, Any]]) -> list[InjectionFlag]:
    """Scan the full command line and its decoded form, before the 300-character cap."""
    texts: dict[str, Any] = {}
    for doc in docs:
        cmdline = (doc.get("process") or {}).get("cmdline")
        if not cmdline:
            continue
        fields = {"cmdline": cmdline}
        decoded = decode_encoded_command(cmdline)
        if decoded is not None:
            fields["decoded_cmdline"] = decoded
        texts[doc["event_id"]] = fields
    return [
        flag.model_copy(update={"field": f"trigger_events.{flag.field}"})
        for event_id, fields in texts.items()
        for flag in scan(fields, event_id=event_id)
    ]


def make_nodes(deps: Deps) -> dict[str, Callable[[AgentState], Awaitable[dict[str, Any]]]]:
    budget = deps.settings.tool_budget
    llm = deps.llm

    async def ingest(state: AgentState) -> dict[str, Any]:
        a = state.alert
        host = await deps.call_tool("get_host_info", {"host": a.host})
        user = await deps.call_tool("get_user_info", {"user": a.user}) if a.user else None
        docs = await deps.telemetry.events(a.trigger_event_ids)
        flags = trigger_flags(docs) + scan({"alert_description": a.description})
        return {
            "host_info": host,
            "user_info": user,
            "trigger_events": [trigger_row(d) for d in docs],
            "seen_event_ids": {d["event_id"]: "ingest" for d in docs},
            "injection_flags": flags,
        }

    async def plan(state: AgentState) -> dict[str, Any]:
        prompt = PLAN.format(tools=TOOL_NAMES)
        messages = [SystemMessage(f"{SYSTEM}\n\n{prompt}"), case_context(state, with_plan=False)]
        draft = await llm.invoke_structured("plan", messages, PlanDraft)
        return {"hypotheses": draft.hypotheses, "first_checks": draft.first_checks}

    async def investigate(state: AgentState) -> dict[str, Any]:
        if state.tool_calls_used >= budget:
            return {"stop_reason": "budget"}
        messages: list[BaseMessage] = [
            SystemMessage(f"{SYSTEM}\n\n{INVESTIGATE.format(budget=budget)}"),
            case_context(state, with_plan=True),
            *render_history(state.messages),
        ]
        try:
            try:
                reply = await llm.invoke_tools("investigate", messages, tool_specs())
            except InvalidToolCallError as exc:
                # The API rejected the call before run_tools could answer it, so tell the model
                # why (once) instead of ending the turn. The reason is screened like any other
                # model-derived text that goes back into a prompt.
                (reason,) = shown([str(exc)])
                retry = [*messages, HumanMessage(REJECTED_CALL.format(reason=reason))]
                reply = await llm.invoke_tools("investigate", retry, tool_specs())
        except LLMError as exc:
            log.warning("investigate stopped: %s", exc)
            return {"stop_reason": "llm_error"}
        update: dict[str, Any] = {"messages": [reply]}
        if not reply.tool_calls:
            update["stop_reason"] = "agent_done"
        return update

    async def run_tools(state: AgentState) -> dict[str, Any]:
        last = state.messages[-1]
        if not isinstance(last, AIMessage):
            raise RuntimeError("run_tools reached without a model turn to answer")
        used = state.tool_calls_used
        seen = dict(state.seen_event_ids)
        flags = list(state.injection_flags)
        records = list(state.tool_log)
        replies = []
        # Several calls in one turn each count against the budget, in order.
        for call in last.tool_calls:
            if used >= budget:
                result: dict[str, Any] = {"error": BUDGET_EXHAUSTED}
            else:
                used += 1
                result = await deps.call_tool(call["name"], call["args"])
            ids = event_ids_in(result)
            for eid in ids:
                seen.setdefault(eid, call["name"])
            known = {(f.event_id, f.field, f.method) for f in flags}
            flags += [f for f in scan(result) if (f.event_id, f.field, f.method) not in known]
            records.append(
                ToolCallRecord(
                    name=call["name"],
                    args=call["args"],
                    ok="error" not in result,
                    error=result.get("error"),
                    event_ids=len(ids),
                )
            )
            content = _json(result | {"budget_left": budget - used})
            replies.append(ToolMessage(content, tool_call_id=call["id"], name=call["name"]))
        return {
            "messages": replies,
            "tool_calls_used": used,
            "seen_event_ids": seen,
            "injection_flags": flags,
            "tool_log": records,
            "stop_reason": "budget" if used >= budget else None,
        }

    async def check_coverage(state: AgentState) -> dict[str, Any]:
        """The minimum investigation, enforced in code: the prompt asks for it, this makes sure."""
        gap = coverage_gap(state, budget)
        if gap is None:
            return {}
        log.info("coverage rule %s triggered after %d tool calls", gap.rule, state.tool_calls_used)
        return {
            "messages": [HumanMessage(gap.message)],
            "coverage_nudges": [*state.coverage_nudges, gap.rule],
            "stop_reason": None,
        }

    async def summarize_findings(state: AgentState) -> dict[str, Any]:
        limit = MAX_FINDINGS - len(state.findings)
        if limit <= 0:
            return {}
        notes = [m.content for m in state.messages if isinstance(m, AIMessage) and m.content]
        evidence: dict[str, Any] = {
            "tool_calls": transcript(state.messages, TRANSCRIPT_TOKENS),
            "agent_notes": shown([str(n) for n in notes][-2:]),
        }
        if state.findings:
            evidence["already_recorded"] = [f.shown_claim() for f in state.findings]
        instructions = SUMMARIZE.format(limit=limit)
        if state.findings:
            instructions += f" {ALREADY_RECORDED}"
        messages = [
            SystemMessage(f"{SYSTEM}\n\n{instructions}"),
            case_context(state, with_plan=True),
            HumanMessage(_json(evidence)),
        ]
        try:
            draft = await llm.invoke_structured("summarize_findings", messages, FindingsDraft)
        except LLMError as exc:
            log.warning("summarize_findings failed: %s", exc)
            return {}
        # Hard rule 5: a finding may only cite events a tool actually returned.
        valid = [d for d in draft.findings if all(e in state.seen_event_ids for e in d.event_ids)]
        dropped = len(draft.findings) - len(valid)
        if dropped:
            log.warning(
                "summarize_findings: dropped %d finding(s) citing unseen event IDs", dropped
            )
        existing = {f.claim for f in state.findings}
        valid = [d for d in valid if d.claim not in existing][:limit]
        detections = detect_many([d.claim for d in valid])
        new = [
            Finding(
                claim=d.claim,
                event_ids=d.event_ids,
                tool=state.seen_event_ids[d.event_ids[0]],
                withheld_by=sorted({h.pattern or h.method for h in hits}),
            )
            for d, hits in zip(valid, detections, strict=True)
        ]
        return {
            "findings": state.findings + new,
            "findings_dropped": state.findings_dropped + dropped,
        }

    async def critic(state: AgentState) -> dict[str, Any]:
        left = budget - state.tool_calls_used
        review_input = {
            "findings": [
                {"claim": f.shown_claim(), "event_ids": f.event_ids} for f in state.findings
            ],
            "tool_calls": [{"tool": r.name, "args": r.args, "ok": r.ok} for r in state.tool_log],
        }
        messages = [
            SystemMessage(f"{SYSTEM}\n\n{CRITIC.format(budget_left=left, tools=TOOL_NAMES)}"),
            case_context(state, with_plan=True),
            HumanMessage(_json(review_input)),
        ]
        try:
            review = await llm.invoke_structured("critic", messages, CriticReview)
        except LLMError as exc:
            log.warning("critic failed: %s", exc)
            return {"stop_reason": state.stop_reason or "llm_error"}
        # Hard rule 8: one reopen at most, and only with budget left to act on it.
        if review.reopen and state.reopened < 1 and left > 0:
            checks = "; ".join(shown(review.missing_checks)) or "see the plan"
            return {
                "critic": review,
                "reopened": state.reopened + 1,
                "stop_reason": None,
                "messages": [HumanMessage(REOPEN.format(checks=checks))],
            }
        return {"critic": review, "stop_reason": state.stop_reason or "complete"}

    return {
        "ingest": ingest,
        "plan": plan,
        "investigate": investigate,
        "run_tools": run_tools,
        "check_coverage": check_coverage,
        "summarize_findings": summarize_findings,
        "critic": critic,
    }
