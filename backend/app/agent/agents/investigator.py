"""Investigator-Agent: plan, investigate, run_tools, check_coverage, summarize_findings.

Starts from the intel brief with only the telemetry tools bound. The LLM reasons; code does what
must be exactly right: the budget (from Sentinel-Triage's priority, counted across a reopen),
the minimum investigation, and which citations a finding may keep (grounding.py).
"""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

from app.agent.agents.common import INVESTIGATOR_TOOLS, case_context, handoff, to_json, with_records
from app.agent.case import MAX_FINDINGS, Case, Finding, FindingDraft, FindingsDraft, PlanDraft
from app.agent.context import render_history, transcript
from app.agent.deps import Deps
from app.agent.grounding import grounded_citations, is_absence_claim
from app.agent.injection import regex_hits, screen
from app.agent.prompts.coverage import TOO_FEW_CALLS, UNCHECKED_PLAN
from app.agent.prompts.investigate import INVESTIGATE, REJECTED_CALL
from app.agent.prompts.plan import PLAN
from app.agent.prompts.summarize import ALREADY_RECORDED, SUMMARIZE
from app.agent.prompts.system import SYSTEM
from app.agent.toolrun import auto_reputation, run_call
from app.config import INVESTIGATOR, REVIEWER
from app.llm import InvalidToolCallError, LLMError
from app.tools import tool_specs

log = logging.getLogger(__name__)

# Token budget for the summarize transcript of tool calls (Groq: ~8,000 tokens/min).
TRANSCRIPT_TOKENS = 3500
BUDGET_EXHAUSTED = "tool budget exhausted; conclude with the evidence you have"
MIN_DATA_CALLS = 3
TOOL_NAMES = ", ".join(sorted(INVESTIGATOR_TOOLS))


@dataclass(frozen=True)
class CoverageGap:
    rule: Literal["first_checks", "min_data_calls"]
    message: str


def tools_named(text: str) -> list[str]:
    return [name for name in sorted(INVESTIGATOR_TOOLS) if name in text]


def coverage_gap(state: Case, budget: int) -> CoverageGap | None:
    """The first unmet minimum-investigation rule that hasn't been used yet, or None.

    1. first_checks: every planned check that names a tool must have had that tool attempted
       (a check naming no tool can't be verified and is skipped).
    2. min_data_calls: at least 3 successful calls, or the whole budget if smaller.

    Each rule sends the run back at most once and only with budget left (hard rule 8)."""
    if state.tool_calls_used >= budget:
        return None
    log_rows = [r for r in state.tool_logs.get(INVESTIGATOR, []) if r.source == "llm"]
    attempted = {r.name for r in log_rows}
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
                    unchecked, screen([c for _, c in unchecked]), strict=True
                )
            )
            return CoverageGap("first_checks", UNCHECKED_PLAN.format(checks=listed))
    if "min_data_calls" not in state.coverage_nudges:
        done = sum(1 for r in log_rows if r.ok)
        required = min(MIN_DATA_CALLS, budget)
        if done < required:
            message = TOO_FEW_CALLS.format(done=done, required=required)
            return CoverageGap("min_data_calls", message)
    return None


def citation_tool(citation: str, state: Case) -> str:
    if citation.startswith("tool:"):
        return citation.removeprefix("tool:").split("#")[0]
    return state.evidence.seen_event_ids.get(citation, "unknown")


def build_findings(
    drafts: list[FindingDraft],
    docs: dict[str, dict[str, Any]],
    state: Case,
    limit: int,
) -> tuple[list[Finding], int, int]:
    """New findings from drafts, keeping only grounded citations. Also returns how many findings
    were dropped and how many single citations were removed."""
    existing = {f.claim for f in state.findings}
    new: list[Finding] = []
    dropped = removed = 0
    for draft in drafts:
        # The summarizer labels absence claims; the regex catches the ones it mislabels.
        kind = (
            "absence"
            if draft.kind == "absence" or is_absence_claim(draft.claim)
            else ("observation")
        )
        kept = grounded_citations(draft, kind, docs, state.evidence)
        removed += len(draft.citations) - len(kept)
        if not kept:
            dropped += 1
            log.warning("finding dropped: no citation supports it")
            continue
        if draft.claim in existing or len(new) >= limit:
            continue
        new.append(
            Finding(
                id=f"F{len(state.findings) + len(new) + 1}",
                claim=draft.claim,
                kind=kind,
                citations=kept,
                tool=citation_tool(kept[0], state),
                withheld_by=regex_hits(draft.claim),
            )
        )
    return new, dropped, removed


def make_investigator(deps: Deps) -> dict[str, Callable[[Case], Awaitable[dict[str, Any]]]]:
    llm = deps.llm
    specs = tool_specs(INVESTIGATOR_TOOLS)

    async def plan(state: Case) -> dict[str, Any]:
        prompt = PLAN.format(tools=TOOL_NAMES)
        messages = [SystemMessage(f"{SYSTEM}\n\n{prompt}"), case_context(state, with_plan=False)]
        draft = await llm.invoke_structured("plan", messages, PlanDraft)
        return {"hypotheses": draft.hypotheses, "first_checks": draft.first_checks}

    async def investigate(state: Case) -> dict[str, Any]:
        budget = state.investigator_budget
        if state.tool_calls_used >= budget:
            return {"stop_reason": "budget"}
        messages: list[BaseMessage] = [
            SystemMessage(f"{SYSTEM}\n\n{INVESTIGATE.format(budget=budget)}"),
            case_context(state, with_plan=True),
            *render_history(state.messages),
        ]
        try:
            try:
                reply = await llm.invoke_tools("investigate", messages, specs)
            except InvalidToolCallError as exc:
                # The API rejected the call before run_tools could answer it, so tell the model
                # why (once) instead of ending the turn. The reason is screened like any other
                # model-derived text that goes back into a prompt.
                (reason,) = screen([str(exc)])
                retry = [*messages, HumanMessage(REJECTED_CALL.format(reason=reason))]
                reply = await llm.invoke_tools("investigate", retry, specs)
        except LLMError as exc:
            log.warning("investigate stopped: %s", exc)
            return {"stop_reason": "llm_error"}
        update: dict[str, Any] = {"messages": [reply]}
        if not reply.tool_calls:
            update["stop_reason"] = "agent_done"
        return update

    async def run_tools(state: Case) -> dict[str, Any]:
        last = state.messages[-1]
        if not isinstance(last, AIMessage):
            raise RuntimeError("run_tools reached without a model turn to answer")
        budget = state.investigator_budget
        used = state.tool_calls_used
        evidence = state.evidence.model_copy(deep=True)
        records = []
        replies = []
        # Several calls in one turn each count against the budget, in order.
        for call in last.tool_calls:
            if used >= budget:
                result: dict[str, Any] = {"error": BUDGET_EXHAUSTED}
            else:
                used += 1
                result, record = await run_call(
                    deps,
                    evidence,
                    INVESTIGATOR,
                    INVESTIGATOR_TOOLS,
                    state.alert,
                    call["name"],
                    call["args"],
                )
                records.append(record)
                rows, rule_records = await auto_reputation(
                    deps, evidence, INVESTIGATOR, state.alert, result
                )
                records += rule_records
                if rows:
                    result = result | {"intel_rule": rows}
            content = to_json(result | {"budget_left": budget - used})
            replies.append(ToolMessage(content, tool_call_id=call["id"], name=call["name"]))
        return {
            "messages": replies,
            "tool_calls_used": used,
            "evidence": evidence,
            "tool_logs": with_records(state.tool_logs, INVESTIGATOR, records),
            "stop_reason": "budget" if used >= budget else None,
        }

    async def check_coverage(state: Case) -> dict[str, Any]:
        """The minimum investigation, enforced in code: the prompt asks for it, this makes sure."""
        gap = coverage_gap(state, state.investigator_budget)
        if gap is None:
            return {}
        log.info("coverage rule %s triggered after %d tool calls", gap.rule, state.tool_calls_used)
        return {
            "messages": [HumanMessage(gap.message)],
            "coverage_nudges": [*state.coverage_nudges, gap.rule],
            "stop_reason": None,
        }

    async def summarize_findings(state: Case) -> dict[str, Any]:
        done: dict[str, Any] = {
            "token_use": llm.usage.by_agent(),
            "handoffs": [*state.handoffs, handoff(INVESTIGATOR, REVIEWER)],
        }
        active = [f for f in state.findings if f.status != "disputed"]
        limit = MAX_FINDINGS - len(active)
        if limit <= 0:
            return done
        notes = [str(m.content) for m in state.messages if isinstance(m, AIMessage) and m.content]
        evidence: dict[str, Any] = {
            "tool_calls": transcript(state.messages, TRANSCRIPT_TOKENS),
            "agent_notes": screen(notes[-2:]),
        }
        instructions = SUMMARIZE.format(limit=limit)
        if state.findings:
            evidence["already_recorded"] = [f.shown_claim() for f in state.findings]
            instructions += f"\n\n{ALREADY_RECORDED}"
        messages = [
            SystemMessage(f"{SYSTEM}\n\n{instructions}"),
            case_context(state, with_plan=True),
            HumanMessage(to_json(evidence)),
        ]
        try:
            draft = await llm.invoke_structured("summarize_findings", messages, FindingsDraft)
        except LLMError as exc:
            log.warning("summarize_findings failed: %s", exc)
            return done | {"token_use": llm.usage.by_agent()}
        cited = [c for d in draft.findings for c in d.citations if c.startswith("evt_")]
        docs = {d["event_id"]: d for d in await deps.telemetry.events(sorted(set(cited)))}
        new, dropped, removed = build_findings(draft.findings, docs, state, limit)
        if dropped or removed:
            log.warning(
                "summarize_findings: %d finding(s) dropped, %d citation(s) removed by grounding",
                dropped,
                removed,
            )
        return done | {
            "findings": state.findings + new,
            "findings_dropped": state.findings_dropped + dropped,
            "citations_removed": state.citations_removed + removed,
            "token_use": llm.usage.by_agent(),
        }

    return {
        "plan": plan,
        "investigate": investigate,
        "run_tools": run_tools,
        "check_coverage": check_coverage,
        "summarize_findings": summarize_findings,
    }
