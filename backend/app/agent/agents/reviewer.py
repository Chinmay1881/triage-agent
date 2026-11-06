"""Reviewer-Agent: the critic with tools of its own. Checks the findings before the report.

Every absence claim ("no X observed") must be re-verified: code only accepts it as confirmed if
the reviewer actually ran a successful call for it, either the ref it names or the same tool the
claim cites, and an unverified one is disputed. So "nothing else ran" can't reach the report
because a model said so twice.

Findings the reviewer doesn't list: an observation that passed grounding stays reportable, marked
"unreviewed"; an absence claim is disputed. It can reopen the investigator at most once, and has
3 tool calls per run across both passes.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage

from app.agent.agents.common import INVESTIGATOR_TOOLS, alert_block, handoff, to_json, with_records
from app.agent.agents.triage import trigger_row
from app.agent.case import Case, Dispute, Finding, Review, ReviewDraft, ToolCallRecord
from app.agent.context import transcript
from app.agent.deps import Deps
from app.agent.injection import screen
from app.agent.prompts.review import REOPEN, REVIEW, REVIEW_VERDICT
from app.agent.prompts.system import SYSTEM
from app.agent.toolrun import auto_reputation, run_call
from app.config import INVESTIGATOR, REVIEWER
from app.llm import LLMError
from app.tools import tool_specs

log = logging.getLogger(__name__)

# Roughly: the investigator's evidence for the verdict, compact (Groq: ~8,000 tokens/min).
TRANSCRIPT_TOKENS = 1500
MAX_CITED_EVENTS = 8
NOT_VERIFIED = "absence claim not re-verified by a reviewer tool call"
NOT_LISTED = "absence claim not reviewed"
TOOL_NAMES = ", ".join(sorted(INVESTIGATOR_TOOLS))


def _tool_of(ref: str) -> str:
    return ref.split("#")[0]


def verified_by_own_call(finding: Finding, named_ref: str, own_refs: set[str]) -> bool:
    """The reviewer ran a successful call for this absence claim: the ref it named, or the same
    tool the claim cites. Checked from the tool log, not from how well the model quotes a ref."""
    cited_tools = {_tool_of(c) for c in finding.citations if c.startswith("tool:")}
    return named_ref in own_refs or bool(cited_tools & {_tool_of(r) for r in own_refs})


def apply_verdict(
    findings: list[Finding], draft: ReviewDraft | None, own_refs: set[str]
) -> tuple[list[Finding], Review]:
    """Statuses for the pending findings, pure so the rules can be tested directly. `draft` is
    None if the verdict call failed: nothing was verified, so the same rules treat every finding
    as unlisted. A finding both confirmed and disputed counts as disputed."""
    disputes = {d.finding: d.reason for d in draft.disputed} if draft else {}
    confirmations = {c.finding: c.verified_by for c in draft.confirmed} if draft else {}
    out: list[Finding] = []
    review = Review()
    for finding in findings:
        if finding.status != "pending":
            out.append(finding)
            continue
        if finding.id in disputes:
            status, reason = "disputed", disputes[finding.id]
        elif finding.id in confirmations:
            verified = verified_by_own_call(finding, confirmations[finding.id], own_refs)
            if finding.kind == "absence" and not verified:
                status, reason = "disputed", NOT_VERIFIED
            else:
                status, reason = "confirmed", None
        elif finding.kind == "absence":
            status, reason = "disputed", NOT_LISTED
        else:
            status, reason = "unreviewed", None
        out.append(finding.model_copy(update={"status": status, "dispute_reason": reason}))
        if status == "disputed":
            review.disputed.append(Dispute(finding=finding.id, reason=reason or ""))
        elif status == "confirmed":
            review.confirmed.append(finding.id)
        else:
            review.unreviewed.append(finding.id)
    return out, review


def make_reviewer(deps: Deps) -> Callable[[Case], Awaitable[dict[str, Any]]]:
    llm = deps.llm
    specs = tool_specs(INVESTIGATOR_TOOLS)

    def findings_block(findings: list[Finding]) -> list[dict[str, Any]]:
        return [
            {"id": f.id, "kind": f.kind, "claim": f.shown_claim(), "citations": f.citations}
            for f in findings
        ]

    async def verify(
        state: Case, pending: list[Finding], evidence: Any, records: list[ToolCallRecord]
    ) -> tuple[list[BaseMessage], int]:
        """The tool turns; returns the conversation and the calls left."""
        left = deps.settings.reviewer_tool_calls - state.review_calls_used
        conversation: list[BaseMessage] = []
        if left <= 0:
            return conversation, 0
        calls = [
            {"ref": r.ref, "tool": r.name, "args": r.args, "ok": r.ok}
            for r in state.tool_logs.get(INVESTIGATOR, [])
            if r.source == "llm"
        ]
        start: list[BaseMessage] = [
            SystemMessage(f"{SYSTEM}\n\n{REVIEW.format(calls=left)}"),
            HumanMessage(
                to_json(
                    {
                        "alert": alert_block(state.alert),
                        "findings": findings_block(pending),
                        "investigator_calls": calls,
                    }
                )
            ),
        ]
        while left > 0:
            try:
                reply = await llm.invoke_tools("review", [*start, *conversation], specs)
            except LLMError as exc:
                log.warning("reviewer tool turn stopped: %s", exc)
                break
            if not reply.tool_calls:
                break
            conversation.append(reply)
            for call in reply.tool_calls:
                if left <= 0:
                    answer: dict[str, Any] = {"error": "no reviewer calls left"}
                else:
                    left -= 1
                    answer, record = await run_call(
                        deps,
                        evidence,
                        REVIEWER,
                        INVESTIGATOR_TOOLS,
                        state.alert,
                        call["name"],
                        call["args"],
                    )
                    records.append(record)
                    rows, rule_records = await auto_reputation(
                        deps, evidence, REVIEWER, state.alert, answer
                    )
                    records += rule_records
                    if rows:
                        answer = answer | {"intel_rule": rows}
                conversation.append(
                    ToolMessage(to_json(answer), tool_call_id=call["id"], name=call["name"])
                )
        return conversation, left

    async def review(state: Case) -> dict[str, Any]:
        evidence = state.evidence.model_copy(deep=True)
        records: list[ToolCallRecord] = []
        pending = [f for f in state.findings if f.status == "pending"]
        conversation: list[BaseMessage] = []
        left = deps.settings.reviewer_tool_calls - state.review_calls_used
        draft: ReviewDraft | None = None
        budget_left = state.investigator_budget - state.tool_calls_used
        if pending:
            conversation, left = await verify(state, pending, evidence, records)
            instructions = REVIEW_VERDICT.format(tools=TOOL_NAMES, budget_left=budget_left)
            # The evidence behind the findings: the trigger and the brief aren't in the
            # investigator's own tool calls, and without them true findings look unsupported.
            cited = sorted(
                {e for f in pending for e in f.event_ids} - set(state.alert.trigger_event_ids)
            )
            docs = await deps.telemetry.events(cited[:MAX_CITED_EVENTS])
            prompt = {
                "alert": alert_block(state.alert),
                "findings": findings_block(pending),
                "untrusted_log_data": {
                    "trigger_events": state.trigger_events,
                    "cited_events": [trigger_row(d) for d in docs],
                    "intel_facts": state.intel_brief.facts() if state.intel_brief else {},
                },
                "investigator_evidence": transcript(state.messages, TRANSCRIPT_TOKENS),
                "your_calls": transcript(conversation, TRANSCRIPT_TOKENS),
            }
            messages = [
                SystemMessage(f"{SYSTEM}\n\n{instructions}"),
                HumanMessage(to_json(prompt)),
            ]
            try:
                draft = await llm.invoke_structured("review_verdict", messages, ReviewDraft)
            except LLMError as exc:
                log.warning("review verdict failed: %s", exc)

        own_refs = {
            r.ref
            for r in [*state.tool_logs.get(REVIEWER, []), *records]
            if r.ok and r.source == "llm"
        }
        findings, outcome = apply_verdict(state.findings, draft, own_refs)
        previous = state.review or Review()
        wants_reopen = bool(draft and draft.reopen)
        reopen = wants_reopen and state.reopened < 1 and budget_left > 0
        merged = Review(
            confirmed=[*previous.confirmed, *outcome.confirmed],
            disputed=[*previous.disputed, *outcome.disputed],
            unreviewed=[*previous.unreviewed, *outcome.unreviewed],
            reopen_requested=previous.reopen_requested or wants_reopen,
            reason=draft.reason if draft else "review verdict unavailable",
            passes=previous.passes + 1,
        )
        update: dict[str, Any] = {
            "findings": findings,
            "review": merged,
            "evidence": evidence,
            "review_calls_used": deps.settings.reviewer_tool_calls - left,
            "tool_logs": with_records(state.tool_logs, REVIEWER, records),
            "token_use": llm.usage.by_agent(),
        }
        if reopen and draft:
            # Hard rule 8: one reopen at most, and only with budget left to act on it.
            checks = "; ".join(screen(draft.missing_checks)) or "see the plan"
            log.info("reviewer reopens the investigation")
            return update | {
                "reopened": state.reopened + 1,
                "stop_reason": None,
                "messages": [HumanMessage(REOPEN.format(checks=checks))],
                "handoffs": [*state.handoffs, handoff(REVIEWER, INVESTIGATOR, "reopen")],
            }
        return update | {
            "stop_reason": state.stop_reason or "complete",
            "handoffs": [*state.handoffs, handoff(REVIEWER, "report")],
        }

    return review
