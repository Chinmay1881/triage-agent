"""The agent chain, built by hand (no prebuilt agents):

    START -> Sentinel-Triage -> CyberIntel-Agent -> Investigator-Agent -> Reviewer-Agent -> END
                                                            ^                   |
                                                            +---- reopen, once -+

Investigator-Agent is a compiled subgraph with the same Case schema:

    START -> plan -> investigate       (a reopened run goes straight to investigate)
    investigate -> run_tools           if the model called tools
    investigate -> check_coverage      if it stopped calling tools
    investigate -> summarize_findings  if the budget or the LLM ran out
    run_tools -> investigate           while budget is left, else -> summarize_findings
    check_coverage -> investigate      a minimum-investigation rule is unmet (each rule once)
    check_coverage -> summarize_findings

Bounds (hard rule 8): each agent's tool budget is enforced in code; each coverage rule and the
reviewer send the run back at most once; LangGraph's recursion limit and an overall timeout stop
anything else. Every routing decision reads Case fields that only the agents set, and every
handoff is logged in Case.handoffs so the API can stream it.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agent.agents.intel import make_intel
from app.agent.agents.investigator import make_investigator
from app.agent.agents.reviewer import make_reviewer
from app.agent.agents.triage import make_triage
from app.agent.case import Case
from app.agent.deps import Deps
from app.telemetry.models import Alert

log = logging.getLogger(__name__)

TRIAGE_NODE = "sentinel_triage"
INTEL_NODE = "cyberintel"
INVESTIGATOR_NODE = "investigator"
REVIEWER_NODE = "reviewer"


def investigator_entry(state: Case) -> str:
    return "investigate" if state.hypotheses else "plan"


def after_investigate(state: Case) -> str:
    if state.stop_reason is None:
        return "run_tools"
    return "check_coverage" if state.stop_reason == "agent_done" else "summarize_findings"


def after_run_tools(state: Case) -> str:
    return "summarize_findings" if state.stop_reason == "budget" else "investigate"


def after_check_coverage(state: Case) -> str:
    return "investigate" if state.stop_reason is None else "summarize_findings"


def after_review(state: Case) -> str:
    return INVESTIGATOR_NODE if state.stop_reason is None else END


def build_investigator(deps: Deps) -> CompiledStateGraph:
    graph = StateGraph(Case)
    for name, node in make_investigator(deps).items():
        graph.add_node(name, node)
    graph.add_conditional_edges(START, investigator_entry, ["plan", "investigate"])
    graph.add_edge("plan", "investigate")
    graph.add_conditional_edges(
        "investigate", after_investigate, ["run_tools", "check_coverage", "summarize_findings"]
    )
    graph.add_conditional_edges("run_tools", after_run_tools, ["investigate", "summarize_findings"])
    graph.add_conditional_edges(
        "check_coverage", after_check_coverage, ["investigate", "summarize_findings"]
    )
    graph.add_edge("summarize_findings", END)
    return graph.compile()


def build_chain(deps: Deps) -> CompiledStateGraph:
    graph = StateGraph(Case)
    graph.add_node(TRIAGE_NODE, make_triage(deps))
    graph.add_node(INTEL_NODE, make_intel(deps))
    graph.add_node(INVESTIGATOR_NODE, build_investigator(deps))
    graph.add_node(REVIEWER_NODE, make_reviewer(deps))
    graph.add_edge(START, TRIAGE_NODE)
    graph.add_edge(TRIAGE_NODE, INTEL_NODE)
    graph.add_edge(INTEL_NODE, INVESTIGATOR_NODE)
    graph.add_edge(INVESTIGATOR_NODE, REVIEWER_NODE)
    graph.add_conditional_edges(REVIEWER_NODE, after_review, [INVESTIGATOR_NODE, END])
    return graph.compile()


OnStep = Callable[[str, dict[str, Any]], None]


@dataclass
class RunResult:
    state: Case
    seconds: float
    timed_out: bool


async def run_case(deps: Deps, alert: Alert, on_step: OnStep | None = None) -> RunResult:
    """One investigation under the overall timeout. `on_step(node, update)` sees each node's
    update as it happens, inside the investigator too. On timeout the last complete state comes
    back with timed_out=True."""
    graph = build_chain(deps)
    config: RunnableConfig = {"recursion_limit": deps.settings.recursion_limit}
    started = time.monotonic()
    latest: dict[str, Any] = {}

    async def consume() -> None:
        async for _, mode, chunk in graph.astream(
            Case(alert=alert), config, stream_mode=["updates", "values"], subgraphs=True
        ):
            if mode == "values":
                latest.clear()
                latest.update(chunk)
            elif on_step is not None:
                for node, update in chunk.items():
                    # The parent's view of the subgraph repeats what its nodes already reported.
                    if node != INVESTIGATOR_NODE:
                        on_step(node, update or {})

    timed_out = False
    try:
        await asyncio.wait_for(consume(), timeout=deps.settings.run_timeout_s)
    except TimeoutError:
        timed_out = True
    state = Case.model_validate(latest) if latest else Case(alert=alert)
    seconds = time.monotonic() - started
    log.info(
        "run %s: priority %s, %d/%d investigator tool calls, %d reviewer calls, stop=%s, %.0fs%s",
        alert.alert_id,
        state.triage.priority if state.triage else "?",
        state.tool_calls_used,
        state.investigator_budget,
        state.review_calls_used,
        state.stop_reason,
        seconds,
        " (timed out)" if timed_out else "",
    )
    return RunResult(state, seconds, timed_out)
