"""The agent graph, built by hand (no prebuilt agents):

    START -> ingest -> plan -> investigate
    investigate -> run_tools           if the model called tools
    investigate -> check_coverage      if it stopped calling tools
    investigate -> summarize_findings  if the budget or the LLM ran out
    run_tools -> investigate           while budget is left, else -> summarize_findings
    check_coverage -> investigate      a minimum-investigation rule is unmet (each rule once)
    check_coverage -> summarize_findings
    summarize_findings -> critic
    critic -> investigate              reopen, at most once, with budget left
    critic -> END

Bounds (hard rule 8): the tool budget is enforced in code by run_tools; each coverage rule
and the critic send the run back at most once; LangGraph's recursion limit and an overall
timeout (run_investigation) stop anything else. Every routing decision reads `stop_reason`,
which only the nodes set.
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
from pymongo.asynchronous.database import AsyncDatabase

from app.agent.nodes import Deps, make_nodes
from app.agent.state import AgentState
from app.telemetry.models import Alert

log = logging.getLogger(__name__)


class MongoTelemetry:
    """The read-only telemetry db (the telemetry_reader user), for ingest."""

    def __init__(self, db: AsyncDatabase) -> None:
        self._db = db

    async def alert(self, alert_id: str) -> Alert | None:
        doc = await self._db.alerts.find_one({"alert_id": alert_id}, {"_id": 0})
        return Alert.model_validate(doc) if doc else None

    async def events(self, event_ids: list[str]) -> list[dict[str, Any]]:
        docs = await self._db.events.find({"event_id": {"$in": event_ids}}, {"_id": 0}).to_list()
        order = {eid: i for i, eid in enumerate(event_ids)}
        return sorted(docs, key=lambda d: order[d["event_id"]])


def after_investigate(state: AgentState) -> str:
    if state.stop_reason is None:
        return "run_tools"
    return "check_coverage" if state.stop_reason == "agent_done" else "summarize_findings"


def after_run_tools(state: AgentState) -> str:
    return "summarize_findings" if state.stop_reason == "budget" else "investigate"


def after_check_coverage(state: AgentState) -> str:
    return "investigate" if state.stop_reason is None else "summarize_findings"


def after_critic(state: AgentState) -> str:
    return "investigate" if state.stop_reason is None else END


def build_graph(deps: Deps) -> CompiledStateGraph:
    graph = StateGraph(AgentState)
    for name, node in make_nodes(deps).items():
        graph.add_node(name, node)
    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "plan")
    graph.add_edge("plan", "investigate")
    graph.add_conditional_edges(
        "investigate", after_investigate, ["run_tools", "check_coverage", "summarize_findings"]
    )
    graph.add_conditional_edges("run_tools", after_run_tools, ["investigate", "summarize_findings"])
    graph.add_conditional_edges(
        "check_coverage", after_check_coverage, ["investigate", "summarize_findings"]
    )
    graph.add_edge("summarize_findings", "critic")
    graph.add_conditional_edges("critic", after_critic, ["investigate", END])
    return graph.compile()


OnStep = Callable[[str, dict[str, Any]], None]


@dataclass
class RunResult:
    state: AgentState
    seconds: float
    timed_out: bool


async def run_investigation(deps: Deps, alert: Alert, on_step: OnStep | None = None) -> RunResult:
    """One investigation under the overall timeout. `on_step(node, update)` sees each node's
    update as it happens. On timeout the last complete state comes back with timed_out=True."""
    graph = build_graph(deps)
    config: RunnableConfig = {"recursion_limit": deps.settings.recursion_limit}
    started = time.monotonic()
    latest: dict[str, Any] = {}

    async def consume() -> None:
        async for mode, chunk in graph.astream(
            AgentState(alert=alert), config, stream_mode=["updates", "values"]
        ):
            if mode == "values":
                latest.clear()
                latest.update(chunk)
            elif on_step is not None:
                for node, update in chunk.items():
                    on_step(node, update or {})

    timed_out = False
    try:
        await asyncio.wait_for(consume(), timeout=deps.settings.run_timeout_s)
    except TimeoutError:
        timed_out = True
    state = AgentState.model_validate(latest) if latest else AgentState(alert=alert)
    seconds = time.monotonic() - started
    log.info(
        "run %s: %d/%d tool calls, stop=%s, %.0fs%s",
        alert.alert_id,
        state.tool_calls_used,
        deps.settings.tool_budget,
        state.stop_reason,
        seconds,
        " (timed out)" if timed_out else "",
    )
    return RunResult(state, seconds, timed_out)
