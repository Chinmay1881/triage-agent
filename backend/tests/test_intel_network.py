"""CyberIntel-Agent's network enrichment: a C2 address appears in network activity, not in the tree,
so code looks it up without waiting for the model to think of it."""

from typing import Any

import pytest

from app.agent.agents.closure import KNOWN_BAD_IN_CASE
from app.agent.agents.intel import network_calls, network_indicators
from app.agent.case import Evidence
from app.config import CYBERINTEL
from app.ml.injection import InjectionModel
from tests.test_agent_graph import ALERT, TREE_RESULT, deps, run

C2_IP = "203.0.113.200"
C2_DOMAIN = "c2-host.example"
QUIET_IP = "198.51.100.7"
INTERNAL_IP = "10.0.0.5"
TREE = TREE_RESULT["untrusted_log_data"]


@pytest.fixture(autouse=True)
def _classifier(trained_classifier: InjectionModel) -> None:
    """The chain scans tool results, which needs the classifier."""


def connections(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("process_name") != "msupdate.exe":
        return {"untrusted_log_data": [], "total": 0, "shown": 0}
    rows = [{"dst_ip": ip, "dst_port": 443, "event_ids": []} for ip in (C2_IP, INTERNAL_IP)]
    return {"untrusted_log_data": rows, "total": 2, "shown": 2}


def dns(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("process_name") != "msupdate.exe":
        return {"untrusted_log_data": [], "total": 0, "shown": 0}
    rows = [{"domain": C2_DOMAIN, "answers": [QUIET_IP], "event_ids": []}]
    return {"untrusted_log_data": rows, "total": 1, "shown": 1}


def feed(args: dict[str, Any]) -> dict[str, Any]:
    known = {C2_IP: "known_bad", C2_DOMAIN: "known_bad"}
    reputation = known.get(args["indicator"], "unknown")
    return {
        "untrusted_log_data": {
            "indicator": args["indicator"],
            "type": args["type"],
            "reputation": reputation,
        }
    }


NETWORK = {
    "get_network_connections": connections,
    "get_dns_queries": dns,
    "check_reputation": feed,
}


def test_each_tree_process_gets_both_calls_with_the_trigger_first() -> None:
    calls = network_calls(ALERT, [TREE])

    names = [args["process_name"] for _, args in calls[::2]]
    assert names == ["powershell.exe", "msupdate.exe", "AdminToolkit.exe"]
    assert [tool for tool, _ in calls[:2]] == ["get_network_connections", "get_dns_queries"]
    assert all(args["host"] == "FIN-WS-01" and "around" in args for _, args in calls)


def test_a_process_seen_twice_is_called_once() -> None:
    assert len(network_calls(ALERT, [TREE, TREE])) == 6


def test_indicators_put_ips_first_and_skip_internal_and_known_ones() -> None:
    answers = [dns({"process_name": "msupdate.exe"}), connections({"process_name": "msupdate.exe"})]

    found = network_indicators(answers, Evidence(looked_up=[QUIET_IP]))

    assert found == [(C2_IP, "ip"), (C2_DOMAIN, "domain")]


async def test_a_c2_in_network_activity_reaches_the_ledger_and_the_brief() -> None:
    d, _, _ = deps(results=NETWORK)

    state = (await run(d)).state

    assert state.evidence.reputations[C2_IP] == "known_bad"
    assert state.evidence.reputations[C2_DOMAIN] == "known_bad"
    assert state.intel_brief is not None
    listed = {r["indicator"] for r in state.intel_brief.reputation}
    assert {C2_IP, C2_DOMAIN} <= listed


async def test_unknown_lookups_stay_out_of_the_brief_and_internal_ips_arent_looked_up() -> None:
    d, _, _ = deps(results=NETWORK)

    state = (await run(d)).state

    assert state.evidence.reputations[QUIET_IP] == "unknown"
    assert state.intel_brief is not None
    assert QUIET_IP not in {r["indicator"] for r in state.intel_brief.reputation}
    assert INTERNAL_IP not in state.evidence.reputations


async def test_enrichment_is_code_run_and_charged_to_no_budget() -> None:
    d, _, _ = deps(results=NETWORK)

    state = (await run(d)).state

    records = [
        r
        for r in state.tool_logs[CYBERINTEL]
        if r.name in ("get_network_connections", "get_dns_queries")
    ]
    assert len(records) == 6 and all(r.source == "code" for r in records)
    assert state.tool_calls_used == 0 and state.review_calls_used == 0


async def test_the_lookup_cap_keeps_the_ips_and_is_noted_in_the_report() -> None:
    d, _, _ = deps(results=NETWORK, intel_max_network_indicators=1)

    state = (await run(d)).state

    assert state.evidence.reputations[C2_IP] == "known_bad"
    assert C2_DOMAIN not in state.evidence.reputations
    assert "Network enrichment hit its cap: 0 network call(s) and 2 reputation lookup(s)" in (
        state.report_md or ""
    )


async def test_the_process_cap_limits_the_calls_and_is_noted() -> None:
    d, _, calls = deps(results=NETWORK, intel_max_network_processes=1)

    state = (await run(d)).state

    network = [c for c in calls if c[0] in ("get_network_connections", "get_dns_queries")]
    assert len(network) == 2 and network[0][1]["process_name"] == "powershell.exe"
    assert "4 network call(s)" in (state.report_md or "")


async def test_no_cap_note_when_everything_fits() -> None:
    d, _, _ = deps(results=NETWORK)

    assert "Network enrichment hit its cap" not in ((await run(d)).state.report_md or "")


async def test_a_c2_found_only_in_network_activity_blocks_a_benign_verdict() -> None:
    benign = {
        "verdict": "benign",
        "confidence": 0.95,
        "reasoning": "Routine.",
        "supporting_benign": ["F1"],
    }
    d, _, _ = deps({"assess": [benign]}, results=NETWORK)

    state = (await run(d)).state

    assert state.verdict == "suspicious" and KNOWN_BAD_IN_CASE in state.verdict_notes
