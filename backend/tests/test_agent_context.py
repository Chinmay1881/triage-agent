"""app/agent/context.py: shortened tool results keep what the agent needs to pivot on."""

import json

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from app.agent.context import event_ids_in, identifiers, render_history, shrink, tokens, transcript

TREE = {
    "untrusted_log_data": {
        "host": "FIN-WS-03",
        "process": {
            "event_id": "evt_000101",
            "pid": 4120,
            "ppid": 3876,
            "name": "powershell.exe",
            "user": "priya.n",
            "sha256": "a" * 64,
            "cmdline": "powershell -nop " + "x" * 400,
        },
        "ancestors": [{"event_id": "evt_000099", "pid": 3876, "name": "WINWORD.EXE"}],
        "activity": [{"event_id": "evt_000102", "task_name": "Updater", "run_as": "SYSTEM"}],
    },
    "children_total": 0,
}
NETWORK = {
    "untrusted_log_data": [
        {
            "dst_ip": "203.0.113.10",
            "domains": ["files.example"],
            "processes": [{"name": "rclone.exe", "pid": 77}],
            "event_ids": ["evt_000201", "evt_000202"],
        }
    ],
    "total": 1,
    "shown": 1,
}


def test_identifiers_keep_pivots_from_a_process_tree() -> None:
    ids = identifiers(TREE["untrusted_log_data"])

    assert ids["event_ids"] == ["evt_000101", "evt_000099", "evt_000102"]
    assert ids["hosts"] == ["FIN-WS-03"]
    assert ids["users"] == ["priya.n", "SYSTEM"]
    assert ids["pids"] == [4120, 3876]
    assert ids["sha256"] == ["a" * 64]
    assert ids["tasks"] == ["Updater"]


def test_identifiers_keep_ips_and_domains_from_network_groups() -> None:
    ids = identifiers(NETWORK["untrusted_log_data"])

    assert ids["ips"] == ["203.0.113.10"]
    assert ids["domains"] == ["files.example"]
    assert ids["event_ids"] == ["evt_000201", "evt_000202"]
    assert ids["pids"] == [77]


def test_shrunk_result_stays_under_untrusted_log_data() -> None:
    small = shrink(TREE, "ids")

    assert set(small) == {"shortened", "untrusted_log_data"}
    assert "cmdline" not in json.dumps(small)
    rows = shrink(TREE, "rows")["untrusted_log_data"]["rows"]
    assert len(rows["process"]["cmdline"]) == 100


def test_errors_pass_through_unshrunk() -> None:
    assert shrink({"error": "no host named X"}, "ids") == {"error": "no host named X"}


def test_event_ids_in_is_uncapped() -> None:
    many = {"untrusted_log_data": [{"event_id": f"evt_{i:06d}"} for i in range(40)]}

    assert len(event_ids_in(many)) == 40


def conversation(n: int) -> list:
    messages = [HumanMessage("case")]
    for i in range(n):
        call = {"name": "get_process_tree", "args": {"event_id": "evt_000101"}, "id": f"c{i}"}
        messages.append(AIMessage("", tool_calls=[call | {"type": "tool_call"}]))
        messages.append(
            ToolMessage(json.dumps(TREE), tool_call_id=f"c{i}", name="get_process_tree")
        )
    return messages


def test_render_history_keeps_last_two_results_in_full() -> None:
    rendered = render_history(conversation(4))

    tool_contents = [json.loads(m.content) for m in rendered if isinstance(m, ToolMessage)]
    assert [c.get("shortened", False) for c in tool_contents] == [True, True, False, False]
    assert tool_contents[0]["untrusted_log_data"]["identifiers"]["event_ids"][0] == "evt_000101"


def test_transcript_falls_back_to_identifiers_over_budget() -> None:
    roomy = transcript(conversation(3), budget_tokens=100_000)
    tight = transcript(conversation(3), budget_tokens=tokens(roomy) - 1)

    assert all("rows" in e["result"]["untrusted_log_data"] for e in roomy)
    assert "rows" not in tight[0]["result"]["untrusted_log_data"]
    assert all(e["tool"] == "get_process_tree" for e in tight)
