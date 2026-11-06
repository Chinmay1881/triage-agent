"""The 12 investigation tools: caps, validation, error handling, and results on scenario
data. Pure tests run anywhere; the rest need Mongo and load variant 1 first."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.database import Database

from app.ml import ModelMissingError
from app.ml import anomaly as anomaly_model_module
from app.telemetry.decode import UNDECODABLE, decode_encoded_command
from app.tools import TOOLS, call_tool, tool_specs
from app.tools._common import (
    CMDLINE_CHARS,
    TOKEN_CAP,
    contains,
    enforce_cap,
    estimate_tokens,
    format_duration,
    list_result,
)
from app.tools.process import ProcessSearchInput, process_row
from scripts.gen.dataset import Dataset
from scripts.gen.scenario import ScenarioResult, encode_powershell
from scripts.load import load_collections

ALERT_TS = "2026-10-06T10:00:00Z"


def scenario(ds: Dataset, scenario_id: str) -> ScenarioResult:
    return next(r for r in ds.scenarios if r.scenario_id == scenario_id)


# --- pure: no database -------------------------------------------------------------------


def test_twelve_tools_with_descriptions() -> None:
    assert len(TOOLS) == 12
    specs = [s["function"] for s in tool_specs()]
    assert sorted(s["name"] for s in specs) == sorted(TOOLS)
    assert all(len(s["description"]) > 60 for s in specs)


def test_compact_schema_keeps_constraints_and_drops_noise() -> None:
    (spec,) = [s["function"] for s in tool_specs() if s["function"]["name"] == "get_process_tree"]
    text = str(spec["parameters"])

    assert "anyOf" not in text and "'title'" not in text and "'default': None" not in text
    assert spec["parameters"]["properties"]["event_id"]["pattern"] == r"^evt_\d{6}$"
    assert spec["parameters"]["additionalProperties"] is False


def test_decode_happens_before_cap() -> None:
    script = "Write-Output 'maintenance';" * 40  # decodes to ~1,100 chars
    encoded = encode_powershell(script)
    doc = {
        "event_id": "evt_000001",
        "ts": datetime(2026, 10, 6, tzinfo=UTC),
        "user": "a.b",
        "process": {
            "pid": 8,
            "ppid": 4,
            "name": "powershell.exe",
            "parent_name": "cmd.exe",
            "cmdline": f"powershell.exe -NoP -EncodedCommand {encoded}",
            "sha256": "0" * 64,
            "signer": None,
        },
    }

    row = process_row(doc)

    assert len(encoded) > CMDLINE_CHARS  # cutting first would have broken the base64
    assert len(row["cmdline"]) == CMDLINE_CHARS and row["cmdline"].endswith("…")
    assert len(row["decoded_cmdline"]) == CMDLINE_CHARS
    assert row["decoded_cmdline"].startswith("Write-Output 'maintenance';Write-Output")
    assert row["signer"] is None and "signer" in row


@pytest.mark.parametrize("flag", ["-enc", "-EC", "-EncodedCommand", "-e"])
def test_decode_accepts_powershell_flag_forms(flag: str) -> None:
    assert decode_encoded_command(f"powershell {flag} {encode_powershell('Get-Date')}") == (
        "Get-Date"
    )


def test_decode_reports_garbage_and_ignores_plain_commands() -> None:
    assert decode_encoded_command("powershell -enc !!!!notbase64!!!!") is None
    # Valid base64 but an odd number of bytes, so it cannot be UTF-16LE.
    assert decode_encoded_command("powershell -enc QUJDREVGRw==") == UNDECODABLE
    assert decode_encoded_command("powershell -ExecutionPolicy Bypass -File x.ps1") is None


def test_list_result_caps_tokens_and_says_narrow() -> None:
    rows = [{"event_id": f"evt_{i:06d}", "cmdline": "x" * 300} for i in range(25)]

    result = list_result(rows, total=40)

    assert estimate_tokens(result) <= TOKEN_CAP
    assert result["total"] == 40 and result["shown"] < 25
    assert "narrow your search" in result["note"]


def test_enforce_cap_never_passes_oversized_results() -> None:
    huge = {"untrusted_log_data": ["y" * 10_000], "total": 1}

    capped = enforce_cap(huge)

    assert "untrusted_log_data" not in capped
    assert "narrow your search" in capped["note"]


def test_filters_are_escaped_not_regex() -> None:
    assert contains("a.b*(c)") == {"$regex": r"a\.b\*\(c\)", "$options": "i"}


@pytest.mark.parametrize(
    ("tool", "args", "message"),
    [
        ("search_process_events", {"host": "FIN-WS-01"}, "give start and end, or around"),
        (
            "search_process_events",
            {
                "host": "FIN-WS-01",
                "around": ALERT_TS,
                "start": "2026-10-06T09:00:00Z",
                "end": "2026-10-06T11:00:00Z",
            },
            "use either around or start and end",
        ),
        (
            "get_logon_history",
            {"user": "a.b", "around": ALERT_TS, "start": "2026-10-06T09:00:00Z"},
            "use either around or start and end",
        ),
        (
            "search_process_events",
            {"host": "FIN-WS-01", "start": "2026-10-06T10:00:00Z", "end": "2026-10-06T09:00:00Z"},
            "end must be after start",
        ),
        ("search_process_events", {"host": "bad host!", "around": ALERT_TS}, "host"),
        (
            "search_process_events",
            {"host": "FIN-WS-01", "around": ALERT_TS, "rm": "-rf"},
            "Extra inputs",
        ),
        ("get_process_tree", {}, "give event_id, or all of host, pid and ts"),
        ("get_process_tree", {"event_id": "evt_1"}, "event_id"),
        ("get_logon_history", {"around": ALERT_TS}, "give user, host, or both"),
        ("check_reputation", {"indicator": "not-an-ip", "type": "ip"}, "not an IP address"),
        ("check_reputation", {"indicator": "abc", "type": "hash"}, "64-character hex"),
        ("check_reputation", {"indicator": "x.example", "type": "url"}, "type"),
        (
            "get_network_connections",
            {"host": "FIN-WS-01", "around": ALERT_TS, "remote_ip": "x"},
            "remote_ip",
        ),
        ("score_anomaly", {"event_ids": []}, "at least 1 item"),
        ("score_anomaly", {"event_ids": [f"evt_{i:06d}" for i in range(1, 12)]}, "at most 10"),
        ("score_anomaly", {"event_ids": ["evt_000001", "evt_000001"]}, "must not repeat"),
        ("score_anomaly", {"event_ids": ["evt_1"]}, "event_ids.0"),
        ("score_anomaly", {"event_ids": "evt_000001"}, "valid list"),
    ],
)
async def test_bad_inputs_return_clear_errors(
    tool: str, args: dict[str, Any], message: str
) -> None:
    # Validation runs before any database access, so no db is needed.
    result = await call_tool(tool, args, db=None)  # type: ignore[arg-type]

    assert message in result["error"]


async def test_unknown_tool_is_an_error() -> None:
    result = await call_tool("run_shell", {"cmd": "whoami"}, db=None)  # type: ignore[arg-type]

    assert "unknown tool" in result["error"]


async def test_score_anomaly_without_model_says_how_to_train(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing() -> None:
        raise ModelMissingError("anomaly model not trained; run `python tasks.py train`")

    monkeypatch.setattr(anomaly_model_module, "load", missing)

    result = await call_tool("score_anomaly", {"event_ids": ["evt_000001"]}, db=None)  # type: ignore[arg-type]

    assert "python tasks.py train" in result["error"]


async def test_attack_tools_use_pinned_catalog() -> None:
    found = await call_tool("search_attack_techniques", {"keyword": "lsass"}, db=None)  # type: ignore[arg-type]
    revoked = await call_tool("lookup_attack_technique", {"technique_id": "T1086"}, db=None)  # type: ignore[arg-type]
    fake = await call_tool("lookup_attack_technique", {"technique_id": "T1999"}, db=None)  # type: ignore[arg-type]

    assert "T1003.001" in [t["id"] for t in found["attack_catalog"]]
    assert "untrusted_log_data" not in found
    assert revoked["attack_catalog"]["revoked"] and "revoked" in revoked["note"]
    assert "not a technique in ATT&CK v20" in fake["error"]


# --- against MongoDB, variant 1 -----------------------------------------------------------


@pytest.fixture(scope="module")
def ds(seeder_db: Database, datasets: dict[int, Dataset]) -> Dataset:
    load_collections(seeder_db, datasets[1].collections())
    return datasets[1]


def alert_args(result: ScenarioResult) -> dict[str, Any]:
    return {"host": result.alert.host, "around": result.alert.ts.isoformat()}


def all_results_capped(*results: dict[str, Any]) -> bool:
    return all(estimate_tokens(r) <= TOKEN_CAP for r in results)


@pytest.mark.mongo
async def test_every_event_row_has_event_id(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s01 = scenario(ds, "s01")
    args = alert_args(s01)
    calls = {
        "search_process_events": args,
        "get_network_connections": args,
        "get_dns_queries": args,
        "get_persistence_events": args,
        "get_logon_history": {"user": s01.alert.user, "around": args["around"]},
    }
    for name, call_args in calls.items():
        result = await call_tool(name, call_args, tools_db)
        assert "untrusted_log_data" in result, (name, result)
        for row in result["untrusted_log_data"]:
            assert row.get("event_id") or row.get("event_ids"), (name, row)
        assert all_results_capped(result)


@pytest.mark.mongo
async def test_search_process_events_caps_rows(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s01 = scenario(ds, "s01")
    day = s01.alert.ts.replace(hour=0, minute=0, second=0)
    args = {
        "host": s01.alert.host,
        "start": day.isoformat(),
        "end": (day + timedelta(hours=24)).isoformat(),
    }

    result = await call_tool("search_process_events", args, tools_db)

    assert result["total"] > 25
    assert result["shown"] <= 25
    assert "narrow your search" in result["note"]
    assert all(len(r["cmdline"]) <= CMDLINE_CHARS for r in result["untrusted_log_data"])
    assert all_results_capped(result)


@pytest.mark.mongo
async def test_process_tree_shows_signer_and_decoded_payload(
    ds: Dataset, tools_db: AsyncDatabase
) -> None:
    s01 = scenario(ds, "s01")
    trigger = s01.alert.triggers[0].event_id

    result = await call_tool("get_process_tree", {"event_id": trigger}, tools_db)

    tree = result["untrusted_log_data"]
    assert tree["process"]["name"] == "powershell.exe"
    assert tree["process"]["signer"] == "Microsoft Windows"
    assert "invoice-portal.example" in tree["process"]["decoded_cmdline"]
    assert [a["name"] for a in tree["ancestors"]] == ["WINWORD.EXE", "OUTLOOK.EXE", "explorer.exe"]
    payload = tree["descendants"][0]
    assert payload["name"] == "msupdate.exe" and payload["signer"] is None
    assert [a["event_type"] for a in tree["activity"]] == ["file_write"]


@pytest.mark.mongo
async def test_network_groups_show_beacon_timing(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s01 = scenario(ds, "s01")
    args = alert_args(s01) | {"process_name": "msupdate.exe"}

    result = await call_tool("get_network_connections", args, tools_db)

    (group,) = result["untrusted_log_data"]
    assert group["count"] == 3 and len(group["event_ids"]) == 3
    first = datetime.fromisoformat(group["first_seen"])
    last = datetime.fromisoformat(group["last_seen"])
    assert timedelta(minutes=8) < last - first < timedelta(minutes=14)


@pytest.mark.mongo
async def test_network_groups_name_destinations(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s06 = scenario(ds, "s06")
    args = alert_args(s06) | {"process_name": "rclone.exe"}

    result = await call_tool("get_network_connections", args, tools_db)

    (group,) = result["untrusted_log_data"]
    assert group["count"] == 8
    assert group["domains"][0].endswith(".example")
    assert group["bytes_out"] > 1_000_000_000


@pytest.mark.mongo
async def test_logons_by_host_show_spray(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s03 = scenario(ds, "s03")

    result = await call_tool("get_logon_history", alert_args(s03), tools_db)

    rows = result["untrusted_log_data"]
    failures = [r for r in rows if r["result"] == "failure"]
    assert len({r["user"] for r in failures}) >= 10
    assert len({r["src_ip"] for r in failures}) == 1
    assert any(r["result"] == "success" and r["mfa"] is False for r in rows)


@pytest.mark.mongo
async def test_logons_for_guessed_account_say_not_in_directory(
    ds: Dataset, tools_db: AsyncDatabase
) -> None:
    s03 = scenario(ds, "s03")
    args = {"user": "administrator", "around": s03.alert.ts.isoformat()}

    result = await call_tool("get_logon_history", args, tools_db)

    assert result["user_in_directory"] is False
    assert result["untrusted_log_data"][0]["failure_reason"] == "unknown_user"


@pytest.mark.mongo
async def test_persistence_and_reputation(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s05 = scenario(ds, "s05")
    tasks = await call_tool("get_persistence_events", alert_args(s05), tools_db)
    c2 = next(i for i in s05.indicators if i.listed)
    bad = await call_tool("check_reputation", {"indicator": c2.indicator, "type": "ip"}, tools_db)
    unknown = await call_tool(
        "check_reputation", {"indicator": "Unseen.Example", "type": "domain"}, tools_db
    )

    task = tasks["untrusted_log_data"][0]
    assert task["trigger"] == "At logon" and task["created_by"]["name"] == "schtasks.exe"
    assert bad["untrusted_log_data"]["reputation"] == "known_bad"
    assert unknown["untrusted_log_data"]["reputation"] == "unknown"


@pytest.mark.mongo
async def test_host_and_user_info(ds: Dataset, tools_db: AsyncDatabase) -> None:
    s04 = scenario(ds, "s04")
    server = await call_tool("get_host_info", {"host": s04.alert.host.lower()}, tools_db)
    by_ip = await call_tool("get_host_info", {"host": server["untrusted_log_data"]["ip"]}, tools_db)
    user = await call_tool("get_user_info", {"user": s04.alert.user}, tools_db)

    assert by_ip == server
    assert user["untrusted_log_data"]["is_admin"] is True


@pytest.mark.mongo
@pytest.mark.parametrize(
    ("tool", "args", "message"),
    [
        ("get_host_info", {"host": "NOPE-01"}, "no host matches NOPE-01"),
        ("get_user_info", {"user": "nobody.x"}, "no account nobody.x"),
        ("search_process_events", {"host": "NOPE-01", "around": ALERT_TS}, "no host named"),
        ("get_process_tree", {"event_id": "evt_999999"}, "no event evt_999999"),
    ],
)
async def test_unknown_entities_return_errors(
    ds: Dataset, tools_db: AsyncDatabase, tool: str, args: dict[str, Any], message: str
) -> None:
    result = await call_tool(tool, args, tools_db)

    assert message in result["error"]


@pytest.mark.mongo
async def test_tree_for_event_without_process_is_an_error(
    ds: Dataset, tools_db: AsyncDatabase
) -> None:
    logon = next(e for e in ds.events if e.event_type == "logon")

    result = await call_tool("get_process_tree", {"event_id": logon.event_id}, tools_db)

    assert "no process" in result["error"]


@pytest.fixture
def pid_reuse(seeder_db: Database, datasets: dict[int, Dataset]) -> Iterator[dict[str, Any]]:
    """Variant 1 plus a PID that gets reused an hour after its first owner started."""
    ds = datasets[1]
    first = next(
        e
        for e in ds.events
        if e.event_type == "process_start" and e.process and e.process.name == "OUTLOOK.EXE"
    )
    assert first.process is not None
    pid, host = first.process.pid, first.host
    reuse_ts, child_ts = first.ts + timedelta(hours=1), first.ts + timedelta(hours=1, seconds=9)
    base = {
        "host": host,
        "user": first.user,
        "event_type": "process_start",
        "network": None,
        "dns": None,
        "logon": None,
        "file": None,
        "task": None,
        "access": None,
    }
    extra = [
        base
        | {
            "event_id": "evt_900001",
            "ts": reuse_ts,
            "process": {
                "pid": pid,
                "ppid": 4,
                "name": "notepad.exe",
                "parent_name": "System",
                "cmdline": "notepad.exe",
                "sha256": "1" * 64,
                "signer": None,
            },
        },
        base
        | {
            "event_id": "evt_900002",
            "ts": child_ts,
            "process": {
                "pid": 39996,
                "ppid": pid,
                "name": "calc.exe",
                "parent_name": "notepad.exe",
                "cmdline": "calc.exe",
                "sha256": "2" * 64,
                "signer": None,
            },
        },
    ]
    rows = ds.collections()
    rows["events"] = rows["events"] + extra
    try:
        load_collections(seeder_db, rows)
        yield {"host": host, "pid": pid, "first": first}
    finally:
        load_collections(seeder_db, ds.collections())


@pytest.mark.mongo
async def test_process_tree_resolves_reused_pid_by_time(
    pid_reuse: dict[str, Any], tools_db: AsyncDatabase
) -> None:
    child = await call_tool("get_process_tree", {"event_id": "evt_900002"}, tools_db)
    before = await call_tool(
        "get_process_tree",
        {
            "host": pid_reuse["host"],
            "pid": pid_reuse["pid"],
            "ts": (pid_reuse["first"].ts + timedelta(minutes=5)).isoformat(),
        },
        tools_db,
    )

    assert child["untrusted_log_data"]["ancestors"][0]["name"] == "notepad.exe"
    early = before["untrusted_log_data"]
    assert early["process"]["name"] == "OUTLOOK.EXE"
    assert "calc.exe" not in [d["name"] for d in early["descendants"]]


@pytest.mark.mongo
async def test_score_anomaly_scores_explains_and_caps(
    ds: Dataset,
    tools_db: AsyncDatabase,
    monkeypatch: pytest.MonkeyPatch,
    anomaly_model: anomaly_model_module.AnomalyModel,
) -> None:
    monkeypatch.setattr(anomaly_model_module, "load", lambda: anomaly_model)
    trigger = scenario(ds, "s01").alert.triggers[0].event_id
    others = [
        e.event_id
        for e in ds.events
        if e.event_type in ("process_start", "network_conn") and e.event_id != trigger
    ]
    logon = next(e.event_id for e in ds.events if e.event_type == "logon")
    found = [trigger, *others[:7], logon]

    result = await call_tool("score_anomaly", {"event_ids": [*found, "evt_999999"]}, tools_db)

    rows = result["untrusted_log_data"]
    assert [r["event_id"] for r in rows] == found
    assert result["not_found"] == ["evt_999999"]
    assert all_results_capped(result)
    for row in rows[:8]:
        assert 0 < row["score"] < 1 and 0 <= row["percentile"] <= 100
        assert len(row["stood_out"]) == 3
        assert {"feature", "value", "baseline_share"} == set(row["stood_out"][0])
    assert "not scored" in rows[8]["note"]
    assert rows[0]["percentile"] > 90


# --- windows: over-long ones are cut, not refused ---------------------------------------------


def test_long_window_is_cut_to_its_last_24_hours_with_a_note() -> None:
    params = ProcessSearchInput(
        host="FIN-WS-01", start="2026-10-05T00:00:00Z", end="2026-10-08T00:00:00Z"
    )

    start, end = params.bounds()
    assert end - start == timedelta(hours=24)
    assert end == datetime(2026, 10, 8, tzinfo=UTC)
    note = params.window_note()
    assert note is not None
    assert "72 h" in note and "2026-10-07T00:00:00Z" in note


def test_window_just_over_the_limit_says_so_exactly() -> None:
    params = ProcessSearchInput(
        host="FIN-WS-01", start="2026-10-06T13:25:00Z", end="2026-10-07T13:30:00Z"
    )

    note = params.window_note()
    assert note is not None and "24 h 5 min" in note


def test_window_of_exactly_24_hours_is_left_alone() -> None:
    params = ProcessSearchInput(
        host="FIN-WS-01", start="2026-10-06T00:00:00Z", end="2026-10-07T00:00:00Z"
    )

    assert params.window_note() is None


@pytest.mark.parametrize(
    ("span", "text"),
    [
        (timedelta(hours=24), "24 h"),
        (timedelta(hours=24, minutes=5), "24 h 5 min"),
        (timedelta(hours=24, seconds=1), "24 h 1 min"),
        (timedelta(hours=72), "72 h"),
    ],
)
def test_format_duration_never_rounds_down_to_the_limit(span: timedelta, text: str) -> None:
    assert format_duration(span) == text


@pytest.mark.mongo
async def test_long_window_result_carries_the_note(ds: Dataset, tools_db: AsyncDatabase) -> None:
    args = {
        "host": scenario(ds, "s01").alert.host,
        "start": "2026-10-05T00:00:00Z",
        "end": "2026-10-08T00:00:00Z",
    }

    result = await call_tool("search_process_events", args, tools_db)

    assert "error" not in result and "72 h" in result["window_note"]
    assert all_results_capped(result)
