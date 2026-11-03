"""Every key event of every scenario, in every variant, is reachable with the tools.

Each scenario has a scripted analyst path (scripts/analyst_paths.py) that starts from the
alert and picks every later argument from earlier tool output. If a key event can't be
reached that way, no agent could cite it, so the scenario (or a tool) is broken.

Loading variants 2 and 3 replaces the dev telemetry; variant 1 (what `seed` loads) is put
back after each variant, so the database ends as it started.
"""

from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any

import pytest
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.database import Database

from app.tools._common import TOKEN_CAP, estimate_tokens
from scripts.analyst_paths import PATHS, Analyst, cited_event_ids, investigate
from scripts.gen.dataset import VARIANTS, Dataset
from scripts.gen.infra import CORPORATE_VPN_EGRESS
from scripts.gen.scenario import AlertDraft
from scripts.load import load_collections

pytestmark = pytest.mark.mongo


@pytest.fixture(scope="module", params=VARIANTS, ids=lambda v: f"variant{v}")
def loaded(
    request: pytest.FixtureRequest, seeder_db: Database, datasets: dict[int, Dataset]
) -> Iterator[Dataset]:
    # try/finally so variant 1 is restored even if loading this variant fails partway.
    try:
        load_collections(seeder_db, datasets[request.param].collections())
        yield datasets[request.param]
    finally:
        load_collections(seeder_db, datasets[1].collections())


@pytest.mark.parametrize("scenario_id", sorted(PATHS))
async def test_key_events_reachable_from_alert(
    loaded: Dataset, tools_db: AsyncDatabase, scenario_id: str
) -> None:
    result = next(r for r in loaded.scenarios if r.scenario_id == scenario_id)

    analyst = await investigate(tools_db, scenario_id, result.alert.alert_id)

    seen = set().union(*(cited_event_ids(step.result) for step in analyst.steps))
    missing = {e.event_id for e in result.key_events} - seen
    assert not missing, f"{scenario_id}: key events no tool call returned: {sorted(missing)}"
    for step in analyst.steps:
        assert estimate_tokens(step.result) <= TOKEN_CAP, (step.tool, step.args)


def outputs(analyst: Analyst, tool: str) -> list[Any]:
    return [s.result["untrusted_log_data"] for s in analyst.steps if s.tool == tool]


def reputations(analyst: Analyst) -> dict[str, str]:
    return {r["indicator"]: r["reputation"] for r in outputs(analyst, "check_reputation")}


def check_s08(analyst: Analyst, alert: AlertDraft) -> None:
    (tree,) = outputs(analyst, "get_process_tree")
    launcher = tree["ancestors"][0]
    assert launcher["signer"] == "Northbeam Software Ltd"
    assert reputations(analyst)[launcher["sha256"]] == "known_good"


def check_s09(analyst: Analyst, alert: AlertDraft) -> None:
    trip, before = outputs(analyst, "get_logon_history")
    assert all(r["src_ip"] == CORPORATE_VPN_EGRESS and r["mfa"] for r in trip)
    assert {r["country"] for r in trip} == {"IE"}
    assert "IE" not in {r["country"] for r in before}
    (user,) = outputs(analyst, "get_user_info")
    assert "IE" in user["usual_countries"]
    assert reputations(analyst)[CORPORATE_VPN_EGRESS] == "known_good"


def check_s10(analyst: Analyst, alert: AlertDraft) -> None:
    (tree,) = outputs(analyst, "get_process_tree")
    job = tree["process"]
    assert tree["host"] == "BKP-01" and job["user"] == "svc_backup"
    assert job["signer"] == "Vaultline Ltd" and "--schedule" in job["cmdline"]
    assert 1 <= datetime.fromisoformat(job["ts"]).hour < 3
    assert reputations(analyst)[job["sha256"]] == "known_good"
    (night_before,) = outputs(analyst, "search_process_events")
    assert any(
        r["user"] == "svc_backup" and datetime.fromisoformat(r["ts"]).hour == 1
        for r in night_before
    ), "the backup account should run at the same hour the night before"


def check_s11(analyst: Analyst, alert: AlertDraft) -> None:
    (tree,) = outputs(analyst, "get_process_tree")
    creator = tree["process"]
    assert creator["signer"] == "Adobe Inc."
    assert reputations(analyst)[creator["sha256"]] == "known_good"
    (tasks,) = outputs(analyst, "get_persistence_events")
    assert next(t for t in tasks if t["event_id"] == alert.triggers[0].event_id)["run_as"] == (
        "SYSTEM"
    )


BENIGN_EVIDENCE: dict[str, Callable[[Analyst, AlertDraft], None]] = {
    "s08": check_s08,
    "s09": check_s09,
    "s10": check_s10,
    "s11": check_s11,
}


@pytest.mark.parametrize("scenario_id", sorted(BENIGN_EVIDENCE))
async def test_benign_evidence_visible_in_tool_output(
    loaded: Dataset, tools_db: AsyncDatabase, scenario_id: str
) -> None:
    result = next(r for r in loaded.scenarios if r.scenario_id == scenario_id)
    assert result.verdict == "benign"

    analyst = await investigate(tools_db, scenario_id, result.alert.alert_id)

    BENIGN_EVIDENCE[scenario_id](analyst, result.alert)
