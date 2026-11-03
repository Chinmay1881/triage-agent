"""Every key event of every scenario, in every variant, is reachable with the tools.

Each scenario has a scripted analyst path (scripts/analyst_paths.py) that starts from the
alert and picks every later argument from earlier tool output. If a key event can't be
reached that way, no agent could cite it, so the scenario (or a tool) is broken.

Loading variants 2 and 3 replaces the dev telemetry; variant 1 (what `seed` loads) is put
back after each variant, so the database ends as it started.
"""

from collections.abc import Iterator

import pytest
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.database import Database

from app.tools._common import TOKEN_CAP, estimate_tokens
from scripts.analyst_paths import PATHS, cited_event_ids, investigate
from scripts.gen.dataset import VARIANTS, Dataset
from scripts.load import load_collections

pytestmark = pytest.mark.mongo


@pytest.fixture(scope="module", params=VARIANTS, ids=lambda v: f"variant{v}")
def loaded(
    request: pytest.FixtureRequest, seeder_db: Database, datasets: dict[int, Dataset]
) -> Iterator[Dataset]:
    load_collections(seeder_db, datasets[request.param].collections())
    yield datasets[request.param]
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
