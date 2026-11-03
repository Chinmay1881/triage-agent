import os
from collections.abc import AsyncIterator, Iterator
from functools import cache

import pytest
from pydantic import ValidationError
from pymongo import MongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.database import Database
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

# Set before any app module is imported so no test can reach the real LLM API.
os.environ["LLM_MODE"] = "mock"

from app.config import get_settings
from app.telemetry.db import telemetry_client, telemetry_db
from scripts.gen.dataset import VARIANTS, Dataset, build_dataset
from scripts.load import SeederSettings

SEED = 42


@cache
def dataset(variant: int) -> Dataset:
    return build_dataset(SEED, variant)


def pytest_sessionstart(session: pytest.Session) -> None:
    """Stop at once if the dev telemetry isn't variant 1 (what `seed` loads), e.g. after an
    interrupted test run that had loaded another variant. Mongo being down is fine: the
    Mongo tests skip themselves."""
    try:
        uri = get_settings().telemetry_mongo_uri.get_secret_value()
    except ValidationError:
        return
    client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=2000, tz_aware=True)
    try:
        db = client.get_default_database()
        stored = list(db.alerts.find({}, {"_id": 0}).sort("alert_id", 1))
        event_count = db.events.estimated_document_count()
    except (ServerSelectionTimeoutError, OperationFailure):
        return
    finally:
        client.close()
    expected = dataset(1)
    if stored != [a.model_dump() for a in expected.alerts] or event_count != len(expected.events):
        pytest.exit(
            "dev telemetry in MongoDB is not seed 42 variant 1 "
            f"({len(stored)} alerts, {event_count} events); run `python tasks.py seed`",
            returncode=1,
        )


@pytest.fixture(scope="session")
def datasets() -> dict[int, Dataset]:
    """All three variants of seed 42, built in memory once per test session."""
    return {variant: dataset(variant) for variant in VARIANTS}


@pytest.fixture(scope="session")
def seeder_db() -> Iterator[Database]:
    """Write access to telemetry, for loading a variant before tool tests. Skips if Mongo
    or the seeder user isn't available."""
    try:
        uri = SeederSettings().seeder_mongo_uri.get_secret_value()
    except ValidationError:
        pytest.skip("SEEDER_MONGO_URI not set; copy .env.example to .env")
    client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=2000, tz_aware=True)
    try:
        client.admin.command("ping")
    except ServerSelectionTimeoutError:
        client.close()
        pytest.skip("MongoDB not reachable; run `python tasks.py up`")
    except OperationFailure:
        client.close()
        pytest.skip("seeder rejected; run `python tasks.py down --volumes` then `up`")
    yield client.get_default_database()
    client.close()


@pytest.fixture
async def tools_db() -> AsyncIterator[AsyncDatabase]:
    """The read-only database the tools use in production."""
    client = telemetry_client()
    yield telemetry_db(client)
    await client.close()
