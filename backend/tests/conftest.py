import os
from collections.abc import AsyncIterator, Iterator

import pytest
from pydantic import ValidationError
from pymongo import MongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.database import Database
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

# Set before any app module is imported so no test can reach the real LLM API.
os.environ["LLM_MODE"] = "mock"

from app.telemetry.db import telemetry_client, telemetry_db
from scripts.gen.dataset import VARIANTS, Dataset, build_dataset
from scripts.load import SeederSettings

SEED = 42


@pytest.fixture(scope="session")
def datasets() -> dict[int, Dataset]:
    """All three variants of seed 42, built in memory once per test session."""
    return {variant: build_dataset(SEED, variant) for variant in VARIANTS}


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
