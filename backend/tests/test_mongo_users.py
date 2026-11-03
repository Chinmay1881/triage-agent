"""Proves the database itself enforces each user's limits, not just our code.

Needs the container from `python tasks.py up` and a filled-in .env; skips otherwise.
"""

from collections.abc import AsyncIterator, Callable

import pytest
from pydantic import ValidationError
from pymongo import AsyncMongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

from app.config import get_settings
from scripts.load import SeederSettings

pytestmark = pytest.mark.mongo

UNAUTHORIZED = 13
AUTHENTICATION_FAILED = 18


async def connect(get_uri: Callable[[], str], name: str) -> AsyncMongoClient:
    try:
        uri = get_uri()
    except ValidationError:
        pytest.skip(f"{name} not set; copy .env.example to .env")
    client: AsyncMongoClient = AsyncMongoClient(uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except ServerSelectionTimeoutError:
        await client.close()
        pytest.skip("MongoDB not reachable; run `python tasks.py up`")
    except OperationFailure as exc:
        await client.close()
        if exc.code != AUTHENTICATION_FAILED:
            raise
        pytest.skip(
            f"{name} rejected by MongoDB; users are created only on a fresh volume, "
            "so run `python tasks.py down --volumes` then `python tasks.py up`"
        )
    return client


@pytest.fixture
async def reader() -> AsyncIterator[AsyncMongoClient]:
    client = await connect(
        lambda: get_settings().telemetry_mongo_uri.get_secret_value(), "TELEMETRY_MONGO_URI"
    )
    yield client
    await client.close()


@pytest.fixture
async def seeder() -> AsyncIterator[AsyncMongoClient]:
    client = await connect(
        lambda: SeederSettings().seeder_mongo_uri.get_secret_value(), "SEEDER_MONGO_URI"
    )
    yield client
    await client.close()


async def test_reader_can_read_telemetry(reader: AsyncMongoClient) -> None:
    # Guards the write tests: they must fail for lack of permission, not bad credentials.
    await reader["telemetry"]["events"].find_one()


@pytest.mark.parametrize("db_name", ["telemetry", "triage"])
async def test_reader_cannot_insert(reader: AsyncMongoClient, db_name: str) -> None:
    with pytest.raises(OperationFailure) as exc_info:
        await reader[db_name]["events"].insert_one({"event_id": "evt_write_probe"})

    assert exc_info.value.code == UNAUTHORIZED


async def test_reader_cannot_drop_collection(reader: AsyncMongoClient) -> None:
    with pytest.raises(OperationFailure) as exc_info:
        await reader["telemetry"].drop_collection("events")

    assert exc_info.value.code == UNAUTHORIZED


async def test_seeder_can_write_telemetry(seeder: AsyncMongoClient) -> None:
    # A scratch collection, so the probe never touches seeded data.
    probe = seeder["telemetry"]["_seeder_probe"]
    await probe.insert_one({"probe": True})
    await seeder["telemetry"].drop_collection("_seeder_probe")


async def test_seeder_cannot_insert_into_triage(seeder: AsyncMongoClient) -> None:
    with pytest.raises(OperationFailure) as exc_info:
        await seeder["triage"]["investigations"].insert_one({"probe": True})

    assert exc_info.value.code == UNAUTHORIZED


async def test_seeder_cannot_drop_triage_collection(seeder: AsyncMongoClient) -> None:
    with pytest.raises(OperationFailure) as exc_info:
        await seeder["triage"].drop_collection("investigations")

    assert exc_info.value.code == UNAUTHORIZED
