"""Proves the database itself enforces read-only access, not just our code.

Needs the container from `python tasks.py up` and a filled-in .env; skips otherwise.
"""

from collections.abc import AsyncIterator

import pytest
from pydantic import ValidationError
from pymongo import AsyncMongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

from app.config import get_settings

pytestmark = pytest.mark.mongo

UNAUTHORIZED = 13


@pytest.fixture
async def reader() -> AsyncIterator[AsyncMongoClient]:
    try:
        uri = get_settings().telemetry_mongo_uri.get_secret_value()
    except ValidationError:
        pytest.skip("TELEMETRY_MONGO_URI not set; copy .env.example to .env")
    client: AsyncMongoClient = AsyncMongoClient(uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except ServerSelectionTimeoutError:
        await client.close()
        pytest.skip("MongoDB not reachable; run `python tasks.py up`")
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
