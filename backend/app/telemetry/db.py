"""Telemetry access for the tools. Always the read-only `telemetry_reader` user, so even a
bug in a tool can't write: MongoDB itself refuses (see tests/test_mongo_users.py)."""

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from app.config import get_settings


def telemetry_client() -> AsyncMongoClient:
    uri = get_settings().telemetry_mongo_uri.get_secret_value()
    # tz_aware so timestamps come back as UTC datetimes, matching the models.
    return AsyncMongoClient(uri, tz_aware=True, serverSelectionTimeoutMS=3000)


def telemetry_db(client: AsyncMongoClient) -> AsyncDatabase:
    return client.get_default_database()
