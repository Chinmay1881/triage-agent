"""Load data/generated/*.jsonl into the Mongo `telemetry` db as the `seeder` user.

    uv run --project backend python scripts/load.py

Replaces the five collections and builds their indexes. Reads only data/generated/:
ground truth (scenarios/truth/) never goes into Mongo, so no tool can query it.
"""

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from pymongo import ASCENDING, IndexModel, MongoClient
from pymongo.database import Database
from pymongo.errors import PyMongoError

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "data" / "generated"

INDEXES: dict[str, list[IndexModel]] = {
    "events": [
        IndexModel([("event_id", ASCENDING)], unique=True),
        IndexModel([("host", ASCENDING), ("ts", ASCENDING)]),
        IndexModel([("user", ASCENDING), ("ts", ASCENDING)]),
    ],
    "hosts": [IndexModel([("hostname", ASCENDING)], unique=True)],
    "users": [IndexModel([("username", ASCENDING)], unique=True)],
    "intel": [IndexModel([("indicator", ASCENDING)], unique=True)],
    "alerts": [IndexModel([("alert_id", ASCENDING)], unique=True)],
}


class SeederSettings(BaseSettings):
    """Kept here, not in app.config, so the backend never even sees the write credential."""

    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    seeder_mongo_uri: SecretStr


def read_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            # Stored as BSON dates, not strings, so the tools can range-query on time.
            if "ts" in row:
                row["ts"] = datetime.fromisoformat(row["ts"])
            rows.append(row)
    return rows


def load_collections(db: Database, collections: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    """Replace each telemetry collection with `collections[name]` and rebuild its indexes.
    Also used by the tool tests to load other variants."""
    for name, indexes in INDEXES.items():
        rows = collections[name]
        db.drop_collection(name)
        if rows:
            db[name].insert_many(rows, ordered=False)
        db[name].create_indexes(indexes)
    return {name: len(collections[name]) for name in INDEXES}


def main() -> int:
    try:
        uri = SeederSettings().seeder_mongo_uri.get_secret_value()
    except ValidationError:
        print("error: SEEDER_MONGO_URI is not set in .env (see .env.example)", file=sys.stderr)
        return 1
    missing = [c for c in INDEXES if not (GENERATED / f"{c}.jsonl").exists()]
    if missing:
        print(f"error: {GENERATED} lacks {missing}; run scripts/generate.py", file=sys.stderr)
        return 1

    client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=3000, tz_aware=True)
    try:
        db = client.get_default_database()
        loaded = load_collections(db, {n: read_rows(GENERATED / f"{n}.jsonl") for n in INDEXES})
        for name, n in loaded.items():
            print(f"loaded {n:>6} {name}")
        counts = Counter(e["event_type"] for e in db["events"].find({}, {"event_type": 1}))
        print("events by type:")
        for event_type, n in sorted(counts.items()):
            print(f"  {event_type:<15} {n:>6}")
    except PyMongoError as exc:
        print(f"error: MongoDB: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
