"""Where runs, their step events and analyst decisions live: Mongo db `triage`, user `app`.

Decisions are append-only: there is no update or delete for them here. Each record is flat and
self-contained, so Phase 5 can count agent verdict against analyst verdict with one query:
`decisions.find({"kind": "verdict"})` gives agent_verdict, analyst_verdict and agreed.

InMemoryStore has the same interface, for tests and the offline sample report.
"""

from datetime import UTC, datetime
from typing import Any, Protocol

from pymongo import ASCENDING, IndexModel
from pymongo.asynchronous.database import AsyncDatabase

Doc = dict[str, Any]


class Store(Protocol):
    async def create_investigation(self, doc: Doc) -> None: ...

    async def get_investigation(self, investigation_id: str) -> Doc | None: ...

    async def update_investigation(self, investigation_id: str, fields: Doc) -> None: ...

    async def latest_status_by_alert(self) -> dict[str, str]: ...

    async def mark_interrupted(self) -> int: ...

    async def append_event(self, investigation_id: str, seq: int, kind: str, data: Doc) -> None: ...

    async def events_after(self, investigation_id: str, seq: int) -> list[Doc]: ...

    async def add_decision(self, doc: Doc) -> None: ...

    async def decisions(self, investigation_id: str) -> list[Doc]: ...


ACTIVE = ("queued", "running")
INTERRUPTED = "the server restarted during this run"


def now() -> datetime:
    return datetime.now(UTC)


class MongoStore:
    def __init__(self, db: AsyncDatabase) -> None:
        self._db = db

    async def ensure_indexes(self) -> None:
        await self._db.investigations.create_indexes(
            [
                IndexModel([("investigation_id", ASCENDING)], unique=True),
                IndexModel([("alert_id", ASCENDING), ("created_at", ASCENDING)]),
            ]
        )
        await self._db.investigation_events.create_indexes(
            [IndexModel([("investigation_id", ASCENDING), ("seq", ASCENDING)], unique=True)]
        )
        await self._db.decisions.create_indexes(
            [
                IndexModel([("investigation_id", ASCENDING), ("ts", ASCENDING)]),
                IndexModel([("kind", ASCENDING)]),
            ]
        )

    async def create_investigation(self, doc: Doc) -> None:
        await self._db.investigations.insert_one(dict(doc))

    async def get_investigation(self, investigation_id: str) -> Doc | None:
        return await self._db.investigations.find_one(
            {"investigation_id": investigation_id}, {"_id": 0}
        )

    async def update_investigation(self, investigation_id: str, fields: Doc) -> None:
        await self._db.investigations.update_one(
            {"investigation_id": investigation_id}, {"$set": fields}
        )

    async def latest_status_by_alert(self) -> dict[str, str]:
        cursor = self._db.investigations.find(
            {}, {"_id": 0, "alert_id": 1, "status": 1}, sort=[("created_at", ASCENDING)]
        )
        return {doc["alert_id"]: doc["status"] async for doc in cursor}

    async def mark_interrupted(self) -> int:
        result = await self._db.investigations.update_many(
            {"status": {"$in": list(ACTIVE)}},
            {"$set": {"status": "failed", "error": INTERRUPTED, "finished_at": now()}},
        )
        return result.modified_count

    async def append_event(self, investigation_id: str, seq: int, kind: str, data: Doc) -> None:
        await self._db.investigation_events.insert_one(
            {
                "investigation_id": investigation_id,
                "seq": seq,
                "kind": kind,
                "ts": now(),
                "data": data,
            }
        )

    async def events_after(self, investigation_id: str, seq: int) -> list[Doc]:
        cursor = self._db.investigation_events.find(
            {"investigation_id": investigation_id, "seq": {"$gt": seq}},
            {"_id": 0},
            sort=[("seq", ASCENDING)],
        )
        return await cursor.to_list()

    async def add_decision(self, doc: Doc) -> None:
        await self._db.decisions.insert_one(dict(doc))

    async def decisions(self, investigation_id: str) -> list[Doc]:
        cursor = self._db.decisions.find(
            {"investigation_id": investigation_id}, {"_id": 0}, sort=[("ts", ASCENDING)]
        )
        return await cursor.to_list()


class InMemoryStore:
    def __init__(self) -> None:
        self.investigations: dict[str, Doc] = {}
        self.events: list[Doc] = []
        self.decision_log: list[Doc] = []

    async def create_investigation(self, doc: Doc) -> None:
        self.investigations[doc["investigation_id"]] = dict(doc)

    async def get_investigation(self, investigation_id: str) -> Doc | None:
        doc = self.investigations.get(investigation_id)
        return dict(doc) if doc else None

    async def update_investigation(self, investigation_id: str, fields: Doc) -> None:
        self.investigations[investigation_id].update(fields)

    async def latest_status_by_alert(self) -> dict[str, str]:
        ordered = sorted(self.investigations.values(), key=lambda d: d["created_at"])
        return {d["alert_id"]: d["status"] for d in ordered}

    async def mark_interrupted(self) -> int:
        active = [d for d in self.investigations.values() if d["status"] in ACTIVE]
        for doc in active:
            doc.update(status="failed", error=INTERRUPTED, finished_at=now())
        return len(active)

    async def append_event(self, investigation_id: str, seq: int, kind: str, data: Doc) -> None:
        self.events.append(
            {
                "investigation_id": investigation_id,
                "seq": seq,
                "kind": kind,
                "ts": now(),
                "data": data,
            }
        )

    async def events_after(self, investigation_id: str, seq: int) -> list[Doc]:
        rows = [
            e for e in self.events if e["investigation_id"] == investigation_id and e["seq"] > seq
        ]
        return sorted(rows, key=lambda e: e["seq"])

    async def add_decision(self, doc: Doc) -> None:
        self.decision_log.append(dict(doc))

    async def decisions(self, investigation_id: str) -> list[Doc]:
        return [dict(d) for d in self.decision_log if d["investigation_id"] == investigation_id]
