"""What the agents depend on, passed in so tests can run the whole chain offline."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from pymongo.asynchronous.database import AsyncDatabase

from app.config import Settings
from app.llm import LLM
from app.telemetry.models import Alert


class Telemetry(Protocol):
    async def events(self, event_ids: list[str]) -> list[dict[str, Any]]: ...


ToolRunner = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass
class Deps:
    llm: LLM
    telemetry: Telemetry
    call_tool: ToolRunner
    settings: Settings


class MongoTelemetry:
    """The read-only telemetry db (the telemetry_reader user)."""

    def __init__(self, db: AsyncDatabase) -> None:
        self._db = db

    async def alert(self, alert_id: str) -> Alert | None:
        doc = await self._db.alerts.find_one({"alert_id": alert_id}, {"_id": 0})
        return Alert.model_validate(doc) if doc else None

    async def events(self, event_ids: list[str]) -> list[dict[str, Any]]:
        docs = await self._db.events.find({"event_id": {"$in": event_ids}}, {"_id": 0}).to_list()
        order = {eid: i for i, eid in enumerate(event_ids)}
        return sorted(docs, key=lambda d: order[d["event_id"]])
