"""get_logon_history and get_persistence_events."""

from typing import Any, Self

from pydantic import Field, model_validator
from pymongo.asynchronous.database import AsyncDatabase

from app.tools._common import (
    MAX_ROWS,
    HostName,
    UserName,
    WindowInput,
    cap_text,
    ensure_host,
    iso,
    list_result,
)


class LogonInput(WindowInput):
    user: UserName | None = Field(default=None, description="Account name, e.g. priya.n.")
    host: HostName | None = Field(
        default=None, description="Host the logons landed on, e.g. VPN-01 for VPN logons."
    )

    @model_validator(mode="after")
    def _user_or_host(self) -> Self:
        if self.user is None and self.host is None:
            raise ValueError("give user, host, or both")
        return self


async def get_logon_history(params: LogonInput, db: AsyncDatabase) -> dict[str, Any]:
    if params.host:
        await ensure_host(db, params.host)
    start, end = params.bounds()
    query: dict[str, Any] = {"event_type": "logon", "ts": {"$gte": start, "$lte": end}}
    if params.user:
        query["user"] = params.user
    if params.host:
        query["host"] = params.host
    total = await db.events.count_documents(query)
    docs = await db.events.find(query).sort([("ts", 1), ("event_id", 1)]).to_list(MAX_ROWS)
    rows = []
    for doc in docs:
        logon = doc["logon"]
        row = {"event_id": doc["event_id"], "ts": iso(doc["ts"]), "host": doc["host"]}
        row["user"] = doc["user"]
        row |= {k: logon[k] for k in ("logon_type", "src_ip", "country", "result", "mfa")}
        if logon.get("failure_reason"):
            row["failure_reason"] = logon["failure_reason"]
        rows.append(row)
    result = list_result(rows, total)
    if params.user:
        # Sprays try names that don't exist; saying so is evidence, not an error.
        known = await db.users.find_one({"username": params.user}, {"_id": 1})
        result["user_in_directory"] = known is not None
    return result


class PersistenceInput(WindowInput):
    host: HostName


async def get_persistence_events(params: PersistenceInput, db: AsyncDatabase) -> dict[str, Any]:
    await ensure_host(db, params.host)
    start, end = params.bounds()
    query = {
        "host": params.host,
        "event_type": "scheduled_task",
        "ts": {"$gte": start, "$lte": end},
    }
    total = await db.events.count_documents(query)
    docs = await db.events.find(query).sort([("ts", 1), ("event_id", 1)]).to_list(MAX_ROWS)
    rows = []
    for doc in docs:
        task = doc["task"]
        rows.append(
            {
                "event_id": doc["event_id"],
                "ts": iso(doc["ts"]),
                "user": doc["user"],
                "kind": "scheduled_task",
                "task_name": task["task_name"],
                "action": task["action"],
                "command": cap_text(task["command"]),
                "trigger": task["trigger"],
                "run_as": task["run_as"],
                "created_by": {"name": doc["process"]["name"], "pid": doc["process"]["pid"]},
            }
        )
    return list_result(rows, total)
