"""search_process_events and get_process_tree."""

from datetime import datetime
from typing import Any, Self

from pydantic import Field, model_validator
from pymongo.asynchronous.database import AsyncDatabase

from app.telemetry.decode import decode_encoded_command
from app.tools._common import (
    MAX_ROWS,
    EventId,
    HostName,
    TextFilter,
    ToolError,
    ToolInput,
    UtcDatetime,
    WindowInput,
    cap_text,
    contains,
    ensure_host,
    fit,
    iso,
    list_result,
)

ACTIVITY_TYPES = ["file_write", "lsass_access", "scheduled_task"]
MAX_ANCESTORS = 3
MAX_DEPTH = 3
MAX_CHILDREN = 10
MAX_GRANDCHILDREN = 5
MAX_DESCENDANTS = 15
MAX_ACTIVITY = 10
BOOT_NOTE = "started before telemetry begins (boot-time process)"


def process_row(doc: dict[str, Any]) -> dict[str, Any]:
    """One process_start as the agent sees it. Signer is always present: null = unsigned."""
    p = doc["process"]
    cmdline = p.get("cmdline") or ""
    row = {
        "event_id": doc["event_id"],
        "ts": iso(doc["ts"]),
        "user": doc["user"],
        "pid": p["pid"],
        "ppid": p.get("ppid"),
        "name": p["name"],
        "parent_name": p.get("parent_name"),
        "cmdline": cap_text(cmdline),
        "signer": p.get("signer"),
        "sha256": p.get("sha256"),
    }
    decoded = decode_encoded_command(cmdline)
    if decoded is not None:
        row["decoded_cmdline"] = cap_text(decoded)
    return row


def activity_row(doc: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"event_id": doc["event_id"], "ts": iso(doc["ts"])}
    row["event_type"] = doc["event_type"]
    if doc.get("file"):
        f = doc["file"]
        row |= {"path": cap_text(f["path"]), "action": f["action"], "size": f["size"]}
        row["sha256"] = f.get("sha256")
    if doc.get("access"):
        row |= doc["access"]
    if doc.get("task"):
        t = doc["task"]
        row |= {"task_name": t["task_name"], "action": t["action"], "trigger": t["trigger"]}
        row |= {"command": cap_text(t["command"]), "run_as": t["run_as"]}
    return row


class ProcessSearchInput(WindowInput):
    host: HostName
    name: TextFilter | None = Field(
        default=None, description="Case-insensitive substring of the process name."
    )
    cmdline_contains: TextFilter | None = Field(
        default=None, description="Case-insensitive substring of the command line."
    )


async def search_process_events(params: ProcessSearchInput, db: AsyncDatabase) -> dict[str, Any]:
    await ensure_host(db, params.host)
    start, end = params.bounds()
    query: dict[str, Any] = {
        "host": params.host,
        "event_type": "process_start",
        "ts": {"$gte": start, "$lte": end},
    }
    if params.name:
        query["process.name"] = contains(params.name)
    if params.cmdline_contains:
        query["process.cmdline"] = contains(params.cmdline_contains)
    total = await db.events.count_documents(query)
    docs = await db.events.find(query).sort([("ts", 1), ("event_id", 1)]).to_list(MAX_ROWS)
    return list_result([process_row(d) for d in docs], total)


class ProcessTreeInput(ToolInput):
    event_id: EventId | None = Field(
        default=None,
        description="Any event with a process (a process start, connection, file write...). "
        "Preferred over host + pid + ts.",
    )
    host: HostName | None = None
    pid: int | None = Field(default=None, ge=0)
    ts: UtcDatetime | None = Field(default=None, description="A time the process was running.")

    @model_validator(mode="after")
    def _one_way_to_identify(self) -> Self:
        by_pid = (self.host, self.pid, self.ts)
        if self.event_id is not None and any(v is not None for v in by_pid):
            raise ValueError("give event_id, or host + pid + ts, not both")
        if self.event_id is None and any(v is None for v in by_pid):
            raise ValueError("give event_id, or all of host, pid and ts")
        return self


async def _start_at(db: AsyncDatabase, host: str, pid: int, ts: datetime) -> dict | None:
    """PIDs get reused, so the process running at `ts` is the latest start at or before it."""
    query = {"host": host, "event_type": "process_start", "process.pid": pid, "ts": {"$lte": ts}}
    return await db.events.find_one(query, sort=[("ts", -1), ("event_id", -1)])


async def _end_of(
    db: AsyncDatabase, host: str, pid: int, start: datetime | None
) -> datetime | None:
    """A process's lifetime ends, at the latest, when its PID is next reused on that host."""
    query: dict[str, Any] = {"host": host, "event_type": "process_start", "process.pid": pid}
    if start is not None:
        query["ts"] = {"$gt": start}
    nxt = await db.events.find_one(query, sort=[("ts", 1)])
    return nxt["ts"] if nxt else None


def _lifetime(start: datetime | None, end: datetime | None) -> dict[str, Any]:
    bounds: dict[str, Any] = {}
    if start is not None:
        bounds["$gte"] = start
    if end is not None:
        bounds["$lt"] = end
    return {"ts": bounds} if bounds else {}


async def _ancestors(db: AsyncDatabase, host: str, doc: dict) -> list[dict[str, Any]]:
    ancestors = []
    child = doc
    for _ in range(MAX_ANCESTORS):
        ppid, name = child["process"].get("ppid"), child["process"].get("parent_name")
        if ppid is None:
            break
        parent = await _start_at(db, host, ppid, child["ts"])
        if parent is None:
            ancestors.append({"pid": ppid, "name": name, "note": BOOT_NOTE})
            break
        ancestors.append(process_row(parent))
        child = parent
    return ancestors


async def _descendants(
    db: AsyncDatabase, host: str, pid: int, start: datetime | None, end: datetime | None
) -> tuple[list[dict[str, Any]], int]:
    children_query = {"host": host, "event_type": "process_start", "process.ppid": pid}
    children_query |= _lifetime(start, end)
    total_children = await db.events.count_documents(children_query)
    out: list[dict[str, Any]] = []
    frontier: list[tuple[int, datetime | None, datetime | None, int]] = [(pid, start, end, 1)]
    while frontier and len(out) < MAX_DESCENDANTS:
        parent_pid, p_start, p_end, depth = frontier.pop(0)
        query = {"host": host, "event_type": "process_start", "process.ppid": parent_pid}
        query |= _lifetime(p_start, p_end)
        limit = MAX_CHILDREN if depth == 1 else MAX_GRANDCHILDREN
        kids = await db.events.find(query).sort([("ts", 1), ("event_id", 1)]).to_list(limit)
        for kid in kids:
            if len(out) >= MAX_DESCENDANTS:
                break
            out.append(process_row(kid) | {"depth": depth})
            if depth < MAX_DEPTH:
                kid_pid = kid["process"]["pid"]
                kid_end = await _end_of(db, host, kid_pid, kid["ts"])
                frontier.append((kid_pid, kid["ts"], kid_end, depth + 1))
    return out, total_children


async def get_process_tree(params: ProcessTreeInput, db: AsyncDatabase) -> dict[str, Any]:
    if params.event_id is not None:
        event = await db.events.find_one({"event_id": params.event_id})
        if event is None:
            raise ToolError(f"no event {params.event_id}")
        if not event.get("process"):
            raise ToolError(f"{params.event_id} is a {event['event_type']} event with no process")
        host, pid, ts = event["host"], event["process"]["pid"], event["ts"]
        known_name = event["process"]["name"]
    else:
        if params.host is None or params.pid is None or params.ts is None:
            raise ToolError("give event_id, or all of host, pid and ts")
        await ensure_host(db, params.host)
        host, pid, ts, known_name = params.host, params.pid, params.ts, None

    focal = await _start_at(db, host, pid, ts)
    start = focal["ts"] if focal else None
    end = await _end_of(db, host, pid, start)
    if focal is not None:
        focal_row = process_row(focal)
        ancestors = await _ancestors(db, host, focal)
    elif known_name is not None:
        focal_row = {"pid": pid, "name": known_name, "note": BOOT_NOTE}
        ancestors = []
    else:
        raise ToolError(f"no process with pid {pid} on {host} at {iso(ts)}")

    descendants, total_children = await _descendants(db, host, pid, start, end)
    activity_query = {"host": host, "process.pid": pid, "event_type": {"$in": ACTIVITY_TYPES}}
    activity_query |= _lifetime(start, end)
    total_activity = await db.events.count_documents(activity_query)
    activity_docs = await db.events.find(activity_query).sort([("ts", 1)]).to_list(MAX_ACTIVITY)
    activity = [activity_row(d) for d in activity_docs]

    data = {
        "host": host,
        "process": focal_row,
        "ancestors": ancestors,
        "descendants": descendants,
        "activity": activity,
    }
    result: dict[str, Any] = {"untrusted_log_data": data}
    trimmed = fit(result, descendants, activity)
    result["children_total"] = total_children
    result["activity_total"] = total_activity
    if (
        trimmed
        or total_children > len([d for d in descendants if d["depth"] == 1])
        or (total_activity > len(activity))
    ):
        result["note"] = (
            "only the first children and activity are shown; call get_process_tree on a "
            "listed process to look further down"
        )
    return result
