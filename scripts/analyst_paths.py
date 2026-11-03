"""Scripted analyst investigations, one per scenario, using only the agent's tools.

Each path starts from what the agent is given (the alert's host, user, time and trigger
event IDs) and chooses every later argument from earlier tool output, never from truth
files. The solvability test runs these to prove every key event is reachable; try_tools.py
prints them so you can see what an analyst would see.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pymongo.asynchronous.database import AsyncDatabase

from app.tools import call_tool

BROWSERS = ("chrome.exe", "msedge.exe")


class PathError(RuntimeError):
    """A tool returned an error, or the evidence the path expected wasn't in the output."""


@dataclass
class Step:
    tool: str
    args: dict[str, Any]
    result: dict[str, Any]


@dataclass
class Analyst:
    db: AsyncDatabase
    steps: list[Step] = field(default_factory=list)

    async def __call__(self, tool: str, **args: Any) -> Any:
        """Call a tool and return its payload (log data or catalog data)."""
        result = await call_tool(tool, args, self.db)
        self.steps.append(Step(tool, args, result))
        if "error" in result:
            raise PathError(f"{tool}({args}) failed: {result['error']}")
        return result.get("untrusted_log_data", result.get("attack_catalog"))


def pick(rows: list[dict[str, Any]], what: str, **match: Any) -> dict[str, Any]:
    for row in rows:
        if all(row.get(k) == v for k, v in match.items()):
            return row
    raise PathError(f"expected {what} ({match}) in tool output")


def basename(path: str) -> str:
    return path.replace('"', "").rsplit("\\", 1)[-1].split(" ", 1)[0]


async def s01(a: Analyst, alert: dict[str, Any]) -> None:
    host, ts = alert["host"], alert["ts"]
    tree = await a("get_process_tree", event_id=alert["trigger_event_ids"][0])
    outlook = pick(
        tree["ancestors"], "the mail client that opened the document", name="OUTLOOK.EXE"
    )
    await a("get_process_tree", event_id=outlook["event_id"])
    for proc in [tree["process"], *tree["descendants"]]:
        await a("get_dns_queries", host=host, around=ts, process_name=proc["name"])
        await a("get_network_connections", host=host, around=ts, process_name=proc["name"])


async def s02(a: Analyst, alert: dict[str, Any]) -> None:
    tree = await a("get_process_tree", event_id=alert["trigger_event_ids"][0])
    parent = tree["ancestors"][0]
    await a("get_process_tree", event_id=parent["event_id"])


async def s03(a: Analyst, alert: dict[str, Any]) -> None:
    logons = await a("get_logon_history", host=alert["host"], around=alert["ts"])
    success = pick(logons, "a successful logon from the spraying source", result="success")
    await a("get_user_info", user=success["user"])


async def s04(a: Analyst, alert: dict[str, Any]) -> None:
    host, user, ts = alert["host"], alert["user"], alert["ts"]
    tree = await a("get_process_tree", event_id=alert["trigger_event_ids"][0])
    shell = tree["ancestors"][0]
    await a("get_process_tree", event_id=shell["event_id"])
    logons = await a("get_logon_history", user=user, around=ts)
    rdp = [r for r in logons if r["host"] == host and r["logon_type"] == "remote_interactive"]
    rdp = [r for r in rdp if r["ts"] <= shell["ts"]]
    if not rdp:
        raise PathError("expected an RDP logon onto the alert host before the shell started")
    source = await a("get_host_info", host=rdp[-1]["src_ip"])
    target = await a("get_host_info", host=host)
    await a("search_process_events", host=source["hostname"], around=ts, name="mstsc")
    await a("get_network_connections", host=source["hostname"], around=ts, remote_ip=target["ip"])


async def s05(a: Analyst, alert: dict[str, Any]) -> None:
    host, ts = alert["host"], alert["ts"]
    tasks = await a("get_persistence_events", host=host, around=ts)
    task = pick(tasks, "the alerting task", event_id=alert["trigger_event_ids"][0])
    tree = await a("get_process_tree", event_id=task["event_id"])
    installer = tree["ancestors"][1]  # schtasks <- cmd <- installer
    await a("get_process_tree", event_id=installer["event_id"])

    # Where did the installer come from? Look just before it ran for a browser download.
    ran = _ts(installer["ts"])
    lookups = await a("get_dns_queries", host=host, start=ran - timedelta(minutes=15), end=ran)
    by_browser = [r for r in lookups if any(p["name"] in BROWSERS for p in r["processes"])]
    if not by_browser:
        raise PathError("expected a browser lookup shortly before the installer ran")
    site = max(by_browser, key=lambda r: r["first_seen"])
    browser = next(p for p in site["processes"] if p["name"] in BROWSERS)
    window = {"start": ran - timedelta(minutes=15), "end": ran}
    await a("get_network_connections", host=host, process_name=browser["name"], **window)
    await a("get_process_tree", host=host, pid=browser["pid"], ts=site["first_seen"])

    # An at-logon task runs later: follow it for the next 24 hours.
    implant = basename(task["command"])
    runs = await a(
        "search_process_events", host=host, start=ts, end=ts + timedelta(hours=24), name=implant
    )
    first_run = pick(runs, "the task's program running", name=implant)
    await a("get_dns_queries", host=host, around=first_run["ts"], process_name=implant)
    await a("get_network_connections", host=host, around=first_run["ts"], process_name=implant)


async def s06(a: Analyst, alert: dict[str, Any]) -> None:
    host, ts = alert["host"], alert["ts"]
    tree = await a("get_process_tree", event_id=alert["trigger_event_ids"][0])
    uploader = tree["process"]["name"]
    await a("get_network_connections", host=host, around=ts, process_name=uploader)
    await a("get_dns_queries", host=host, around=ts, process_name=uploader)
    desktop = tree["ancestors"][1]  # uploader <- cmd <- explorer
    await a("get_process_tree", event_id=desktop["event_id"])


def _ts(value: str | datetime) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


PATHS: dict[str, Callable[[Analyst, dict[str, Any]], Awaitable[None]]] = {
    "s01": s01,
    "s02": s02,
    "s03": s03,
    "s04": s04,
    "s05": s05,
    "s06": s06,
}


def cited_event_ids(obj: Any) -> set[str]:
    """Every event_id anywhere in a tool result (rows, groups, trees)."""
    found: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "event_id" and isinstance(value, str):
                found.add(value)
            elif key == "event_ids" and isinstance(value, list):
                found |= {v for v in value if isinstance(v, str)}
            else:
                found |= cited_event_ids(value)
    elif isinstance(obj, list):
        for item in obj:
            found |= cited_event_ids(item)
    return found


async def investigate(db: AsyncDatabase, scenario_id: str, alert_id: str) -> Analyst:
    alert = await db.alerts.find_one({"alert_id": alert_id}, {"_id": 0})
    if alert is None:
        raise PathError(f"no alert {alert_id}; run `python tasks.py seed`")
    analyst = Analyst(db)
    await PATHS[scenario_id](analyst, alert)
    return analyst
