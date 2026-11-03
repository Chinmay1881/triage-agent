"""get_network_connections and get_dns_queries. Both group rows so one call shows patterns:
per-destination count with first_seen/last_seen makes a beacon (s01 checks in every ~6 min)
or a bulk upload (s06) visible without paging through individual connections."""

import ipaddress
from datetime import timedelta
from typing import Annotated, Any

from pydantic import AfterValidator, Field
from pymongo.asynchronous.database import AsyncDatabase

from app.tools._common import (
    MAX_ROWS,
    HostName,
    TextFilter,
    WindowInput,
    ensure_host,
    exact,
    iso,
    list_result,
)

# Groups are built in Python from at most this many raw events; a 24 h window on the
# busiest host is well under it.
FETCH_LIMIT = 5000
GROUP_EVENT_IDS = 10
DNS_EVENT_IDS = 5
MAX_PROCESSES = 5
# DNS answers usually precede the connection, so look a little before the window.
DNS_LOOKBACK = timedelta(hours=1)


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


IpAddress = Annotated[str, AfterValidator(_ip)]


class _HostWindowInput(WindowInput):
    host: HostName
    process_name: TextFilter | None = Field(
        default=None, description="Only this process name (exact, case-insensitive)."
    )


class NetworkInput(_HostWindowInput):
    remote_ip: IpAddress | None = Field(default=None, description="Only this destination IP.")


class DnsInput(_HostWindowInput):
    pass


def _base_query(params: _HostWindowInput, event_type: str) -> dict[str, Any]:
    start, end = params.bounds()
    query: dict[str, Any] = {
        "host": params.host,
        "event_type": event_type,
        "ts": {"$gte": start, "$lte": end},
    }
    if params.process_name:
        query["process.name"] = exact(params.process_name)
    return query


def _add_process(processes: list[dict[str, Any]], doc: dict[str, Any]) -> None:
    ref = {"name": doc["process"]["name"], "pid": doc["process"]["pid"]}
    if ref not in processes and len(processes) < MAX_PROCESSES:
        processes.append(ref)


async def get_network_connections(params: NetworkInput, db: AsyncDatabase) -> dict[str, Any]:
    await ensure_host(db, params.host)
    query = _base_query(params, "network_conn")
    if params.remote_ip:
        query["network.dst_ip"] = params.remote_ip
    docs = await db.events.find(query).sort([("ts", 1), ("event_id", 1)]).to_list(FETCH_LIMIT)

    groups: dict[tuple[str, int], dict[str, Any]] = {}
    for doc in docs:
        n = doc["network"]
        key = (n["dst_ip"], n["dst_port"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "dst_ip": n["dst_ip"],
                "dst_port": n["dst_port"],
                "count": 0,
                "bytes_out": 0,
                "bytes_in": 0,
                "first_seen": iso(doc["ts"]),
                "processes": [],
                "event_ids": [],
            }
        g["count"] += 1
        g["bytes_out"] += n["bytes_out"]
        g["bytes_in"] += n["bytes_in"]
        g["last_seen"] = iso(doc["ts"])
        _add_process(g["processes"], doc)
        if len(g["event_ids"]) < GROUP_EVENT_IDS:
            g["event_ids"].append(doc["event_id"])

    await _label_destinations(db, params, list(groups.values()))
    rows = list(groups.values())[:MAX_ROWS]
    return list_result(rows, len(groups))


async def _label_destinations(
    db: AsyncDatabase, params: NetworkInput, groups: list[dict[str, Any]]
) -> None:
    """Name each destination: the internal host that owns it, or domains that resolved to it
    on this host. A bare IP is much harder for the agent to reason about."""
    ips = sorted({g["dst_ip"] for g in groups})
    hosts = {h["ip"]: h["hostname"] async for h in db.hosts.find({"ip": {"$in": ips}})}
    start, end = params.bounds()
    dns_query = {
        "host": params.host,
        "event_type": "dns_query",
        "ts": {"$gte": start - DNS_LOOKBACK, "$lte": end},
        "dns.answers": {"$in": ips},
    }
    domains: dict[str, list[str]] = {}
    async for doc in db.events.find(dns_query, {"dns": 1}):
        for answer in doc["dns"]["answers"]:
            names = domains.setdefault(answer, [])
            if doc["dns"]["query"] not in names:
                names.append(doc["dns"]["query"])
    for g in groups:
        if g["dst_ip"] in hosts:
            g["dst_host"] = hosts[g["dst_ip"]]
        if g["dst_ip"] in domains:
            g["domains"] = domains[g["dst_ip"]][:3]


async def get_dns_queries(params: DnsInput, db: AsyncDatabase) -> dict[str, Any]:
    await ensure_host(db, params.host)
    docs = await (
        db.events.find(_base_query(params, "dns_query"))
        .sort([("ts", 1), ("event_id", 1)])
        .to_list(FETCH_LIMIT)
    )
    groups: dict[str, dict[str, Any]] = {}
    for doc in docs:
        d = doc["dns"]
        g = groups.get(d["query"])
        if g is None:
            g = groups[d["query"]] = {
                "domain": d["query"],
                "count": 0,
                "answers": [],
                "first_seen": iso(doc["ts"]),
                "processes": [],
                "event_ids": [],
            }
        g["count"] += 1
        g["last_seen"] = iso(doc["ts"])
        g["answers"] += [a for a in d["answers"] if a not in g["answers"]]
        _add_process(g["processes"], doc)
        if len(g["event_ids"]) < DNS_EVENT_IDS:
            g["event_ids"].append(doc["event_id"])
    rows = list(groups.values())[:MAX_ROWS]
    return list_result(rows, len(groups))
