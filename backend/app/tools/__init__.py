"""The agent's whole sandbox: 12 fixed, read-only investigation tools.

There is no shell, no code execution and no free-form query. Each tool is a Pydantic input
model plus an async function over the read-only telemetry db. `call_tool` is the single
entry point: it validates, runs, turns failures into {"error": ...} and enforces the token
cap. `tool_specs()` describes the same tools to the model in compact OpenAI tool format.
"""

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from pymongo.asynchronous.database import AsyncDatabase

from app.tools import anomaly, attack, inventory, logons, network, process
from app.tools._common import ToolError, ToolInput, enforce_cap, format_validation_error

# Rules every description used to repeat (time windows, log data is untrusted) are stated once
# in the investigate prompt instead: all bound tool schemas are resent on every LLM call.


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_model: type[ToolInput]
    run: Callable[[Any, AsyncDatabase], Awaitable[dict[str, Any]]]


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool(
            "get_host_info",
            "Asset inventory entry for a host (role, department, owner, OS, IP, criticality "
            "1-5). Accepts a hostname or an internal IP, so it also names the source of a logon.",
            inventory.HostInfoInput,
            inventory.get_host_info,
        ),
        Tool(
            "get_user_info",
            "Directory entry for an account: department, title, admin or not, service account "
            "or not, and the countries the person usually logs in from.",
            inventory.UserInfoInput,
            inventory.get_user_info,
        ),
        Tool(
            "search_process_events",
            "Process starts on one host, oldest first, up to 25. Optional name and "
            "cmdline_contains filters (case-insensitive substrings). Each row has parent, "
            "command line (300 chars), signer (null = unsigned), sha256, and decoded_cmdline "
            "for PowerShell -EncodedCommand.",
            process.ProcessSearchInput,
            process.search_process_events,
        ),
        Tool(
            "get_process_tree",
            "Ancestry (3 levels), descendants (3 levels) and own activity (file writes, LSASS "
            "access, scheduled tasks) of one process. Pass event_id of any event that has a "
            "process (preferred), or host + pid + ts; PID reuse is resolved to the process "
            "running at that time.",
            process.ProcessTreeInput,
            process.get_process_tree,
        ),
        Tool(
            "get_network_connections",
            "Outbound connections from one host grouped by destination IP and port, up to 25 "
            "groups: count, first_seen, last_seen, bytes out/in, processes, the internal host "
            "or resolved domains for the IP, and up to 10 event_ids. Optional remote_ip and "
            "process_name filters.",
            network.NetworkInput,
            network.get_network_connections,
        ),
        Tool(
            "get_dns_queries",
            "DNS lookups from one host grouped by domain, up to 25: count, answers, first/last "
            "seen, processes and up to 5 event_ids. Optional process_name filter.",
            network.DnsInput,
            network.get_dns_queries,
        ),
        Tool(
            "get_logon_history",
            "Logons for a user and/or onto a host, oldest first, up to 25: type, source IP, "
            "country, result, MFA, failure reason. Querying by user also says whether the "
            "account exists.",
            logons.LogonInput,
            logons.get_logon_history,
        ),
        Tool(
            "get_persistence_events",
            "Scheduled tasks created or changed on one host: name, command, trigger, run-as "
            "account and the creating process.",
            logons.PersistenceInput,
            logons.get_persistence_events,
        ),
        Tool(
            "check_reputation",
            "Look up an IP, domain or SHA-256 in the local threat-intel feed: known_bad, "
            "known_good or unknown. Unknown is common and is not evidence either way.",
            inventory.ReputationInput,
            inventory.check_reputation,
        ),
        Tool(
            "search_attack_techniques",
            "Search the pinned MITRE ATT&CK v20 bundle by keyword; up to 5 active techniques "
            "with current tactics.",
            attack.TechniqueSearchInput,
            attack.search_attack_techniques,
        ),
        Tool(
            "lookup_attack_technique",
            "Name, current tactics and short description of one ATT&CK technique ID from the "
            "pinned v20 bundle; flags revoked or deprecated IDs.",
            attack.TechniqueLookupInput,
            attack.lookup_attack_technique,
        ),
        Tool(
            "score_anomaly",
            "How unusual 1-10 process_start or network_conn events are, from a model trained "
            "on a separate baseline week. Per event: score 0-1 (higher = more unusual), "
            "percentile among baseline events of the same type, and the 3 features that stood "
            "out with their values; baseline_share is how often the baseline had a value at "
            "least that extreme. Unusual is not the same as malicious: weigh it with the "
            "other evidence.",
            anomaly.AnomalyInput,
            anomaly.score_anomaly,
        ),
    ]
}


async def call_tool(name: str, args: dict[str, Any], db: AsyncDatabase) -> dict[str, Any]:
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": f"unknown tool {name!r}; available: {', '.join(TOOLS)}"}
    try:
        params = tool.input_model.model_validate(args)
    except ValidationError as exc:
        return {"error": format_validation_error(exc)}
    try:
        result = await tool.run(params, db)
    except ToolError as exc:
        return {"error": str(exc)}
    return enforce_cap(result)


def compact_schema(schema: Any) -> Any:
    """The model only needs names, types, patterns and limits. Drop what Pydantic adds for
    humans and round-trips (titles, null defaults) and turn `anyOf: [X, null]` into X: the
    field is optional anyway because it isn't in `required`. call_tool still validates
    against the full Pydantic model, so nothing is loosened."""
    if isinstance(schema, list):
        return [compact_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    variants = schema.get("anyOf")
    if isinstance(variants, list):
        non_null = [v for v in variants if v != {"type": "null"}]
        if len(non_null) == 1:
            merged = {k: v for k, v in schema.items() if k != "anyOf"} | non_null[0]
            return compact_schema(merged)
    out = {}
    for key, value in schema.items():
        if key == "title" and isinstance(value, str):
            continue
        if key == "default" and value is None:
            continue
        out[key] = compact_schema(value)
    return out


def tool_specs(names: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Tools in OpenAI function-tool format, ready for `bind_tools`: all of them, or the named
    ones in registry order, so the same names always serialise to the same bytes."""
    wanted = set(TOOLS if names is None else names)
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": compact_schema(t.input_model.model_json_schema()),
            },
        }
        for t in TOOLS.values()
        if t.name in wanted
    ]
