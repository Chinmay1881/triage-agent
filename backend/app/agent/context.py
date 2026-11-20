"""What the model sees of the tool conversation, kept inside Groq's ~8,000 tokens a minute.

The state keeps every tool result in full. Prompts get a shortened view:
- `investigate` sees the last 2 results in full and older ones as identifiers only: event IDs
  plus the hosts, users, PIDs, IPs, domains, hashes and task names they mention, so the agent
  can still pivot on them later;
- `summarize_findings` and `critic` get a JSON transcript of the calls in which each result is
  compacted (strings cut to 100 characters, lists to 8 items), falling back to identifiers
  only, oldest first, if the transcript would exceed its token budget.

Shortened results keep their log content under "untrusted_log_data", like the full ones.
"""

import ipaddress
import json
import re
from typing import Any, Literal

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage

EVENT_ID = re.compile(r"^evt_\d{6}$")
MAX_EVENT_IDS = 25
MAX_PER_KIND = 10
STRING_CAP = 100
LIST_CAP = 8
IDENTIFIER_KEYS: dict[str, tuple[str, ...]] = {
    "hosts": ("host", "hostname"),
    "users": ("user", "username", "run_as", "owner"),
    "pids": ("pid", "ppid", "target_pid"),
    "ips": ("ip", "src_ip", "dst_ip", "answers", "indicator"),
    "domains": ("domain", "domains", "query"),
    "sha256": ("sha256",),
    "tasks": ("task_name",),
}
KEY_KIND = {key: kind for kind, keys in IDENTIFIER_KEYS.items() for key in keys}
Level = Literal["ids", "rows"]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _add(found: dict[str, list[Any]], kind: str, value: Any) -> None:
    if kind == "ips" and not (isinstance(value, str) and _is_ip(value)):
        return
    if kind == "domains" and not isinstance(value, str):
        return
    bucket = found.setdefault(kind, [])
    limit = MAX_EVENT_IDS if kind == "event_ids" else MAX_PER_KIND
    if value not in bucket and len(bucket) < limit:
        bucket.append(value)


def identifiers(value: Any, found: dict[str, list[Any]] | None = None) -> dict[str, list[Any]]:
    """Event IDs and pivotable identifiers anywhere in a tool result, in order of appearance."""
    found = {} if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("event_id", "event_ids"):
                for eid in item if isinstance(item, list) else [item]:
                    if isinstance(eid, str) and EVENT_ID.match(eid):
                        _add(found, "event_ids", eid)
            elif key in KEY_KIND and not isinstance(item, dict):
                for v in item if isinstance(item, list) else [item]:
                    if v is not None and not isinstance(v, (dict, list)):
                        _add(found, KEY_KIND[key], v)
            else:
                identifiers(item, found)
    elif isinstance(value, list):
        for item in value:
            identifiers(item, found)
    return found


def event_ids_in(result: Any) -> list[str]:
    """Every event ID in a result, uncapped: these are what findings may cite."""
    out: list[str] = []
    if isinstance(result, dict):
        for key, item in result.items():
            if key in ("event_id", "event_ids"):
                for eid in item if isinstance(item, list) else [item]:
                    if isinstance(eid, str) and EVENT_ID.match(eid) and eid not in out:
                        out.append(eid)
            else:
                out += [e for e in event_ids_in(item) if e not in out]
    elif isinstance(result, list):
        for item in result:
            out += [e for e in event_ids_in(item) if e not in out]
    return out


def compact(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= STRING_CAP else value[: STRING_CAP - 1] + "…"
    if isinstance(value, dict):
        return {k: compact(v) for k, v in value.items()}
    if isinstance(value, list):
        head = [compact(v) for v in value[:LIST_CAP]]
        return [*head, f"… {len(value) - LIST_CAP} more"] if len(value) > LIST_CAP else head
    return value


def shrink(result: dict[str, Any], level: Level) -> dict[str, Any]:
    """A shortened tool result. Errors are short already and pass through unchanged."""
    if "error" in result:
        return result
    out: dict[str, Any] = {"shortened": True}
    for key in (
        "ref",
        "repeat_of",
        "total",
        "shown",
        "budget_left",
        "window_defaulted",
        "window_note",
        "intel_rule",
    ):
        if key in result:
            out[key] = result[key]
    if "attack_catalog" in result:
        out["attack_catalog"] = compact(result["attack_catalog"])
    if "untrusted_log_data" in result:
        data: dict[str, Any] = {"identifiers": identifiers(result["untrusted_log_data"])}
        if level == "rows":
            data["rows"] = compact(result["untrusted_log_data"])
        out["untrusted_log_data"] = data
    return out


def _load(content: Any) -> dict[str, Any] | None:
    try:
        loaded = json.loads(content) if isinstance(content, str) else None
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def tokens(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)) // 4


def render_history(messages: list[BaseMessage], full_last: int = 2) -> list[BaseMessage]:
    """The tool conversation for `investigate`: the last `full_last` tool results in full,
    older ones as identifiers."""
    tool_indexes = [i for i, m in enumerate(messages) if isinstance(m, ToolMessage)]
    keep = set(tool_indexes[-full_last:]) if full_last else set()
    out: list[BaseMessage] = []
    for i, message in enumerate(messages):
        result = _load(message.content) if isinstance(message, ToolMessage) else None
        if i in tool_indexes and i not in keep and result is not None:
            content = json.dumps(shrink(result, "ids"), separators=(",", ":"), default=str)
            message = message.model_copy(update={"content": content})
        out.append(message)
    return out


def transcript(messages: list[BaseMessage], budget_tokens: int) -> list[dict[str, Any]]:
    """Every tool call with its args and a compacted result, for summarize and critic. Over
    budget, results fall back to identifiers only, oldest first."""
    calls: dict[str, dict[str, Any]] = {}
    for message in messages:
        if isinstance(message, AIMessage):
            for call in message.tool_calls:
                calls[call["id"]] = {"tool": call["name"], "args": call["args"]}
    entries: list[dict[str, Any]] = []
    full: list[dict[str, Any]] = []
    for message in messages:
        if isinstance(message, ToolMessage) and message.tool_call_id in calls:
            result = _load(message.content) or {"error": "unreadable result"}
            full.append(result)
            entries.append(calls[message.tool_call_id] | {"result": shrink(result, "rows")})
    for index in range(len(entries)):
        if tokens(entries) <= budget_tokens:
            break
        entries[index]["result"] = shrink(full[index], "ids")
    return entries
