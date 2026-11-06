"""Running one tool call for any agent: the one place the sandbox rules are applied.

- Only the agent's own tools run; anything else comes back as an error the model can see.
- A window tool called with no window gets the alert time +-2 h, logged and marked, instead of
  an error that costs a call.
- Every call gets a ref ("tool:get_host_info#3") that findings can cite, and its log content is
  scanned for injection. Event IDs and entities go into the shared evidence ledger.
- An exact repeat of a successful call is answered from the ledger without running the tool. A
  repeat of another agent's call gets the full result, since this agent hasn't seen it; a repeat
  of its own call gets only the identifiers, since the rest is already in its conversation.
- LLM-chosen calls by the investigator and reviewer also get an automatic reputation lookup for
  new IPs, domains and hashes in their results (source "intel_rule", capped per call, no budget
  cost): those agents don't have check_reputation, but a beacon target they find still needs
  checking. The result stays in the same message, so it costs few tokens.
"""

import json
import logging
import re
from typing import Any, Literal

from app.agent.case import Evidence, StoredAnswer, ToolCallRecord, ToolRef, ToolSource
from app.agent.context import event_ids_in, identifiers, shrink
from app.agent.deps import Deps
from app.agent.grounding import is_internal_ip
from app.agent.injection import scan_tool_result
from app.telemetry.models import Alert
from app.tools import TOOLS
from app.tools._common import WindowInput, iso

log = logging.getLogger(__name__)

WINDOW_KEYS = ("around", "start", "end")
# Extra strings that identify what a result is about, beside identifiers().
ENTITY_KEYS = ("indicator", "display_name", "hostname", "username")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST_CHARS = 240


def with_default_window(
    name: str, args: dict[str, Any], alert: Alert
) -> tuple[dict[str, Any], bool]:
    tool = TOOLS.get(name)
    if tool is None or not issubclass(tool.input_model, WindowInput):
        return args, False
    if any(args.get(key) is not None for key in WINDOW_KEYS):
        return args, False
    return args | {"around": iso(alert.ts)}, True


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _note_rows(data: Any, evidence: Evidence) -> None:
    """Links only a tool result knows: a connection's resolved domains, a hash's file name."""
    for row in _walk(data):
        ids = row.get("event_ids") or ([row["event_id"]] if row.get("event_id") else [])
        domains = row.get("domains") or ([row["domain"]] if row.get("domain") else [])
        if isinstance(domains, list):
            for event_id in ids:
                labels = evidence.event_labels.setdefault(event_id, [])
                labels += [d for d in domains if isinstance(d, str) and d not in labels]
        sha = row.get("sha256")
        name = row.get("name") or (re.split(r"[\\/]", row["path"])[-1] if row.get("path") else None)
        if isinstance(sha, str) and isinstance(name, str):
            names = evidence.aliases.setdefault(sha, [])
            if name not in names:
                names.append(name)


def _entities(data: Any) -> list[str]:
    found = identifiers(data)
    values = [v for kind, items in found.items() if kind != "pids" for v in items]
    for row in _walk(data):
        values += [row[k] for k in ENTITY_KEYS if isinstance(row.get(k), str)]
    return sorted({str(v) for v in values})


def _digest(data: Any) -> str:
    if data is None:
        return ""
    text = json.dumps(data, separators=(",", ":"), default=str, ensure_ascii=False)
    return text if len(text) <= DIGEST_CHARS else text[: DIGEST_CHARS - 1] + "…"


def record_result(
    name: str, args: dict[str, Any], result: dict[str, Any], evidence: Evidence
) -> tuple[str, list[str]]:
    """Enter one result into the ledger; returns its ref and the event IDs it holds."""
    evidence.calls += 1
    ref = f"tool:{name}#{evidence.calls}"
    data = result.get("untrusted_log_data")
    ids = event_ids_in(result)
    for event_id in ids:
        evidence.seen_event_ids.setdefault(event_id, name)
    if data is not None:
        _note_rows(data, evidence)
    evidence.tool_refs[ref] = ToolRef(
        tool=name,
        ok="error" not in result,
        entities=_entities(data),
        args=args,
        digest=_digest(data),
    )
    known = {(f.event_id, f.field, f.method) for f in evidence.injection_flags}
    evidence.injection_flags += [
        f for f in scan_tool_result(result) if (f.event_id, f.field, f.method) not in known
    ]
    return ref, ids


def call_key(name: str, args: dict[str, Any]) -> str:
    return f"{name}:{json.dumps(args, sort_keys=True, default=str)}"


def answer_repeat(
    deps: Deps,
    evidence: Evidence,
    agent: str,
    stored: StoredAnswer,
    name: str,
    args: dict[str, Any],
    defaulted: bool,
) -> tuple[dict[str, Any], ToolCallRecord]:
    used = evidence.free_repeats.get(agent, 0)
    evidence.free_repeats[agent] = used + 1
    own = stored.agent == agent
    result = shrink(stored.result, "ids") if own else stored.result
    note = (
        f"same call as {stored.ref}, already in this conversation"
        if own
        else f"already run by {stored.agent}; answered from the case ledger"
    )
    log.info("%s: %s repeats %s; answered from the ledger", agent, name, stored.ref)
    record = ToolCallRecord(
        ref=stored.ref,
        agent=agent,
        name=name,
        args=args,
        ok=True,
        event_ids=len(event_ids_in(result)),
        defaulted_window=defaulted,
        repeat_of=stored.ref,
        charged=used >= deps.settings.free_repeats_per_agent,
    )
    return result | {"ref": stored.ref, "repeat_of": stored.ref, "repeat_note": note}, record


async def run_call(
    deps: Deps,
    evidence: Evidence,
    agent: str,
    allowed: frozenset[str],
    alert: Alert,
    name: str,
    args: dict[str, Any],
    source: ToolSource = "llm",
) -> tuple[dict[str, Any], ToolCallRecord]:
    """One call; `evidence` is updated in place. The result gets its ref."""
    final_args, defaulted = with_default_window(name, args, alert)
    key = call_key(name, final_args)
    stored = evidence.answers.get(key)
    if stored is not None and source == "llm" and name in allowed:
        return answer_repeat(deps, evidence, agent, stored, name, final_args, defaulted)
    if name not in allowed:
        result: dict[str, Any] = {
            "error": f"{name} is not available to {agent}; available: {', '.join(sorted(allowed))}"
        }
    else:
        result = await deps.call_tool(name, final_args)
    if defaulted:
        log.info("%s: %s called without a window; using the alert time +-2 h", agent, name)
    ref, ids = record_result(name, final_args, result, evidence)
    if name == "check_reputation" and isinstance(args.get("indicator"), str):
        indicator = args["indicator"].lower()
        evidence.looked_up.append(indicator)
        data = result.get("untrusted_log_data")
        if isinstance(data, dict) and isinstance(data.get("reputation"), str):
            evidence.reputations[indicator] = data["reputation"]
    record = ToolCallRecord(
        ref=ref,
        agent=agent,
        name=name,
        args=final_args,
        ok="error" not in result,
        error=result.get("error"),
        event_ids=len(ids),
        source=source,
        defaulted_window=defaulted,
    )
    annotated = result | {"ref": ref}
    if defaulted:
        annotated["window_defaulted"] = "alert time +-2 h"
    if record.ok:
        evidence.answers[key] = StoredAnswer(ref=ref, agent=agent, result=annotated)
    return annotated, record


IndicatorType = Literal["ip", "domain", "hash"]


def new_indicators(result: dict[str, Any], evidence: Evidence) -> list[tuple[str, IndicatorType]]:
    """IPs, domains and hashes in a result not looked up yet: IPs and domains first, since a
    capped lookup should reach the destinations before yet another benign binary's hash."""
    found = identifiers(result.get("untrusted_log_data"))
    ips: list[tuple[str, IndicatorType]] = [
        (ip, "ip") for ip in found.get("ips", []) if not is_internal_ip(ip)
    ]
    domains: list[tuple[str, IndicatorType]] = [(d, "domain") for d in found.get("domains", [])]
    hashes: list[tuple[str, IndicatorType]] = [
        (h, "hash") for h in found.get("sha256", []) if SHA256.match(str(h))
    ]
    seen = set(evidence.looked_up)
    return [(value, kind) for value, kind in [*ips, *domains, *hashes] if value.lower() not in seen]


async def auto_reputation(
    deps: Deps, evidence: Evidence, agent: str, alert: Alert, result: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[ToolCallRecord]]:
    """Lookups for new indicators in `result`, with no LLM choice and no budget cost."""
    rows, records = [], []
    wanted = new_indicators(result, evidence)[: deps.settings.auto_reputation_per_call]
    for value, kind in wanted:
        answer, record = await run_call(
            deps,
            evidence,
            agent,
            frozenset({"check_reputation"}),
            alert,
            "check_reputation",
            {"indicator": value, "type": kind},
            source="intel_rule",
        )
        records.append(record)
        data = answer.get("untrusted_log_data") or {}
        rows.append(
            {
                "indicator": value,
                "reputation": data.get("reputation"),
                "source": "intel_rule",
                "ref": answer["ref"],
            }
        )
    return rows, records
