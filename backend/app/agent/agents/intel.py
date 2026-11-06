"""CyberIntel-Agent: what is already known about everything the trigger touched?

Code does the certain part, with no LLM choice: fetch the trigger's process tree, extract every
host, user, IP, domain and sha256 from the trigger, its parent and its children, and look them
all up. So the parent's reputation is in the brief every time, not when the model thinks of it.
Then it fetches each tree process's connections and DNS queries and looks up every destination: a
C2 address usually shows up only in network activity, never in the tree itself. The LLM may then
make a few more calls and writes the assessment; the facts stay code-written.
"""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from app.agent.agents.common import INTEL_TOOLS, alert_block, handoff, to_json, with_records
from app.agent.agents.triage import anomaly_rows
from app.agent.case import Case, Evidence, IntelBrief, IntelDraft, ToolCallRecord
from app.agent.context import transcript
from app.agent.deps import Deps
from app.agent.grounding import FILE_NAME, IPV4, is_internal_ip, text_entities
from app.agent.prompts.intel import INTEL, INTEL_BRIEF
from app.agent.prompts.system import SYSTEM
from app.agent.toolrun import IndicatorType, new_indicators, run_call
from app.config import CYBERINTEL, INVESTIGATOR
from app.llm import LLMError
from app.telemetry.decode import decode_encoded_command
from app.telemetry.models import Alert
from app.tools import tool_specs
from app.tools._common import cap_text, iso

log = logging.getLogger(__name__)

MAX_TREES = 5
ANOMALY_BATCH = 10
CHAIN_CMDLINE_CHARS = 150
EXTRA_LOOKUP_TOKENS = 1000
NOT_DIRECTORY_USERS = {"system", "local service", "network service"}
NETWORK_TOOLS = ("get_network_connections", "get_dns_queries")


@dataclass
class Entities:
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)

    def add_text(self, text: str) -> None:
        for entity in sorted(text_entities(text)):
            if IPV4.fullmatch(entity):
                _add(self.ips, entity)
            elif not FILE_NAME.fullmatch(entity):
                _add(self.domains, entity.lower())


def _add(bucket: list[str], value: Any) -> None:
    if isinstance(value, str) and value and value not in bucket:
        bucket.append(value)


def _add_row(found: Entities, row: dict[str, Any], host: str | None) -> None:
    """A row from get_process_tree."""
    _add(found.hosts, host)
    _add(found.event_ids, row.get("event_id"))
    _add(found.users, row.get("user"))
    _add(found.hashes, row.get("sha256"))
    found.add_text(row.get("cmdline") or "")
    found.add_text(row.get("decoded_cmdline") or "")


def extract_entities(docs: list[dict[str, Any]], trees: list[dict[str, Any]]) -> Entities:
    """Everything to look up, from the trigger events and their parents and children."""
    found = Entities()
    for doc in docs:
        _add(found.hosts, doc.get("host"))
        _add(found.users, doc.get("user"))
        _add(found.event_ids, doc.get("event_id"))
        process = doc.get("process") or {}
        _add(found.hashes, process.get("sha256"))
        cmdline = process.get("cmdline") or ""
        found.add_text(cmdline)
        found.add_text(decode_encoded_command(cmdline) or "")
        network = doc.get("network") or {}
        _add(found.ips, network.get("dst_ip"))
        logon = doc.get("logon") or {}
        _add(found.ips, logon.get("src_ip"))
        dns = doc.get("dns") or {}
        _add(found.domains, dns.get("query"))
        file = doc.get("file") or {}
        _add(found.hashes, file.get("sha256"))
    for tree in trees:
        host = tree.get("host")
        _add_row(found, tree.get("process") or {}, host)
        if tree.get("ancestors"):
            _add_row(found, tree["ancestors"][0], host)
        for child in tree.get("descendants") or []:
            if child.get("depth") == 1:
                _add_row(found, child, host)
        for activity in tree.get("activity") or []:
            _add(found.hashes, activity.get("sha256"))
    return found


def chain_row(role: str, row: dict[str, Any]) -> dict[str, Any]:
    out = {
        "role": role,
        "event_id": row.get("event_id"),
        "name": row.get("name"),
        "user": row.get("user"),
        "signer": row.get("signer"),
        "sha256": row.get("sha256"),
    }
    if row.get("cmdline") and role != "trigger":
        out["cmdline"] = cap_text(row["cmdline"], CHAIN_CMDLINE_CHARS)
    return out


def process_chain(trees: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parent, trigger, children; each with reputation filled in by absorb()."""
    rows = []
    for tree in trees:
        if tree.get("ancestors"):
            rows.append(chain_row("parent", tree["ancestors"][0]))
        rows.append(chain_row("trigger", tree.get("process") or {}))
        rows += [
            chain_row("child", child)
            for child in tree.get("descendants") or []
            if child.get("depth") == 1
        ]
    return rows


def network_calls(alert: Alert, trees: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """The connections and DNS calls for each process in the trees, once per host and name, within
    the alert time +-2 h. The trigger and its descendants come first: if the cap cuts the list, the
    parent is the one to lose."""
    processes: dict[tuple[str, str], None] = {}
    for tree in trees:
        rows = [tree.get("process") or {}, *(tree.get("descendants") or [])]
        rows += (tree.get("ancestors") or [])[:1]
        for row in rows:
            if tree.get("host") and row.get("name"):
                processes[(tree["host"], row["name"])] = None
    return [
        (tool, {"host": host, "process_name": name, "around": iso(alert.ts)})
        for host, name in processes
        for tool in NETWORK_TOOLS
    ]


def network_indicators(answers: list[dict[str, Any]], evidence: Evidence) -> list[tuple[str, str]]:
    """Destination IPs, then resolved domains, not looked up yet. IPs first because a beacon target
    is usually a bare address, so a noisy process's domains can't use up the cap before it."""
    found: dict[str, IndicatorType] = {}
    for answer in answers:
        for value, kind in new_indicators(answer, evidence):
            if kind != "hash":
                found[value.lower()] = kind
    return sorted(found.items(), key=lambda item: item[1] != "ip")


def absorb(brief: IntelBrief, name: str, answer: dict[str, Any]) -> None:
    """Put a successful lookup's facts into the brief, with the ref a finding can cite."""
    data = answer.get("untrusted_log_data")
    if data is None:
        return
    ref = answer["ref"]
    if name == "check_reputation":
        brief.reputation.append(
            {
                k: data.get(k)
                for k in ("indicator", "type", "reputation", "description")
                if data.get(k)
            }
            | {"ref": ref}
        )
        for row in brief.process_chain:
            if row.get("sha256") == data.get("indicator"):
                row["reputation"] = data.get("reputation")
    elif name == "get_host_info":
        keys = ("hostname", "role", "department", "owner", "criticality")
        brief.hosts.append({k: data.get(k) for k in keys} | {"ref": ref})
    elif name == "get_user_info":
        keys = ("username", "title", "department", "is_admin", "is_service_account")
        row = {k: data.get(k) for k in keys} | {"usual_countries": data.get("usual_countries")}
        brief.users.append(row | {"ref": ref})
    elif name == "score_anomaly":
        brief.anomaly += [r | {"ref": ref} for r in anomaly_rows(answer)]


def make_intel(deps: Deps) -> Callable[[Case], Awaitable[dict[str, Any]]]:
    settings = deps.settings

    async def look_up(
        evidence: Evidence,
        brief: IntelBrief,
        state: Case,
        records: list[ToolCallRecord],
        name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        answer, record = await run_call(
            deps,
            evidence,
            CYBERINTEL,
            INTEL_TOOLS | {"get_process_tree"},
            state.alert,
            name,
            args,
            source="code",
        )
        records.append(record)
        absorb(brief, name, answer)
        return answer

    async def code_lookups(
        state: Case, evidence: Evidence, brief: IntelBrief, records: list[ToolCallRecord]
    ) -> str | None:
        docs = await deps.telemetry.events(state.alert.trigger_event_ids)
        trees = []
        for doc in [d for d in docs if d.get("process")][:MAX_TREES]:
            answer = await look_up(
                evidence, brief, state, records, "get_process_tree", {"event_id": doc["event_id"]}
            )
            if isinstance(answer.get("untrusted_log_data"), dict):
                trees.append(answer["untrusted_log_data"])
        brief.process_chain = process_chain(trees)

        found = extract_entities(docs, trees)
        indicators = [
            *[(ip, "ip") for ip in found.ips if not is_internal_ip(ip)],
            *[(domain, "domain") for domain in found.domains],
            *[(sha, "hash") for sha in found.hashes],
        ]
        for value, kind in indicators[: settings.intel_max_indicators]:
            await look_up(
                evidence,
                brief,
                state,
                records,
                "check_reputation",
                {"indicator": value, "type": kind},
            )
        for host in found.hosts[: settings.intel_max_hosts_users]:
            await look_up(evidence, brief, state, records, "get_host_info", {"host": host})
        users = [u for u in found.users if u.lower() not in NOT_DIRECTORY_USERS]
        for user in users[: settings.intel_max_hosts_users]:
            await look_up(evidence, brief, state, records, "get_user_info", {"user": user})
        event_ids = found.event_ids[: settings.intel_max_anomaly_events]
        for i in range(0, len(event_ids), ANOMALY_BATCH):
            await look_up(
                evidence,
                brief,
                state,
                records,
                "score_anomaly",
                {"event_ids": event_ids[i : i + ANOMALY_BATCH]},
            )
        return await network_enrichment(state, evidence, brief, records, trees)

    async def network_enrichment(
        state: Case,
        evidence: Evidence,
        brief: IntelBrief,
        records: list[ToolCallRecord],
        trees: list[dict[str, Any]],
    ) -> str | None:
        """Code-run and uncharged. Returns a note for the report if the cap left anything out."""
        calls = network_calls(state.alert, trees)
        allowed = settings.intel_max_network_processes * len(NETWORK_TOOLS)
        answers = []
        for name, args in calls[:allowed]:
            answer, record = await run_call(
                deps,
                evidence,
                CYBERINTEL,
                frozenset(NETWORK_TOOLS),
                state.alert,
                name,
                args,
                "code",
            )
            records.append(record)
            answers.append(answer)
        indicators = network_indicators(answers, evidence)
        checked = indicators[: settings.intel_max_network_indicators]
        known_bad = 0
        for value, kind in checked:
            answer, record = await run_call(
                deps,
                evidence,
                CYBERINTEL,
                frozenset({"check_reputation"}),
                state.alert,
                "check_reputation",
                {"indicator": value, "type": kind},
                "code",
            )
            records.append(record)
            reputation = (answer.get("untrusted_log_data") or {}).get("reputation")
            known_bad += reputation == "known_bad"
            # Unknown lookups stay in the ledger, not the brief: every later prompt carries it.
            if reputation not in (None, "unknown"):
                absorb(brief, "check_reputation", answer)
        calls_left_out = max(len(calls) - allowed, 0)
        lookups_left_out = len(indicators) - len(checked)
        log.info(
            "network enrichment: %d calls, %d indicators checked, %d known_bad; "
            "the cap left out %d calls and %d lookups",
            len(answers),
            len(checked),
            known_bad,
            calls_left_out,
            lookups_left_out,
        )
        if calls_left_out or lookups_left_out:
            return (
                f"Network enrichment hit its cap: {calls_left_out} network call(s) and "
                f"{lookups_left_out} reputation lookup(s) were left out."
            )
        return None

    async def llm_lookups(
        state: Case, evidence: Evidence, brief: IntelBrief, records: list[ToolCallRecord]
    ) -> list[BaseMessage]:
        """Up to settings.intel_tool_calls more lookups chosen by the model."""
        left = settings.intel_tool_calls
        specs = tool_specs(INTEL_TOOLS)
        conversation: list[BaseMessage] = []
        start: list[BaseMessage] = [
            SystemMessage(f"{SYSTEM}\n\n{INTEL.format(calls=left)}"),
            intel_context(state, brief),
        ]
        while left > 0:
            try:
                reply = await deps.llm.invoke_tools("intel", [*start, *conversation], specs)
            except LLMError as exc:
                log.warning("intel lookups stopped: %s", exc)
                break
            if not reply.tool_calls:
                break
            conversation.append(reply)
            for call in reply.tool_calls:
                if left <= 0:
                    answer: dict[str, Any] = {"error": "no lookups left"}
                else:
                    answer, record = await run_call(
                        deps,
                        evidence,
                        CYBERINTEL,
                        INTEL_TOOLS,
                        state.alert,
                        call["name"],
                        call["args"],
                    )
                    records.append(record)
                    left -= int(record.charged)
                    if record.repeat_of is None:
                        absorb(brief, call["name"], answer)
                conversation.append(
                    ToolMessage(to_json(answer), tool_call_id=call["id"], name=call["name"])
                )
        return conversation

    def intel_context(state: Case, brief: IntelBrief) -> HumanMessage:
        return HumanMessage(
            to_json(
                {
                    "alert": alert_block(state.alert),
                    "untrusted_log_data": {
                        "alert_description": state.alert.description,
                        "trigger_events": state.trigger_events,
                        "intel_facts": brief.facts(),
                    },
                }
            )
        )

    async def intel(state: Case) -> dict[str, Any]:
        evidence = state.evidence.model_copy(deep=True)
        brief = IntelBrief()
        records: list[ToolCallRecord] = []
        note = await code_lookups(state, evidence, brief, records)
        conversation = await llm_lookups(state, evidence, brief, records)
        extra = transcript(conversation, EXTRA_LOOKUP_TOKENS)
        messages = [
            SystemMessage(f"{SYSTEM}\n\n{INTEL_BRIEF}"),
            intel_context(state, brief),
            HumanMessage(to_json({"extra_lookups": extra})),
        ]
        try:
            draft = await deps.llm.invoke_structured("intel_brief", messages, IntelDraft)
            brief.assessment, brief.notable = draft.assessment, draft.notable
        except LLMError as exc:
            # The facts are all there; only the model's reading of them is missing.
            log.warning("intel assessment failed: %s", exc)
        return {
            "evidence": evidence,
            "intel_brief": brief,
            "tool_logs": with_records(state.tool_logs, CYBERINTEL, records),
            "token_use": deps.llm.usage.by_agent(),
            "closure_notes": [*state.closure_notes, *([note] if note else [])],
            "handoffs": [*state.handoffs, handoff(CYBERINTEL, INVESTIGATOR)],
        }

    return intel
