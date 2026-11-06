"""Does a finding's evidence actually support it? Pure functions over event documents and the
evidence ledger; hard rule 5's "code verifies citations" goes further than "the ID exists".

- An event citation must contain an entity the claim names: a process, IP, domain, hash, file
  or task. A host or user alone only grounds a logon event, whose subject really is that
  account. Otherwise "FIN-WS-02 runs Windows 11" could cite any event on that host, and any
  claim naming the host would be grounded by any event there.
- Host and user facts, reputation facts and absence claims cite the tool result instead
  ("tool:get_host_info#3"). The ref must exist and have succeeded. An observation must name an
  entity from that result; an absence claim has nothing to name, so the call itself is the
  evidence (Reviewer-Agent re-verifies it).
- Failing citations are removed, and a finding left with none is dropped. An absence claim also
  needs at least one tool citation: an event can't show that something didn't happen.
- An action claim ("msupdate.exe wrote X") must be backed by an event showing that process doing
  that kind of thing. Naming real entities isn't enough: "the file was created by msupdate.exe"
  once passed by citing a process tree, when an event showed powershell.exe wrote the file.
"""

import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from app.agent.case import Evidence, FindingDraft
from app.telemetry.decode import decode_encoded_command

EVENT_CITATION = re.compile(r"^evt_\d{6}$")
TOOL_CITATION = re.compile(r"^tool:[a-z_]+#\d+$")
URL_HOST = re.compile(r"[a-z][a-z0-9+.-]*://([^/:'\"\s]+)", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BARE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:example|com|net|org|io|co|uk|us|gov|edu|info|biz)\b", re.IGNORECASE
)
FILE_NAME = re.compile(r"[\w.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|bin|log|tmp|zip|rar|7z)\b", re.I)
# Process names whose stem is an everyday word, so only the full name counts as naming them.
GENERIC_STEMS = {"system", "code", "services", "updater", "git"}
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MIN_HASH_PREFIX = 8
# Claims that assert something did not happen. A safety net: the summarizer also labels these
# itself. "no signer" is a field value, not an absence claim, so nouns are listed.
ABSENCE = re.compile(
    r"\bno\s+(?:\w+\s+){0,3}?(?:observed|found|seen|detected|evidence|activity|connections?|"
    r"process(?:es)?|persistence|traffic|quer(?:y|ies)|tasks?|logons?|children|instances?)\b"
    r"|\b(?:not|never|n't)\s+(?:\w+\s+){0,2}?(?:observed|found|seen|detected|spawn(?:ed)?|"
    r"contact(?:ed)?|initiated?|establish(?:ed)?|ma(?:ke|de)|created?)\b",
    re.IGNORECASE,
)


# Verb forms by the event type that shows the action. Starting a process is the odd one out:
# the event is the child's process_start, so the acting process is its parent_name.
ACTION_EVENTS: dict[str, frozenset[str]] = {
    "write": frozenset({"file_write"}),
    "create": frozenset({"file_write", "scheduled_task"}),
    "start": frozenset({"process_start"}),
    "connect": frozenset({"network_conn"}),
    "download": frozenset({"network_conn", "file_write"}),
    "resolve": frozenset({"dns_query"}),
}
VERB_KIND: dict[str, str] = {
    "wrote": "write",
    "writes": "write",
    "written": "write",
    "created": "create",
    "creates": "create",
    "started": "start",
    "starts": "start",
    "spawned": "start",
    "spawns": "start",
    "launched": "start",
    "launches": "start",
    "connected": "connect",
    "connects": "connect",
    "downloaded": "download",
    "downloads": "download",
    "resolved": "resolve",
    "resolves": "resolve",
}
VERB = "|".join(sorted(VERB_KIND, key=len, reverse=True))
WORD = r"[A-Za-z0-9_.\-]+"
PID = r"(?:\s*\(pid\s*\d+\))?"
PASSIVE_ACTION = re.compile(rf"\b(?P<verb>{VERB})\s+by\s+(?:the\s+)?(?P<actor>{WORD})", re.I)
PASSIVE_SUBJECT = re.compile(
    rf"(?P<subject>{WORD}){PID}(?:\s+process)?\s+(?:was|is|were)\s*$", re.I
)
ACTIVE_ACTION = re.compile(
    rf"(?<![\w.\-])(?P<actor>{WORD}){PID}(?:\s+process)?(?:,?\s+which)?\s+(?:(?:also|then|has|had)\s+)?"
    rf"(?P<verb>{VERB})\b(?!\s+by\b)(?=(?:\s+(?:(?:a|an|the|new)\s+)*(?P<object>{WORD}))?)",
    re.I,
)
SUBJECT_STARTED = re.compile(
    rf"(?P<subject>{WORD}){PID}(?:\s+process)?\s+(?:was|is|were)\s+"
    rf"(?:started|spawned|launched)\b(?!\s+by\b)",
    re.I,
)
CONNECTION_FROM = re.compile(rf"\bconnections?\s+from\s+(?:the\s+)?(?P<actor>{WORD})", re.I)


@dataclass(frozen=True)
class ActionClaim:
    """`actor` did something of `kind`. For "start", `target` is the started process; `loose` means
    "X started" with no object, where X may be the parent or the process itself."""

    kind: str
    actor: str | None = None
    target: str | None = None
    loose: bool = False


def _stem(name: str | None) -> str:
    return (name or "").lower().removesuffix(".exe")


def _process_token(token: str | None, known: set[str]) -> str | None:
    """`token` if it names a process: a .exe name, or a stem seen in this investigation."""
    if not token:
        return None
    cleaned = token.rstrip(".,;:")
    return cleaned if cleaned.lower().endswith(".exe") or _stem(cleaned) in known else None


def action_claims(claim: str, known: set[str]) -> list[ActionClaim]:
    """The process actions a claim asserts. `known` holds process-name stems."""
    found: list[ActionClaim] = []
    for m in PASSIVE_ACTION.finditer(claim):
        actor = _process_token(m["actor"], known)
        if actor is None:
            continue
        kind = VERB_KIND[m["verb"].lower()]
        before = PASSIVE_SUBJECT.search(claim[: m.start()])
        subject = _process_token(before["subject"], known) if before else None
        found.append(ActionClaim(kind, actor, subject if kind == "start" else None))
    for m in ACTIVE_ACTION.finditer(claim):
        actor = _process_token(m["actor"], known)
        if actor is None:
            continue
        kind = VERB_KIND[m["verb"].lower()]
        target = _process_token(m["object"], known) if kind == "start" else None
        found.append(ActionClaim(kind, actor, target, loose=kind == "start" and target is None))
    for m in SUBJECT_STARTED.finditer(claim):
        subject = _process_token(m["subject"], known)
        if subject is not None:
            found.append(ActionClaim("start", target=subject))
    for m in CONNECTION_FROM.finditer(claim):
        actor = _process_token(m["actor"], known)
        if actor is not None:
            found.append(ActionClaim("connect", actor))
    return found


def event_shows_action(action: ActionClaim, doc: dict[str, Any]) -> bool:
    if doc.get("event_type") not in ACTION_EVENTS[action.kind]:
        return False
    process = doc.get("process") or {}
    name, parent = _stem(process.get("name")), _stem(process.get("parent_name"))
    actor, target = _stem(action.actor), _stem(action.target)
    if action.kind != "start":
        return name == actor
    if action.loose:
        return actor in (name, parent)
    return (not actor or parent == actor) and (not target or name == target)


def known_process_stems(docs: dict[str, dict[str, Any]], evidence: Evidence) -> set[str]:
    names = {_stem(n) for names in evidence.aliases.values() for n in names}
    for doc in docs.values():
        process = doc.get("process") or {}
        names |= {_stem(process.get("name")), _stem(process.get("parent_name"))}
    return names - {""} - GENERIC_STEMS


def check_actions(
    claim: str, kept: list[str], docs: dict[str, dict[str, Any]], evidence: Evidence
) -> list[str]:
    """`kept` minus event citations that show none of the claim's actions. Every action must be
    shown by some cited event, or nothing is kept: a tool result can't prove who did what."""
    actions = action_claims(claim, known_process_stems(docs, evidence))
    if not actions:
        return kept
    events = {c: docs[c] for c in kept if c in docs}
    if not all(any(event_shows_action(a, d) for d in events.values()) for a in actions):
        return []
    return [
        c for c in kept if c not in events or any(event_shows_action(a, events[c]) for a in actions)
    ]


def is_absence_claim(claim: str) -> bool:
    return ABSENCE.search(claim) is not None


def is_internal_ip(value: str) -> bool:
    """RFC 1918 only. ipaddress's is_private also covers the documentation ranges the scenarios'
    bad infrastructure lives in, so it would hide exactly the addresses worth looking up."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and any(address in net for net in RFC1918)


def text_entities(text: str) -> set[str]:
    """Domains, IPs and file names mentioned in free text such as a command line."""
    found = set(URL_HOST.findall(text)) | set(IPV4.findall(text)) | set(BARE_DOMAIN.findall(text))
    return found | set(FILE_NAME.findall(text))


def _names(name: str | None) -> set[str]:
    if not name:
        return set()
    stem = name.lower().removesuffix(".exe")
    return {name} if stem in GENERIC_STEMS else {name, stem}


def event_entities(doc: dict[str, Any], labels: Iterable[str] = ()) -> set[str]:
    """What an event is specifically about: processes, IPs, domains, hashes, files, tasks."""
    found: set[str] = set(labels)
    process = doc.get("process") or {}
    found |= _names(process.get("name")) | _names(process.get("parent_name"))
    if process.get("sha256"):
        found.add(process["sha256"])
    cmdline = process.get("cmdline")
    if cmdline:
        found |= text_entities(cmdline)
        found |= text_entities(decode_encoded_command(cmdline) or "")
    network = doc.get("network") or {}
    found |= {network[k] for k in ("src_ip", "dst_ip") if network.get(k)}
    dns = doc.get("dns") or {}
    if dns.get("query"):
        found.add(dns["query"])
    found |= set(dns.get("answers") or [])
    logon = doc.get("logon") or {}
    if logon.get("src_ip"):
        found.add(logon["src_ip"])
    file = doc.get("file") or {}
    if file.get("path"):
        found |= {file["path"], *_names(re.split(r"[\\/]", file["path"])[-1])}
    if file.get("sha256"):
        found.add(file["sha256"])
    task = doc.get("task") or {}
    if task.get("task_name"):
        found.add(task["task_name"])
    if task.get("command"):
        found |= text_entities(task["command"])
    access = doc.get("access") or {}
    found |= _names(access.get("target_name"))
    return found


def names_entity(claim: str, entity: str) -> bool:
    """`claim` mentions `entity` as a whole token, ignoring case. A long hash may be shortened."""
    if not entity:
        return False
    pattern = rf"(?<![\w-]){re.escape(entity)}(?![\w-])"
    if re.search(pattern, claim, re.IGNORECASE):
        return True
    if re.fullmatch(r"[0-9a-f]{64}", entity):
        return re.search(rf"\b{entity[:MIN_HASH_PREFIX]}[0-9a-f]*", claim) is not None
    return False


def event_grounds(claim: str, doc: dict[str, Any], labels: Iterable[str] = ()) -> bool:
    if any(names_entity(claim, e) for e in event_entities(doc, labels)):
        return True
    if doc.get("event_type") == "logon":
        return any(names_entity(claim, str(doc.get(k) or "")) for k in ("host", "user"))
    return False


def tool_entities(ref: str, evidence: Evidence) -> Iterator[str]:
    info = evidence.tool_refs[ref]
    yield from info.entities
    for entity in info.entities:
        yield from evidence.aliases.get(entity, [])


def tool_grounds(claim: str, kind: str, ref: str, evidence: Evidence) -> bool:
    info = evidence.tool_refs.get(ref)
    if info is None or not info.ok:
        return False
    if kind == "absence":
        return True
    return any(names_entity(claim, e) for e in tool_entities(ref, evidence))


def grounded_citations(
    draft: FindingDraft, kind: str, docs: dict[str, dict[str, Any]], evidence: Evidence
) -> list[str]:
    """The citations of a finding that survive. Empty means the finding is dropped."""
    kept = []
    for citation in draft.citations:
        if EVENT_CITATION.match(citation):
            doc = docs.get(citation)
            labels = evidence.event_labels.get(citation, [])
            if (
                citation in evidence.seen_event_ids
                and doc is not None
                and event_grounds(draft.claim, doc, labels)
            ):
                kept.append(citation)
        elif TOOL_CITATION.match(citation) and tool_grounds(draft.claim, kind, citation, evidence):
            kept.append(citation)
    if kind == "absence":
        return kept if any(c.startswith("tool:") for c in kept) else []
    return check_actions(draft.claim, kept, docs, evidence)
