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
"""

import ipaddress
import re
from collections.abc import Iterable, Iterator
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
    if kind == "absence" and not any(c.startswith("tool:") for c in kept):
        return []
    return kept
