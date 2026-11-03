"""Checks that no generated row points at real attacker-looking infrastructure (hard rule 10).

- Every public IP is a known SaaS address from infra.py, employee home broadband
  (TEST-NET-1), or one of the two reserved "bad" ranges.
- Every DNS name is a known SaaS domain, the internal domain, or a .example domain.
- Every known-bad intel indicator and every scenario indicator is in the bad ranges or .example.
- Every `-EncodedCommand` decodes to printable text, and any URL or IP inside it is a
  .example domain or a reserved bad address. Base64 would otherwise hide what we ship.
"""

import base64
import binascii
import ipaddress
import re
from collections.abc import Iterable

from app.telemetry.models import Event, IntelEntry
from scripts.gen.infra import (
    BENIGN_DOMAINS,
    BENIGN_IPS,
    HOME_NET,
    INTERNAL_DOMAIN,
    is_bad_domain,
    is_bad_ip,
)
from scripts.gen.scenario import ScenarioResult

ENCODED = re.compile(r"-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE)
URL_HOST = re.compile(r"[a-z][a-z0-9+.-]*://([^/:'\"\s]+)", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def decode_encoded_commands(cmdline: str) -> list[str]:
    """Decode every -enc/-EncodedCommand argument; raises ValueError if one isn't readable."""
    decoded = []
    for blob in ENCODED.findall(cmdline):
        try:
            text = base64.b64decode(blob, validate=True).decode("utf-16-le")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError(f"undecodable -enc payload {blob[:20]}...") from exc
        if not text.isprintable():
            raise ValueError(f"-enc payload is not printable text: {text[:40]!r}")
        decoded.append(text)
    return decoded


def _ip_allowed(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return address.is_private or ip in BENIGN_IPS or address in HOME_NET or is_bad_ip(ip)


def _domain_allowed(domain: str) -> bool:
    return (
        domain in BENIGN_DOMAINS or domain.endswith(f".{INTERNAL_DOMAIN}") or is_bad_domain(domain)
    )


def _event_ips(e: Event) -> Iterable[str]:
    if e.network:
        yield from (e.network.src_ip, e.network.dst_ip)
    if e.dns:
        yield from e.dns.answers
    if e.logon and e.logon.src_ip:
        yield e.logon.src_ip


def _indicator_problem(indicator: str, kind: str) -> str | None:
    if kind == "ip" and not is_bad_ip(indicator):
        return f"bad IP {indicator} is outside 203.0.113.0/24 and 198.51.100.0/24"
    if kind == "domain" and not is_bad_domain(indicator):
        return f"bad domain {indicator} is not a .example domain"
    return None


def check_encoded(cmdline: str) -> list[str]:
    try:
        decoded = decode_encoded_commands(cmdline)
    except ValueError as exc:
        return [str(exc)]
    problems = []
    for text in decoded:
        for host in URL_HOST.findall(text):
            if not (is_bad_domain(host) or (IPV4.fullmatch(host) and is_bad_ip(host))):
                problems.append(f"decoded -enc content references {host}")
        for ip in IPV4.findall(text):
            if not is_bad_ip(ip):
                problems.append(f"decoded -enc content references {ip}")
    return problems


def check_dataset(
    events: list[Event], intel: list[IntelEntry], scenarios: list[ScenarioResult]
) -> list[str]:
    problems: list[str] = []
    for e in events:
        problems += [
            f"{e.event_id}: public IP {ip} not allowed"
            for ip in _event_ips(e)
            if not _ip_allowed(ip)
        ]
        if e.dns and not _domain_allowed(e.dns.query):
            problems.append(f"{e.event_id}: domain {e.dns.query} not allowed")
        if e.process and e.process.cmdline:
            problems += [f"{e.event_id}: {p}" for p in check_encoded(e.process.cmdline)]
    for entry in intel:
        if entry.reputation == "known_bad":
            problem = _indicator_problem(entry.indicator, entry.type)
            if problem:
                problems.append(f"intel: {problem}")
    for result in scenarios:
        for i in result.indicators:
            problem = _indicator_problem(i.indicator, i.type)
            if problem:
                problems.append(f"{result.scenario_id}: {problem}")
    return problems
