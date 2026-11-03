"""The local threat-intel feed: vendor allow-list entries, a few unrelated known-bad decoys,
and only the scenario indicators marked `listed`. Most scenario infrastructure is left out on
purpose, so check_reputation often answers "unknown"."""

from typing import Literal

from app.telemetry.models import IntelEntry
from scripts.gen.core import benign_sha256, fake_sha256
from scripts.gen.infra import BENIGN_DOMAINS
from scripts.gen.scenario import ScenarioResult

KNOWN_GOOD_DOMAINS = [
    "outlook.office365.com",
    "login.microsoftonline.com",
    "teams.microsoft.com",
    "definitionupdates.microsoft.com",
    "github.com",
    "pypi.org",
    "www.google.com",
    "update.googleapis.com",
]
KNOWN_GOOD_BINARIES = [
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "OUTLOOK.EXE",
    "WINWORD.EXE",
    "EXCEL.EXE",
    "chrome.exe",
    "msedge.exe",
    "MsMpEng.exe",
]
# Unrelated campaigns, from the top of the reserved ranges (scenarios use the bottom 150).
DECOYS: list[tuple[str, Literal["ip", "domain", "hash"], str]] = [
    ("203.0.113.201", "ip", "Cobalt Strike team server"),
    ("203.0.113.214", "ip", "Phishing kit hosting"),
    ("198.51.100.222", "ip", "SSH brute-force botnet node"),
    ("198.51.100.237", "ip", "Tor exit relay"),
    ("login-microsoftonline-verify.example", "domain", "Credential phishing page"),
    ("cdn-jquery-update.example", "domain", "Web skimmer"),
    ("payroll-portal-secure.example", "domain", "Credential phishing page"),
    (fake_sha256("decoy", "qakbot"), "hash", "Banking trojan loader"),
    (fake_sha256("decoy", "mimikatz"), "hash", "Credential dumping tool"),
]


def build_intel(results: list[ScenarioResult]) -> list[IntelEntry]:
    entries = [
        IntelEntry(
            indicator=d,
            type="domain",
            reputation="known_good",
            source="vendor-allowlist",
            description="Major SaaS provider",
        )
        for d in KNOWN_GOOD_DOMAINS
        if d in BENIGN_DOMAINS
    ]
    entries += [
        IntelEntry(
            indicator=benign_sha256(name),
            type="hash",
            reputation="known_good",
            source="vendor-allowlist",
            description=f"Signed system or vendor binary ({name})",
        )
        for name in KNOWN_GOOD_BINARIES
    ]
    entries += [
        IntelEntry(
            indicator=indicator,
            type=kind,
            reputation="known_bad",
            source="isac-feed",
            description=description,
        )
        for indicator, kind, description in DECOYS
    ]
    entries += [
        IntelEntry(
            indicator=i.indicator,
            type=i.type,
            reputation="known_bad",
            source="isac-feed",
            description=i.description,
        )
        for r in results
        for i in r.indicators
        if i.listed
    ]
    return sorted(entries, key=lambda e: (e.type, e.indicator))
