"""Read-only view of the pinned Enterprise ATT&CK bundle in data/attack/.

Technique names and tactics must come from here, never from the model's memory: ATT&CK v19
retired Defense Evasion, and models trained on older versions still produce it.
"""

import gzip
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from mitreattack.stix20 import MitreAttackData
from pydantic import BaseModel
from stix2 import MemoryStore

ATTACK_DIR = Path(__file__).resolve().parents[3] / "data" / "attack"
EXPECTED_VERSION = "20.0"
SHORT_DESCRIPTION_CHARS = 300

# The catalog only needs techniques and tactics. Dropping relationships, malware, analytics
# etc. before building the STIX store cuts load time from ~10 s to under 1 s.
KEPT_TYPES = frozenset({"attack-pattern", "x-mitre-tactic", "x-mitre-collection"})

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class AttackBundleError(RuntimeError):
    """The pinned bundle is missing, altered, or not the expected ATT&CK version."""


class Technique(BaseModel):
    id: str
    name: str
    tactics: list[str]
    short_description: str
    deprecated: bool
    revoked: bool


def short_description(description: str) -> str:
    first_paragraph = description.strip().split("\n\n", 1)[0]
    text = _MD_LINK.sub(r"\1", _CITATION.sub("", first_paragraph))
    text = " ".join(text.split())
    if len(text) <= SHORT_DESCRIPTION_CHARS:
        return text
    return text[: SHORT_DESCRIPTION_CHARS - 1].rsplit(" ", 1)[0] + "…"


def _load_objects(attack_dir: Path) -> list[dict[str, Any]]:
    manifest_path = attack_dir / "manifest.json"
    if not manifest_path.exists():
        raise AttackBundleError(f"{manifest_path} missing; run `python scripts/fetch_attack.py`")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    packed = (attack_dir / manifest["file"]).read_bytes()
    if hashlib.sha256(packed).hexdigest() != manifest["gz_sha256"]:
        raise AttackBundleError(f"{manifest['file']} does not match its SHA-256 in manifest.json")
    objects: list[dict[str, Any]] = json.loads(gzip.decompress(packed))["objects"]
    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), None
    )
    if version != EXPECTED_VERSION:
        raise AttackBundleError(
            f"ATT&CK bundle is version {version!r}, expected {EXPECTED_VERSION}; "
            "re-run `python scripts/fetch_attack.py`"
        )
    return [o for o in objects if o["type"] in KEPT_TYPES]


class AttackCatalog:
    def __init__(self, attack_dir: Path = ATTACK_DIR) -> None:
        data = MitreAttackData(src=MemoryStore(stix_data=_load_objects(attack_dir)))
        tactic_names = {t["x_mitre_shortname"]: t["name"] for t in data.get_tactics()}
        # Revoked and deprecated techniques stay in the index, flagged, so the mapping
        # validator can say "T1086 is revoked" instead of just "unknown ID".
        self._techniques: dict[str, Technique] = {}
        for obj in data.get_techniques(include_subtechniques=True):
            attack_id = data.get_attack_id(obj["id"])
            if attack_id is None:
                continue
            self._techniques[attack_id] = Technique(
                id=attack_id,
                name=obj["name"],
                tactics=[
                    tactic_names[p["phase_name"]]
                    for p in obj.get("kill_chain_phases", [])
                    if p["phase_name"] in tactic_names
                ],
                short_description=short_description(obj.get("description", "")),
                deprecated=bool(obj.get("x_mitre_deprecated", False)),
                revoked=bool(obj.get("revoked", False)),
            )

    def get_technique(self, technique_id: str) -> Technique | None:
        normalized = technique_id.strip().upper()
        if not _ATTACK_ID.match(normalized):
            return None
        return self._techniques.get(normalized)

    def search(self, keyword: str, limit: int = 5) -> list[Technique]:
        """Active techniques whose name (ranked first) or description contains every word."""
        words = keyword.lower().split()
        if not words or limit < 1:
            return []
        name_hits: list[Technique] = []
        description_hits: list[Technique] = []
        for technique_id in sorted(self._techniques):
            t = self._techniques[technique_id]
            if t.revoked or t.deprecated:
                continue
            name = t.name.lower()
            if all(w in name for w in words):
                name_hits.append(t)
            elif all(w in f"{name} {t.short_description.lower()}" for w in words):
                description_hits.append(t)
        return (name_hits + description_hits)[:limit]


@lru_cache(maxsize=1)
def get_catalog() -> AttackCatalog:
    return AttackCatalog()


def get_technique(technique_id: str) -> Technique | None:
    return get_catalog().get_technique(technique_id)


def search(keyword: str, limit: int = 5) -> list[Technique]:
    return get_catalog().search(keyword, limit)
