import json
import shutil
from pathlib import Path

import pytest

from app.attack import catalog as catalog_module
from app.attack.catalog import (
    ATTACK_DIR,
    AttackBundleError,
    AttackCatalog,
    get_catalog,
    short_description,
)


@pytest.fixture(scope="session")
def catalog() -> AttackCatalog:
    return get_catalog()


def test_powershell_technique(catalog: AttackCatalog) -> None:
    t = catalog.get_technique("T1059.001")

    assert t is not None
    assert t.name == "PowerShell"
    assert t.tactics == ["Execution"]
    assert not t.revoked and not t.deprecated
    assert "(Citation:" not in t.short_description
    assert 0 < len(t.short_description) <= 300


def test_tactics_come_from_v20_bundle(catalog: AttackCatalog) -> None:
    # v19 replaced Defense Evasion; an older bundle or model memory would say otherwise.
    t = catalog.get_technique("T1027")

    assert t is not None
    assert t.tactics == ["Stealth"]


def test_lookup_is_case_and_space_insensitive(catalog: AttackCatalog) -> None:
    assert catalog.get_technique(" t1059.001 ") == catalog.get_technique("T1059.001")


def test_revoked_technique_is_flagged(catalog: AttackCatalog) -> None:
    # T1086 was the pre-2020 PowerShell ID, revoked in favour of T1059.001.
    t = catalog.get_technique("T1086")

    assert t is not None
    assert t.revoked


def test_deprecated_technique_is_flagged(catalog: AttackCatalog) -> None:
    t = catalog.get_technique("T1064")

    assert t is not None
    assert t.deprecated
    assert not t.revoked


@pytest.mark.parametrize("fake_id", ["T9999.999", "T1059.999", "TA0002", "powershell", ""])
def test_unknown_or_malformed_id_returns_none(catalog: AttackCatalog, fake_id: str) -> None:
    assert catalog.get_technique(fake_id) is None


def test_search_ranks_name_matches_and_skips_revoked(catalog: AttackCatalog) -> None:
    results = catalog.search("powershell")

    ids = [t.id for t in results]
    assert ids[0] == "T1059.001"
    assert "T1086" not in ids
    assert len(results) <= 5


def test_search_respects_limit_and_empty_keyword(catalog: AttackCatalog) -> None:
    assert len(catalog.search("credential", limit=2)) == 2
    assert catalog.search("   ") == []
    assert catalog.search("credential", limit=0) == []


def test_short_description_strips_citations_and_links() -> None:
    text = "Uses [PowerShell](https://attack.mitre.org/x) to run.(Citation: A) More.\n\nSecond."

    assert short_description(text) == "Uses PowerShell to run. More."


def test_wrong_version_fails_clearly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = json.loads((ATTACK_DIR / "manifest.json").read_text(encoding="utf-8"))
    shutil.copy(ATTACK_DIR / manifest["file"], tmp_path / manifest["file"])
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(catalog_module, "EXPECTED_VERSION", "99.0")

    with pytest.raises(AttackBundleError, match=r"expected 99\.0"):
        AttackCatalog(tmp_path)


def test_tampered_bundle_fails_clearly(tmp_path: Path) -> None:
    manifest = json.loads((ATTACK_DIR / "manifest.json").read_text(encoding="utf-8"))
    (tmp_path / manifest["file"]).write_bytes(b"not the bundle")
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(AttackBundleError, match="SHA-256"):
        AttackCatalog(tmp_path)
