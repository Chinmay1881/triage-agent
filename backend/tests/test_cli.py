"""app/cli.py refuses blocklisted alerts before it builds a model or touches the database."""

import json
from pathlib import Path

import pytest

from app import blocklist as blocklist_module
from app import cli
from scripts.gen.dataset import Dataset
from scripts.generate import write_blocklist


def blocklist(tmp_path: Path, ids: list[str]) -> Path:
    path = tmp_path / "cli_blocklist.json"
    path.write_text(json.dumps({"alert_ids": ids}), encoding="utf-8")
    return path


def test_refuses_blocklisted_alert(tmp_path: Path) -> None:
    reason = blocklist_module.refusal("alt_0007", blocklist(tmp_path, ["alt_0007"]))

    assert reason is not None and "eval harness" in reason


def test_allows_other_alerts(tmp_path: Path) -> None:
    assert blocklist_module.refusal("alt_0001", blocklist(tmp_path, ["alt_0007"])) is None


def test_missing_blocklist_refuses_everything(tmp_path: Path) -> None:
    reason = blocklist_module.refusal("alt_0001", tmp_path / "missing.json")

    assert reason is not None and "tasks.py seed" in reason


def test_main_refuses_before_building_a_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def no_model(*args: object) -> None:
        raise AssertionError("the model must not be built for a refused alert")

    monkeypatch.setattr(blocklist_module, "BLOCKLIST", blocklist(tmp_path, ["alt_0007"]))
    monkeypatch.setattr(cli, "get_model", no_model)
    monkeypatch.setattr("sys.argv", ["app.cli", "investigate", "--alert", "alt_0007"])

    assert cli.main() == 3
    assert "refused" in capsys.readouterr().err


def test_generator_blocklists_exactly_the_injection_scenario(
    tmp_path: Path, datasets: dict[int, Dataset]
) -> None:
    for ds in datasets.values():
        write_blocklist(ds, tmp_path)
        written = json.loads((tmp_path / "cli_blocklist.json").read_text(encoding="utf-8"))
        expected = [r.alert.alert_id for r in ds.scenarios if r.injection]
        assert written == {"alert_ids": expected} and len(expected) == 1
