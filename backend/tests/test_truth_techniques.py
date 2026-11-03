"""Every technique a truth file expects must exist, unrevoked and undeprecated, in the pinned
ATT&CK bundle. The spec's table was written from memory; this is what makes it trustworthy."""

from pathlib import Path

import pytest
import yaml

from app.attack.catalog import get_catalog
from scripts.gen.dataset import CLAIM_ORDER, VARIANTS, Dataset
from scripts.generate import write_dataset

SEED = 42


@pytest.mark.parametrize("variant", VARIANTS)
def test_truth_techniques_exist_in_catalog(
    datasets: dict[int, Dataset], variant: int, tmp_path: Path
) -> None:
    truth_dir = tmp_path / "truth"
    write_dataset(datasets[variant], SEED, variant, tmp_path / "generated", truth_dir)
    truth_files = sorted(truth_dir.glob("s*.yaml"))
    assert [p.stem for p in truth_files] == sorted(m.SCENARIO_ID for m in CLAIM_ORDER)

    catalog = get_catalog()
    for path in truth_files:
        truth = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert truth["verdict"] in ("malicious", "benign")
        assert truth["key_event_ids"]
        for technique_id in truth["expected_techniques"]:
            technique = catalog.get_technique(technique_id)
            assert technique is not None, f"{path.name}: {technique_id} not in ATT&CK v20"
            assert not technique.revoked, f"{path.name}: {technique_id} is revoked"
            assert not technique.deprecated, f"{path.name}: {technique_id} is deprecated"
