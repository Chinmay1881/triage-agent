"""Hard rule 3, enforced: nothing under backend/app may import the generator or scenarios,
or name the truth directory. pytest's pythonpath includes the repo root so tests can import
scenarios/, which means only this test stops app code from doing the same."""

import ast
import re
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app"
FORBIDDEN_PACKAGES = ("scripts", "scenarios")
# Either path separator, and the dynamic import forms an AST import check would miss.
TRUTH_PATH = re.compile(r"scenarios[\\/]+truth", re.IGNORECASE)
DYNAMIC_IMPORT = re.compile(
    r"(?:import_module|__import__)\(\s*[\"'](?:scripts|scenarios)(?:[.\"'])"
)

APP_FILES = sorted(p for p in APP.rglob("*") if p.is_file() and p.suffix != ".pyc")


def forbidden_imports(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        found += [n for n in names if n.split(".")[0] in FORBIDDEN_PACKAGES]
    return found


def test_app_files_found() -> None:
    assert any(p.suffix == ".py" for p in APP_FILES)


@pytest.mark.parametrize("path", APP_FILES, ids=lambda p: p.relative_to(APP).as_posix())
def test_app_never_touches_scenarios_or_truth(path: Path) -> None:
    text = path.read_text(encoding="utf-8")

    assert not TRUTH_PATH.search(text), "mentions the scenario truth directory"
    assert not DYNAMIC_IMPORT.search(text), "dynamically imports scripts/scenarios"
    if path.suffix == ".py":
        assert forbidden_imports(text) == []


@pytest.mark.parametrize(
    "source",
    [
        "import scenarios",
        "import scenarios.s01_phishing_powershell as s",
        "from scripts.gen import dataset",
        "from scenarios import s01_phishing_powershell",
        "def f():\n    import scripts.load\n",
    ],
)
def test_detects_forbidden_imports(source: str) -> None:
    assert forbidden_imports(source)


@pytest.mark.parametrize(
    "text",
    [
        'open("../scenarios/truth/s01.yaml")',
        r'Path("scenarios\\truth")',
        'importlib.import_module("scenarios.s01_phishing_powershell")',
        '__import__("scripts.gen")',
    ],
)
def test_detects_truth_paths_and_dynamic_imports(text: str) -> None:
    assert TRUTH_PATH.search(text) or DYNAMIC_IMPORT.search(text)


def test_allows_normal_app_imports() -> None:
    assert forbidden_imports("from app.telemetry.models import Event\nimport json") == []
