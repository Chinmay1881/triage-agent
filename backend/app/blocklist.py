"""Alerts the dev tools refuse: the prompt-injection scenario runs only through the eval harness,
so its log text is never printed during development.

The generator writes data/generated/cli_blocklist.json with the alert IDs and nothing else. Only
the CLI and the API use this module; the agents and the tools must investigate every alert without
being told which one is the trap (tests/test_app_isolation.py).
"""

import json
from pathlib import Path

BLOCKLIST = Path(__file__).resolve().parents[2] / "data" / "generated" / "cli_blocklist.json"


def blocked_alerts(path: Path) -> set[str] | None:
    """Alert IDs to refuse, or None if the blocklist hasn't been generated yet."""
    if not path.exists():
        return None
    return set(json.loads(path.read_text(encoding="utf-8"))["alert_ids"])


def refusal(alert_id: str, path: Path | None = None) -> str | None:
    """Why this alert may not run, or None if it may."""
    path = path or BLOCKLIST
    blocked = blocked_alerts(path)
    if blocked is None:
        return f"{path} is missing; run `python tasks.py seed` first"
    if alert_id in blocked:
        return (
            f"{alert_id} is reserved for the eval harness (evals/, Phase 5); it is never run or "
            "printed during development"
        )
    return None
