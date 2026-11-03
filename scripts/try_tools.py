"""Walk through a scenario's alert with the agent's tools, the way an analyst would.

    uv run --project backend python scripts/try_tools.py s01 [--variant 1]

Uses the same scripted path as the solvability test and prints every call and its result
exactly as the agent will receive it. The alert ID comes from regenerating the dataset in
memory, not from truth files. Run `python tasks.py seed` first (it loads variant 1).
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from app.telemetry.db import telemetry_client, telemetry_db  # noqa: E402
from app.tools._common import estimate_tokens  # noqa: E402
from scripts.analyst_paths import PATHS, PathError, investigate  # noqa: E402
from scripts.gen.dataset import VARIANTS, build_dataset  # noqa: E402


async def run(scenario_id: str, variant: int) -> int:
    dataset = build_dataset(42, variant)
    alert = next(r.alert for r in dataset.scenarios if r.scenario_id == scenario_id)
    print(f"ALERT {alert.alert_id}  {alert.rule}  host={alert.host} user={alert.user}")
    print(f"      {alert.ts:%Y-%m-%d %H:%M:%S}Z  triggers={[t.event_id for t in alert.triggers]}")
    client = telemetry_client()
    try:
        analyst = await investigate(telemetry_db(client), scenario_id, alert.alert_id)
    except PathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        await client.close()
    for n, step in enumerate(analyst.steps, start=1):
        args = ", ".join(f"{k}={v}" for k, v in step.args.items())
        print(f"\n[{n}] {step.tool}({args})  ~{estimate_tokens(step.result)} tokens")
        print(json.dumps(step.result, indent=2, default=str, ensure_ascii=False))
    print(f"\n{len(analyst.steps)} tool calls (agent budget: 12)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Investigate one scenario by hand")
    parser.add_argument("scenario", choices=sorted(PATHS))
    parser.add_argument(
        "--variant",
        type=int,
        choices=VARIANTS,
        default=1,
        help="must match the variant loaded in Mongo (seed loads 1)",
    )
    args = parser.parse_args()
    # Windows consoles and redirects default to cp1252; log data can hold any character.
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    return asyncio.run(run(args.scenario, args.variant))


if __name__ == "__main__":
    sys.exit(main())
