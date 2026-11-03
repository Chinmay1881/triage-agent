"""Assembles the world, the background week and the scenarios into one validated dataset."""

import random
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from app.telemetry.models import Alert, Event, Host, IntelEntry, User
from scenarios import (
    s01_phishing_powershell,
    s02_lsass_dump,
    s03_password_spray,
    s04_shadow_copy_delete,
    s05_scheduled_task_persistence,
    s06_cloud_exfil,
)
from scripts.gen.background import generate_background
from scripts.gen.intel import build_intel
from scripts.gen.safety import check_dataset
from scripts.gen.scenario import Claims, Context, ScenarioResult
from scripts.gen.world import build_world

# Order in which scenarios claim hosts and users. s03 sprays many accounts, so it goes
# last and takes whatever the workstation scenarios left unclaimed.
CLAIM_ORDER: list[ModuleType] = [
    s01_phishing_powershell,
    s02_lsass_dump,
    s04_shadow_copy_delete,
    s05_scheduled_task_persistence,
    s06_cloud_exfil,
    s03_password_spray,
]
VARIANTS = (1, 2, 3)


class UnsafeDatasetError(RuntimeError):
    pass


@dataclass
class Dataset:
    events: list[Event]
    hosts: list[Host]
    users: list[User]
    intel: list[IntelEntry]
    alerts: list[Alert]
    scenarios: list[ScenarioResult]

    def collections(self) -> dict[str, list[dict[str, Any]]]:
        """Rows per telemetry collection, as scripts/load.py inserts them."""
        return {
            "events": [e.model_dump() for e in self.events],
            "hosts": [h.model_dump() for h in self.hosts],
            "users": [u.model_dump() for u in self.users],
            "intel": [i.model_dump() for i in self.intel],
            "alerts": [a.model_dump() for a in self.alerts],
        }

    def truth(self, result: ScenarioResult, seed: int, variant: int) -> dict[str, Any]:
        return {
            "scenario": result.scenario_id,
            "title": result.title,
            "seed": seed,
            "variant": variant,
            "alert_id": result.alert.alert_id,
            "verdict": result.verdict,
            "expected_techniques": result.expected_techniques,
            "key_event_ids": [e.event_id for e in result.key_events],
        }


def build_dataset(seed: int, variant: int) -> Dataset:
    if variant not in VARIANTS:
        raise ValueError(f"variant must be one of {VARIANTS}")
    # Each stage gets its own string-seeded RNG, so adding events to one stage doesn't
    # shift the random stream of the others.
    world = build_world(random.Random(f"{seed}:world"))
    generate_background(world, random.Random(f"{seed}:background"))

    claims = Claims()
    results = []
    for module in CLAIM_ORDER:
        result = module.inject(Context(world, seed, variant, module.SCENARIO_ID, claims))
        claims.add(result)
        results.append(result)
    results.sort(key=lambda r: r.scenario_id)

    # IDs are assigned only now, in time order, so injected events are indistinguishable
    # from background ones by ID. `seq` breaks ties so parents precede children.
    drafts = sorted(world.drafts, key=lambda d: (d.ts, d.seq))
    for index, draft in enumerate(drafts, start=1):
        draft.event_id = f"evt_{index:06d}"
    events = [Event.model_validate(d.as_record()) for d in drafts]

    alerts = []
    for index, result in enumerate(sorted(results, key=lambda r: r.alert.ts), start=1):
        a = result.alert
        a.alert_id = f"alt_{index:04d}"
        alerts.append(
            Alert(
                alert_id=a.alert_id,
                ts=a.ts,
                rule=a.rule,
                severity=a.severity,
                host=a.host,
                user=a.user,
                description=a.description,
                trigger_event_ids=[t.event_id for t in a.triggers],
            )
        )

    intel = build_intel(results)
    problems = check_dataset(events, intel, results)
    if problems:
        raise UnsafeDatasetError("; ".join(problems[:10]))
    return Dataset(events, world.hosts, world.users, intel, alerts, results)
