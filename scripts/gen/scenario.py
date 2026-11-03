"""What a scenario module receives and returns. Each module in scenarios/ exposes
`SCENARIO_ID` and `inject(ctx) -> ScenarioResult`."""

import base64
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from scripts.gen.core import Draft, Session, World, day
from scripts.gen.infra import BAD_NETS


@dataclass
class AlertDraft:
    ts: datetime
    rule: str
    severity: Literal["low", "medium", "high", "critical"]
    host: str
    user: str | None
    description: str
    triggers: list[Draft]
    alert_id: str = ""


@dataclass
class Indicator:
    """Attacker infrastructure. `listed` ones appear in the threat-intel feed; the rest are
    deliberately unknown so the agent has to judge behaviour, not just reputation."""

    indicator: str
    type: Literal["ip", "domain", "hash"]
    listed: bool
    description: str


@dataclass
class ScenarioResult:
    scenario_id: str
    title: str
    verdict: Literal["malicious", "benign"]
    expected_techniques: list[str]
    events: list[Draft]
    key_events: list[Draft]
    alert: AlertDraft
    indicators: list[Indicator]

    def hosts(self) -> set[str]:
        return {e.host for e in self.events} | {self.alert.host}

    def users(self) -> set[str]:
        touched = {e.user for e in self.events} | {self.alert.user}
        return {u for u in touched if u is not None}


@dataclass
class Claims:
    """Hosts, users and bad IPs already used by earlier scenarios in this variant. Keeping
    them disjoint means no investigation stumbles on another scenario's evidence."""

    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    bad_ips: set[str] = field(default_factory=set)

    def add(self, result: ScenarioResult) -> None:
        self.hosts |= result.hosts()
        self.users |= result.users()
        self.bad_ips |= {i.indicator for i in result.indicators if i.type == "ip"}


class Context:
    def __init__(self, world: World, seed: int, variant: int, scenario_id: str, claims: Claims):
        self.world = world
        self.variant = variant
        self.claims = claims
        # String seeds go through SHA-512 in `random`, so they don't depend on PYTHONHASHSEED.
        self.rng = random.Random(f"{seed}:{variant}:{scenario_id}")
        self._mark = len(world.drafts)

    def emitted(self) -> list[Draft]:
        """Every event this scenario has added to the world so far."""
        return self.world.drafts[self._mark :]

    def pick_desk(self, departments: tuple[str, ...]) -> tuple[str, str]:
        """An unclaimed single-user workstation in one of `departments`, and its owner."""
        candidates = [
            hostname
            for hostname in sorted(self.world.desk_users)
            if len(self.world.desk_users[hostname]) == 1
            and self.world.host(hostname).department in departments
            and hostname not in self.claims.hosts
            and self.world.desk_users[hostname][0] not in self.claims.users
        ]
        hostname = self.rng.choice(candidates)
        return hostname, self.world.desk_users[hostname][0]

    def pick(self, options: list[str]) -> str:
        return self.rng.choice(sorted(o for o in options if o not in self.claims.hosts))

    def session(self, hostname: str, day_index: int) -> Session:
        return self.world.sessions[(hostname, day(day_index).date())]

    def bad_ip(self, net_index: int) -> str:
        # The first 150 addresses of each range are for scenarios; intel.py's decoys use the
        # top of the range, so the two never collide.
        hosts = [str(h) for h in list(BAD_NETS[net_index].hosts())[:150]]
        ip = self.rng.choice([h for h in hosts if h not in self.claims.bad_ips])
        self.claims.bad_ips.add(ip)
        return ip

    def token(self, k: int, alphabet: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789") -> str:
        return "".join(self.rng.choices(alphabet, k=k))


def encode_powershell(script: str) -> str:
    """What `powershell -EncodedCommand` expects: base64 of the UTF-16LE script."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")
