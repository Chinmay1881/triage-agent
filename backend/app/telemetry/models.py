"""Shapes of the synthetic telemetry. The generator validates every row against these models
before writing, and the tools will read them back the same way.

None of these models has a ground-truth field (verdict, scenario, technique). Truth lives only
in the scenario truth files, which nothing outside evals/ reads.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

EventType = Literal[
    "process_start",
    "network_conn",
    "dns_query",
    "logon",
    "file_write",
    "scheduled_task",
    "lsass_access",
]


def _require_utc(ts: datetime) -> datetime:
    if ts.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be timezone-aware UTC")
    return ts.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_require_utc)]


class _Strict(BaseModel):
    # Unknown keys are an error, so a stray ground-truth field can't slip into telemetry.
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessInfo(_Strict):
    """The process that did the thing. For process_start it is the new process, so the
    parent and command line are required there; other event types carry just pid and name."""

    pid: int = Field(ge=0)
    name: str
    ppid: int | None = Field(default=None, ge=0)
    parent_name: str | None = None
    cmdline: str | None = None
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signer: str | None = None


class NetworkInfo(_Strict):
    src_ip: str
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp"]
    direction: Literal["outbound", "inbound"]
    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)


class DnsInfo(_Strict):
    query: str
    record_type: Literal["A", "AAAA", "CNAME", "TXT"] = "A"
    answers: list[str]


class LogonInfo(_Strict):
    logon_type: Literal["interactive", "remote_interactive", "network", "vpn"]
    # None for local console logons, which have no source address or geolocation.
    src_ip: str | None
    country: str | None = Field(pattern=r"^[A-Z]{2}$")
    result: Literal["success", "failure"]
    mfa: bool
    failure_reason: Literal["bad_password", "unknown_user", "mfa_denied"] | None = None

    @model_validator(mode="after")
    def _reason_only_on_failure(self) -> Self:
        if (self.result == "failure") != (self.failure_reason is not None):
            raise ValueError("failure_reason is required on failures and only on failures")
        return self


class FileInfo(_Strict):
    path: str
    action: Literal["create", "modify", "delete"]
    size: int = Field(ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class TaskInfo(_Strict):
    task_name: str
    action: Literal["create", "modify", "delete"]
    command: str
    trigger: str
    run_as: str


class AccessInfo(_Strict):
    """Handle opened on another process (used for LSASS reads)."""

    target_name: str
    target_pid: int = Field(ge=0)
    granted_access: str = Field(pattern=r"^0x[0-9a-f]+$")


# Which payload fields each event type must carry; every other payload must be null.
PAYLOADS: dict[str, frozenset[str]] = {
    "process_start": frozenset({"process"}),
    "network_conn": frozenset({"process", "network"}),
    "dns_query": frozenset({"process", "dns"}),
    "logon": frozenset({"logon"}),
    "file_write": frozenset({"process", "file"}),
    "scheduled_task": frozenset({"process", "task"}),
    "lsass_access": frozenset({"process", "access"}),
}
PAYLOAD_FIELDS = ("process", "network", "dns", "logon", "file", "task", "access")


class Event(_Strict):
    event_id: str = Field(pattern=r"^evt_\d{6}$")
    ts: UtcDatetime
    host: str
    user: str | None
    event_type: EventType
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    dns: DnsInfo | None = None
    logon: LogonInfo | None = None
    file: FileInfo | None = None
    task: TaskInfo | None = None
    access: AccessInfo | None = None

    @model_validator(mode="after")
    def _payload_matches_type(self) -> Self:
        expected = PAYLOADS[self.event_type]
        present = {f for f in PAYLOAD_FIELDS if getattr(self, f) is not None}
        if present != expected:
            raise ValueError(
                f"{self.event_type} needs exactly {sorted(expected)}, got {sorted(present)}"
            )
        if self.event_type == "process_start":
            p = self.process
            if p is not None and None in (p.ppid, p.parent_name, p.cmdline, p.sha256):
                raise ValueError("process_start needs ppid, parent_name, cmdline and sha256")
        return self


HostRole = Literal[
    "workstation",
    "domain_controller",
    "file_server",
    "database_server",
    "web_server",
    "backup_server",
    "vpn_gateway",
]


class Host(_Strict):
    hostname: str
    role: HostRole
    department: str
    owner: str
    os: str
    ip: str
    criticality: int = Field(ge=1, le=5)


class User(_Strict):
    username: str
    display_name: str
    department: str
    title: str
    is_admin: bool
    is_service_account: bool
    usual_countries: list[str]


class IntelEntry(_Strict):
    indicator: str
    type: Literal["ip", "domain", "hash"]
    reputation: Literal["known_bad", "known_good"]
    source: str
    description: str


class Alert(_Strict):
    alert_id: str = Field(pattern=r"^alt_\d{4}$")
    ts: UtcDatetime
    rule: str
    severity: Literal["low", "medium", "high", "critical"]
    host: str
    user: str | None
    description: str
    trigger_event_ids: list[str] = Field(min_length=1)
