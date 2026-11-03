"""Building blocks shared by the background generator and the scenario modules.

Everything is emitted as a `Draft` first. Event IDs are assigned only after background and
scenario events are merged and sorted by time (see dataset.py), so an ID never reveals
whether an event was injected.
"""

import hashlib
import random
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from app.telemetry.models import Host, User

WEEK_START = datetime(2026, 10, 5, tzinfo=UTC)  # a Monday
DAYS = 7
SYSTEM = "SYSTEM"

MS_WINDOWS = "Microsoft Windows"
MS_CORP = "Microsoft Corporation"

# Image path and Authenticode signer of every benign binary the generator uses.
BINARIES: dict[str, tuple[str, str]] = {
    "winlogon.exe": (r"C:\Windows\System32\winlogon.exe", MS_WINDOWS),
    "services.exe": (r"C:\Windows\System32\services.exe", MS_WINDOWS),
    "lsass.exe": (r"C:\Windows\System32\lsass.exe", MS_WINDOWS),
    "svchost.exe": (r"C:\Windows\System32\svchost.exe", MS_WINDOWS),
    "userinit.exe": (r"C:\Windows\System32\userinit.exe", MS_WINDOWS),
    "explorer.exe": (r"C:\Windows\explorer.exe", MS_WINDOWS),
    "taskhostw.exe": (r"C:\Windows\System32\taskhostw.exe", MS_WINDOWS),
    "CompatTelRunner.exe": (r"C:\Windows\System32\CompatTelRunner.exe", MS_WINDOWS),
    "MoUsoCoreWorker.exe": (r"C:\Windows\System32\MoUsoCoreWorker.exe", MS_WINDOWS),
    "TiWorker.exe": (r"C:\Windows\WinSxS\amd64_tiworker\TiWorker.exe", MS_WINDOWS),
    "cmd.exe": (r"C:\Windows\System32\cmd.exe", MS_WINDOWS),
    "powershell.exe": (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", MS_WINDOWS),
    "rundll32.exe": (r"C:\Windows\System32\rundll32.exe", MS_WINDOWS),
    "tasklist.exe": (r"C:\Windows\System32\tasklist.exe", MS_WINDOWS),
    "schtasks.exe": (r"C:\Windows\System32\schtasks.exe", MS_WINDOWS),
    "vssadmin.exe": (r"C:\Windows\System32\vssadmin.exe", MS_WINDOWS),
    "wmic.exe": (r"C:\Windows\System32\wbem\WMIC.exe", MS_WINDOWS),
    "bcdedit.exe": (r"C:\Windows\System32\bcdedit.exe", MS_WINDOWS),
    "wbadmin.exe": (r"C:\Windows\System32\wbadmin.exe", MS_WINDOWS),
    "mstsc.exe": (r"C:\Windows\System32\mstsc.exe", MS_WINDOWS),
    "mmc.exe": (r"C:\Windows\System32\mmc.exe", MS_WINDOWS),
    "notepad.exe": (r"C:\Windows\System32\notepad.exe", MS_WINDOWS),
    "SnippingTool.exe": (r"C:\Windows\System32\SnippingTool.exe", MS_WINDOWS),
    "ServerManager.exe": (r"C:\Windows\System32\ServerManager.exe", MS_WINDOWS),
    "w3wp.exe": (r"C:\Windows\System32\inetsrv\w3wp.exe", MS_WINDOWS),
    "MsMpEng.exe": (r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe", MS_WINDOWS),
    "MpCmdRun.exe": (
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
        MS_WINDOWS,
    ),
    "OUTLOOK.EXE": (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", MS_CORP),
    "WINWORD.EXE": (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", MS_CORP),
    "EXCEL.EXE": (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", MS_CORP),
    "POWERPNT.EXE": (r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE", MS_CORP),
    "OfficeClickToRun.exe": (
        r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe",
        MS_CORP,
    ),
    "ms-teams.exe": (r"C:\Program Files\WindowsApps\MSTeams_x64\ms-teams.exe", MS_CORP),
    "OneDrive.exe": (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", MS_CORP),
    "OneDriveSetup.exe": (r"C:\Program Files\Microsoft OneDrive\OneDriveSetup.exe", MS_CORP),
    "msedge.exe": (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", MS_CORP),
    "Code.exe": (r"C:\Program Files\Microsoft VS Code\Code.exe", MS_CORP),
    "sqlservr.exe": (
        r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
        MS_CORP,
    ),
    "Ssms.exe": (
        r"C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\Ssms.exe",
        MS_CORP,
    ),
    "chrome.exe": (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google LLC"),
    "updater.exe": (r"C:\Program Files (x86)\Google\GoogleUpdater\updater.exe", "Google LLC"),
    "git.exe": (r"C:\Program Files\Git\cmd\git.exe", "Johannes Schindelin"),
    "python.exe": (r"C:\Program Files\Python312\python.exe", "Python Software Foundation"),
    "Acrobat.exe": (r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "Adobe Inc."),
    "BackupAgent.exe": (r"C:\Program Files\Vaultline\Backup\BackupAgent.exe", "Vaultline Ltd"),
}


def image(name: str) -> str:
    return BINARIES[name][0]


def fake_sha256(*parts: object) -> str:
    """Stable fake file hash: the same binary always hashes the same across runs."""
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()


def benign_sha256(name: str) -> str:
    return fake_sha256("benign-binary", name)


def outlook_cache(user: str) -> str:
    """Where Outlook saves attachments it opens."""
    return rf"C:\Users\{user}\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook"


@dataclass
class Draft:
    """An event before it has an ID. `seq` is creation order, the tie-break for equal ts."""

    seq: int
    ts: datetime
    host: str
    user: str | None
    event_type: str
    payload: dict[str, dict[str, Any]]
    event_id: str = ""

    def as_record(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "ts": self.ts,
            "host": self.host,
            "user": self.user,
            "event_type": self.event_type,
            **self.payload,
        }


@dataclass
class Proc:
    pid: int
    name: str
    host: str
    event: Draft | None = None  # the process_start, if it happened during the week

    def ref(self) -> dict[str, Any]:
        return {"pid": self.pid, "name": self.name}

    def started(self) -> Draft:
        if self.event is None:
            raise ValueError(f"{self.name} ({self.pid}) was running before the week began")
        return self.event


@dataclass
class Session:
    """A user's interactive day on a workstation; scenarios hook into its processes."""

    host: str
    user: str
    start: datetime
    end: datetime
    procs: dict[str, Proc] = field(default_factory=dict)


@dataclass
class World:
    hosts: list[Host]
    users: list[User]
    desk_users: dict[str, list[str]]  # workstation -> assigned users, owner first
    browsers: dict[str, str]  # user -> chrome.exe | msedge.exe
    home_ips: dict[str, str]  # user -> home broadband IP used for VPN
    system: dict[str, dict[str, Proc]] = field(default_factory=dict)
    sessions: dict[tuple[str, date], Session] = field(default_factory=dict)
    drafts: list[Draft] = field(default_factory=list)
    used_pids: dict[str, set[int]] = field(default_factory=dict)

    def host(self, name: str) -> Host:
        return next(h for h in self.hosts if h.hostname == name)

    def user(self, name: str) -> User:
        return next(u for u in self.users if u.username == name)

    def new_pid(self, host: str, rng: random.Random) -> int:
        # Random (not increasing) PIDs, unique per host for the week, so a PID never hints
        # at when or by which part of the generator a process was created.
        used = self.used_pids.setdefault(host, set())
        while True:
            pid = rng.randrange(1000, 40000, 4)
            if pid not in used:
                used.add(pid)
                return pid

    def emit(
        self, ts: datetime, host: str, user: str | None, event_type: str, **payload: Any
    ) -> Draft:
        draft = Draft(len(self.drafts), ts.replace(microsecond=0), host, user, event_type, payload)
        self.drafts.append(draft)
        return draft

    def start(
        self,
        ts: datetime,
        host: str,
        user: str | None,
        name: str,
        parent: Proc,
        rng: random.Random,
        args: str = "",
        *,
        path: str | None = None,
        sha256: str | None = None,
        signer: str | None = None,
    ) -> Proc:
        """Start a process. Binaries outside BINARIES must pass path and sha256 (unsigned)."""
        if path is None:
            path, signer = BINARIES[name]
        cmdline = f'"{path}"' + (f" {args}" if args else "")
        proc = Proc(self.new_pid(host, rng), name, host)
        proc.event = self.emit(
            ts,
            host,
            user,
            "process_start",
            process={
                "pid": proc.pid,
                "name": name,
                "ppid": parent.pid,
                "parent_name": parent.name,
                "cmdline": cmdline,
                "sha256": sha256 or benign_sha256(name),
                "signer": signer,
            },
        )
        return proc

    def connect(
        self,
        ts: datetime,
        proc: Proc,
        user: str | None,
        dst_ip: str,
        dst_port: int,
        bytes_out: int,
        bytes_in: int,
        protocol: str = "tcp",
    ) -> Draft:
        network = {
            "src_ip": self.host(proc.host).ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "direction": "outbound",
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
        }
        return self.emit(ts, proc.host, user, "network_conn", process=proc.ref(), network=network)

    def dns(self, ts: datetime, proc: Proc, user: str | None, query: str, answer: str) -> Draft:
        dns = {"query": query, "record_type": "A", "answers": [answer]}
        return self.emit(ts, proc.host, user, "dns_query", process=proc.ref(), dns=dns)

    def write_file(
        self,
        ts: datetime,
        proc: Proc,
        user: str | None,
        path: str,
        size: int,
        action: str = "create",
        sha256: str | None = None,
    ) -> Draft:
        file = {"path": path, "action": action, "size": size, "sha256": sha256}
        return self.emit(ts, proc.host, user, "file_write", process=proc.ref(), file=file)

    def logon(
        self,
        ts: datetime,
        host: str,
        user: str,
        logon_type: str,
        src_ip: str | None,
        country: str | None = None,
        *,
        result: str = "success",
        mfa: bool = False,
        failure_reason: str | None = None,
    ) -> Draft:
        logon = {
            "logon_type": logon_type,
            "src_ip": src_ip,
            "country": country,
            "result": result,
            "mfa": mfa,
            "failure_reason": failure_reason,
        }
        return self.emit(ts, host, user, "logon", logon=logon)

    def create_task(
        self, ts: datetime, proc: Proc, user: str, name: str, command: str, trigger: str
    ) -> Draft:
        task = {
            "task_name": name,
            "action": "create",
            "command": command,
            "trigger": trigger,
            "run_as": user,
        }
        return self.emit(ts, proc.host, user, "scheduled_task", process=proc.ref(), task=task)

    def open_process(
        self, ts: datetime, proc: Proc, user: str | None, target: Proc, granted_access: str
    ) -> Draft:
        access = {
            "target_name": target.name,
            "target_pid": target.pid,
            "granted_access": granted_access,
        }
        return self.emit(ts, proc.host, user, "lsass_access", process=proc.ref(), access=access)


def day(index: int) -> datetime:
    return WEEK_START + timedelta(days=index)


def at(day_index: int, hour: int, minute: int = 0, second: int = 0) -> datetime:
    return day(day_index) + timedelta(hours=hour, minutes=minute, seconds=second)


def secs(n: float) -> timedelta:
    return timedelta(seconds=n)


def between(rng: random.Random, start: datetime, end: datetime) -> datetime:
    return start + secs(rng.randrange(int((end - start).total_seconds())))
