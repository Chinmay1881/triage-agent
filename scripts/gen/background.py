"""One week of normal activity. It deliberately includes the benign look-alikes of the
scenarios (Outlook opening attachments in Office, admin PowerShell and RDP, Defender touching
LSASS, updaters creating scheduled tasks, big OneDrive uploads, backup jobs running vssadmin)
so an alert can't be judged on process names alone."""

import random
from collections.abc import Callable
from datetime import datetime

from scripts.gen.core import (
    DAYS,
    SYSTEM,
    Proc,
    Session,
    World,
    at,
    between,
    day,
    outlook_cache,
    secs,
)
from scripts.gen.infra import BENIGN_DOMAINS, INTERNAL_DOMAIN, TENANT

INTRANET = f"intranet.{INTERNAL_DOMAIN}"
SHAREPOINT = f"{TENANT}.sharepoint.com"
ONEDRIVE = f"{TENANT}-my.sharepoint.com"
VPN_POOL = "10.8.0"

COMMON_SITES = ["www.google.com", "www.bbc.co.uk", "www.office.com", SHAREPOINT, INTRANET]
DEPT_SITES: dict[str, list[str]] = {
    "Finance": ["go.xero.com", "www.hmrc.gov.uk"],
    "HR": ["www.linkedin.com", "www.gov.uk"],
    "Engineering": ["github.com", "stackoverflow.com", "docs.python.org", "pypi.org"],
    "Sales": ["login.salesforce.com", "app.hubspot.com", "www.linkedin.com", "zoom.us"],
    "IT": ["stackoverflow.com", "github.com", "login.microsoftonline.com"],
    "Executive": ["www.linkedin.com", "zoom.us"],
}
DOC_APPS: dict[str, list[tuple[str, str]]] = {
    "Finance": [("EXCEL.EXE", "xlsx"), ("EXCEL.EXE", "xlsx"), ("WINWORD.EXE", "docx")],
    "Sales": [("POWERPNT.EXE", "pptx"), ("WINWORD.EXE", "docx"), ("EXCEL.EXE", "xlsx")],
    "Executive": [("POWERPNT.EXE", "pptx"), ("WINWORD.EXE", "docx"), ("EXCEL.EXE", "xlsx")],
}
DEFAULT_DOC_APPS = [("WINWORD.EXE", "docx"), ("EXCEL.EXE", "xlsx")]
DOC_NAMES = [
    "Q3 forecast", "Budget 2027 draft", "Team rota", "Meeting notes", "Supplier list",
    "Project plan", "Board update", "Expenses October", "Pipeline review", "Onboarding checklist",
]  # fmt: skip
ATTACHMENTS = [
    ("Acrobat.exe", "Remittance advice.pdf"),
    ("Acrobat.exe", "Signed contract.pdf"),
    ("EXCEL.EXE", "Timesheet week 41.xlsx"),
    ("WINWORD.EXE", "Policy update v2.docx"),
]
ADMIN_COMMANDS = [
    "Get-ADUser -Filter 'Enabled -eq $false' | Select-Object Name, LastLogonDate",
    "Get-Service -ComputerName FS-01 | Where-Object Status -eq 'Stopped'",
    "Test-NetConnection SQL-01 -Port 1433",
    "Get-WinEvent -ComputerName DC-01 -LogName Security -MaxEvents 50",
    "Get-ADGroupMember 'Finance-RW' | Select-Object SamAccountName",
    "Invoke-Command -ComputerName WEB-01 { Get-WebAppPoolState -Name Intranet }",
]
RDP_TARGETS = ["FS-01", "SQL-01", "WEB-01", "BKP-01", "DC-01"]
GIT_ARGS = ["fetch origin", "pull --rebase", "push origin HEAD", "status"]


def resolve(domain: str, world: World) -> str:
    if domain == INTRANET:
        return world.host("WEB-01").ip
    return BENIGN_DOMAINS[domain]


def saas(
    world: World,
    rng: random.Random,
    proc: Proc,
    user: str,
    domain: str,
    ts: datetime,
    bytes_out: int,
    bytes_in: int,
    port: int = 443,
) -> None:
    # Windows caches lookups, so not every connection is preceded by a DNS query.
    ip = resolve(domain, world)
    if rng.random() < 0.6:
        world.dns(ts, proc, user, domain, ip)
    world.connect(ts + secs(1), proc, user, ip, port, bytes_out, bytes_in)


def generate_background(world: World, rng: random.Random) -> None:
    desks = sorted(world.desk_users)
    windows_hosts = sorted(h for h in world.system)
    for d in range(DAYS):
        if day(d).weekday() < 5:
            for hostname in desks:
                assigned = world.desk_users[hostname]
                at_desk = rng.choice(assigned)
                workday(world, rng, hostname, at_desk, d)
                for other in assigned:
                    if other != at_desk:
                        remote_day(world, rng, other, d)
        evening_vpn(world, rng, d)
        for hostname in windows_hosts:
            system_day(world, rng, hostname, d)
        backup_night(world, rng, d)
        sql_night(world, rng, d)
        web_day(world, rng, d)


def workday(world: World, rng: random.Random, hostname: str, user: str, d: int) -> None:
    host = world.host(hostname)
    boot = world.system[hostname]
    start = at(d, 7, 30) + secs(rng.randrange(6000))
    end = at(d, 16, 30) + secs(rng.randrange(7200))
    session = Session(hostname, user, start, end)
    world.sessions[(hostname, day(d).date())] = session

    if rng.random() < 0.06:
        world.logon(
            start - secs(rng.randint(5, 20)),
            hostname,
            user,
            "interactive",
            None,
            result="failure",
            failure_reason="bad_password",
        )
    world.logon(start, hostname, user, "interactive", None)
    world.logon(start + secs(1), "DC-01", user, "network", host.ip)
    userinit = world.start(
        start + secs(2), hostname, user, "userinit.exe", boot["winlogon.exe"], rng
    )
    explorer = world.start(start + secs(4), hostname, user, "explorer.exe", userinit, rng)
    session.procs["explorer.exe"] = explorer
    browser = world.browsers[user]
    startup = [
        (25, "OneDrive.exe", "/background"),
        (31, "ms-teams.exe", "--system-initiated"),
        (48, "OUTLOOK.EXE", ""),
        (70, browser, ""),
    ]
    for offset, name, args in startup:
        session.procs[name] = world.start(
            start + secs(offset), hostname, user, name, explorer, rng, args
        )
    saas(
        world,
        rng,
        session.procs["OUTLOOK.EXE"],
        user,
        "outlook.office365.com",
        start + secs(52),
        rng.randint(4_000, 20_000),
        rng.randint(200_000, 3_000_000),
    )
    saas(
        world,
        rng,
        session.procs["ms-teams.exe"],
        user,
        "teams.microsoft.com",
        start + secs(35),
        rng.randint(3_000, 9_000),
        rng.randint(50_000, 400_000),
    )
    # Mapped drives: SMB from the kernel to the file server, which logs a network logon.
    fs = world.host("FS-01")
    world.connect(start + secs(40), boot["System"], user, fs.ip, 445, 4_000, 12_000)
    world.logon(start + secs(40), "FS-01", user, "network", host.ip)

    actions = activities(host.department)
    cursor = start + secs(rng.randint(300, 900))
    while cursor < end - secs(300):
        action = rng.choices([a for a, _ in actions], weights=[w for _, w in actions])[0]
        action(world, rng, session, cursor)
        cursor += secs(rng.randint(240, 900))

    if rng.random() < 0.05:
        onedrive_update_task(world, rng, session)
    if browser == "chrome.exe" and rng.random() < 0.04:
        chrome_update_task(world, rng, session)


Activity = Callable[[World, random.Random, Session, datetime], None]


def activities(department: str) -> list[tuple[Activity, int]]:
    common: list[tuple[Activity, int]] = [
        (browse, 10),
        (office_doc, 5),
        (email_attachment, 1),
        (download, 1),
        (teams_sync, 4),
        (onedrive_sync, 2),
        (large_onedrive_upload, 0),
    ]
    if department == "Engineering":
        common += [(dev_work, 6)]
    if department == "IT":
        common += [(admin_powershell, 3), (admin_rdp, 1), (admin_console, 1)]
    if department in ("Sales", "Executive"):
        common = [(a, 1 if a is large_onedrive_upload else w) for a, w in common]
    return common


def browse(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    browser = s.procs[world.browsers[s.user]]
    site = rng.choice(COMMON_SITES + DEPT_SITES[world.host(s.host).department])
    if rng.random() < 0.4:
        args = f"--type=renderer --lang=en-GB --renderer-client-id={rng.randint(5, 400)}"
        world.start(t, s.host, s.user, browser.name, browser, rng, args)
    saas(
        world,
        rng,
        browser,
        s.user,
        site,
        t + secs(1),
        rng.randint(2_000, 30_000),
        rng.randint(20_000, 2_500_000),
    )


def office_doc(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    app, ext = rng.choice(DOC_APPS.get(world.host(s.host).department, DEFAULT_DOC_APPS))
    path = rf"C:\Users\{s.user}\OneDrive - Contoso\Documents\{rng.choice(DOC_NAMES)}.{ext}"
    args = f'/n "{path}"' if app == "WINWORD.EXE" else f'"{path}"'
    proc = world.start(t, s.host, s.user, app, s.procs["explorer.exe"], rng, args)
    saved = t + secs(rng.randint(300, 1800))
    if saved < s.end:
        size = rng.randint(30_000, 900_000)
        world.write_file(saved, proc, s.user, path, size, action="modify")
        saas(
            world,
            rng,
            s.procs["OneDrive.exe"],
            s.user,
            ONEDRIVE,
            saved + secs(5),
            size + rng.randint(1_000, 5_000),
            rng.randint(2_000, 8_000),
        )


def email_attachment(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    # Outlook spawning Office/Acrobat is everyday behaviour; s01 differs in what comes next.
    app, filename = rng.choice(ATTACHMENTS)
    folder = "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=8))
    path = rf"{outlook_cache(s.user)}\{folder}\{filename}"
    outlook = s.procs["OUTLOOK.EXE"]
    world.write_file(t, outlook, s.user, path, rng.randint(40_000, 600_000))
    args = f'/n "{path}"' if app == "WINWORD.EXE" else f'"{path}"'
    world.start(t + secs(rng.randint(3, 40)), s.host, s.user, app, outlook, rng, args)


def download(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    browser = s.procs[world.browsers[s.user]]
    site = rng.choice(["www.gov.uk", "acrobat.adobe.com", SHAREPOINT, "www.hmrc.gov.uk"])
    size = rng.randint(100_000, 4_000_000)
    saas(world, rng, browser, s.user, site, t, rng.randint(2_000, 8_000), size)
    name = rng.choice(["guidance", "statement", "brochure", "invoice-copy", "handbook"])
    path = rf"C:\Users\{s.user}\Downloads\{name}-{rng.randint(100, 999)}.pdf"
    world.write_file(t + secs(rng.randint(2, 20)), browser, s.user, path, size)


def teams_sync(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    saas(
        world,
        rng,
        s.procs["ms-teams.exe"],
        s.user,
        "teams.microsoft.com",
        t,
        rng.randint(2_000, 40_000),
        rng.randint(10_000, 600_000),
    )


def onedrive_sync(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    saas(
        world,
        rng,
        s.procs["OneDrive.exe"],
        s.user,
        ONEDRIVE,
        t,
        rng.randint(5_000, 3_000_000),
        rng.randint(2_000, 200_000),
    )


def large_onedrive_upload(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    # Benign counterpart to s06: hundreds of MB to the company's own SharePoint tenant.
    onedrive = s.procs["OneDrive.exe"]
    ip = resolve(ONEDRIVE, world)
    for i in range(rng.randint(2, 4)):
        world.connect(
            t + secs(i * rng.randint(60, 240)),
            onedrive,
            s.user,
            ip,
            443,
            rng.randint(80_000_000, 350_000_000),
            rng.randint(50_000, 300_000),
        )


def dev_work(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    code = s.procs.get("Code.exe")
    if code is None:
        code = world.start(t, s.host, s.user, "Code.exe", s.procs["explorer.exe"], rng)
        s.procs["Code.exe"] = code
    t += secs(rng.randint(5, 60))
    if rng.random() < 0.6:
        git = world.start(t, s.host, s.user, "git.exe", code, rng, rng.choice(GIT_ARGS))
        saas(
            world,
            rng,
            git,
            s.user,
            "github.com",
            t + secs(1),
            rng.randint(2_000, 200_000),
            rng.randint(5_000, 2_000_000),
        )
    else:
        args = rng.choice(
            ["-m pytest -q", "-m pip install -r requirements.txt", "manage.py runserver"]
        )
        python = world.start(t, s.host, s.user, "python.exe", code, rng, args)
        if "pip" in args:
            saas(
                world,
                rng,
                python,
                s.user,
                "files.pythonhosted.org",
                t + secs(2),
                rng.randint(2_000, 20_000),
                rng.randint(500_000, 30_000_000),
            )


def admin_powershell(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    command = rng.choice(ADMIN_COMMANDS)
    args = f'-NoProfile -Command "{command}"' if rng.random() < 0.5 else ""
    world.start(t, s.host, s.user, "powershell.exe", s.procs["explorer.exe"], rng, args)


def admin_console(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    snapin = rng.choice(["dsa.msc", "gpmc.msc", "dnsmgmt.msc", "compmgmt.msc"])
    args = rf"C:\Windows\system32\{snapin}"
    world.start(t, s.host, s.user, "mmc.exe", s.procs["explorer.exe"], rng, args)


def admin_rdp(world: World, rng: random.Random, s: Session, t: datetime) -> None:
    # Benign counterpart to s04: admins RDP to servers every day.
    target = rng.choice(RDP_TARGETS)
    server = world.host(target)
    mstsc = world.start(
        t, s.host, s.user, "mstsc.exe", s.procs["explorer.exe"], rng, f"/v:{target}"
    )
    world.connect(
        t + secs(2),
        mstsc,
        s.user,
        server.ip,
        3389,
        rng.randint(200_000, 3_000_000),
        rng.randint(2_000_000, 40_000_000),
    )
    rdp_session(world, rng, target, s.user, world.host(s.host).ip, t + secs(4))


def rdp_session(
    world: World, rng: random.Random, target: str, user: str, src_ip: str, t: datetime
) -> Proc:
    world.logon(t, target, user, "remote_interactive", src_ip)
    boot = world.system[target]
    userinit = world.start(t + secs(2), target, user, "userinit.exe", boot["winlogon.exe"], rng)
    explorer = world.start(t + secs(4), target, user, "explorer.exe", userinit, rng)
    tool = "Ssms.exe" if target == "SQL-01" else rng.choice(["ServerManager.exe", "powershell.exe"])
    args = (
        '-NoProfile -Command "Get-EventLog -LogName System -Newest 50"'
        if tool == "powershell.exe"
        else ""
    )
    world.start(t + secs(rng.randint(20, 90)), target, user, tool, explorer, rng, args)
    return explorer


def onedrive_update_task(world: World, rng: random.Random, s: Session) -> None:
    t = between(rng, s.start + secs(600), s.end - secs(600))
    setup = world.start(
        t, s.host, s.user, "OneDriveSetup.exe", s.procs["OneDrive.exe"], rng, "/update /restart"
    )
    task = rf"\OneDrive Standalone Update Task-S-1-5-21-{rng.randint(10**9, 4 * 10**9)}-1001"
    command = rf"C:\Users\{s.user}\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"
    world.create_task(t + secs(3), setup, s.user, task, command, "Daily at 14:00")


def chrome_update_task(world: World, rng: random.Random, s: Session) -> None:
    t = between(rng, s.start + secs(600), s.end - secs(600))
    schedule = world.system[s.host]["svchost_schedule"]
    updater = world.start(t, s.host, SYSTEM, "updater.exe", schedule, rng, "--wake --system")
    saas(world, rng, updater, SYSTEM, "update.googleapis.com", t + secs(2), 3_000, 90_000)
    version = "141.0.7340.0"
    task = rf"\GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem{version}"
    command = (
        rf'"C:\Program Files (x86)\Google\GoogleUpdater\{version}\updater.exe" --wake --system'
    )
    world.create_task(t + secs(9), updater, SYSTEM, task, command, "Daily at 09:47")


def remote_day(world: World, rng: random.Random, user: str, d: int) -> None:
    t = at(d, 8) + secs(rng.randrange(5400))
    home = world.home_ips[user]
    if rng.random() < 0.08:
        world.logon(
            t - secs(rng.randint(10, 60)),
            "VPN-01",
            user,
            "vpn",
            home,
            "GB",
            result="failure",
            failure_reason="bad_password",
        )
    world.logon(t, "VPN-01", user, "vpn", home, "GB", mfa=True)
    pool_ip = f"{VPN_POOL}.{10 + rng.randrange(200)}"
    world.logon(t + secs(3), "DC-01", user, "network", pool_ip)
    if rng.random() < 0.4:
        world.logon(t + secs(rng.randint(60, 600)), "FS-01", user, "network", pool_ip)
    if rng.random() < 0.3:
        world.logon(
            at(d, 13) + secs(rng.randrange(3600)), "VPN-01", user, "vpn", home, "GB", mfa=True
        )


def evening_vpn(world: World, rng: random.Random, d: int) -> None:
    people = sorted(u.username for u in world.users if not u.is_service_account)
    for user in rng.sample(people, k=rng.randint(1, 4)):
        t = at(d, 19) + secs(rng.randrange(3 * 3600))
        world.logon(t, "VPN-01", user, "vpn", world.home_ips[user], "GB", mfa=True)


def system_day(world: World, rng: random.Random, hostname: str, d: int) -> None:
    boot = world.system[hostname]
    defender = boot["MsMpEng.exe"]
    # Defender opens LSASS for its scans with limited rights; s02's dumper asks for 0x1fffff.
    world.open_process(
        between(rng, at(d, 0), at(d, 23)), defender, SYSTEM, boot["lsass.exe"], "0x1010"
    )
    for _ in range(2):
        t = between(rng, at(d, 0), at(d, 23))
        updater = world.start(
            t, hostname, SYSTEM, "MpCmdRun.exe", defender, rng, "-SignatureUpdate -MMPC"
        )
        saas(
            world,
            rng,
            updater,
            SYSTEM,
            "definitionupdates.microsoft.com",
            t + secs(2),
            4_000,
            rng.randint(200_000, 9_000_000),
        )
    for _ in range(rng.randint(2, 4)):
        t = between(rng, at(d, 0), at(d, 23, 30))
        world.start(t, hostname, SYSTEM, "taskhostw.exe", boot["svchost_schedule"], rng)
    if rng.random() < 0.5:
        t = between(rng, at(d, 0), at(d, 23))
        telemetry = world.start(
            t,
            hostname,
            SYSTEM,
            "CompatTelRunner.exe",
            boot["svchost_schedule"],
            rng,
            "-m:appraiser.dll -f:DoScheduledTelemetryRun",
        )
        saas(
            world,
            rng,
            telemetry,
            SYSTEM,
            "settings-win.data.microsoft.com",
            t + secs(4),
            rng.randint(20_000, 400_000),
            6_000,
        )
    t = between(rng, at(d, 3), at(d, 5))
    uso = world.start(t, hostname, SYSTEM, "MoUsoCoreWorker.exe", boot["svchost_wuauserv"], rng)
    saas(
        world,
        rng,
        uso,
        SYSTEM,
        "fe3cr.delivery.mp.microsoft.com",
        t + secs(3),
        12_000,
        rng.randint(100_000, 60_000_000),
    )
    if rng.random() < 0.2:
        world.start(
            t + secs(600), hostname, SYSTEM, "TiWorker.exe", boot["svchost_dcom"], rng, "-Embedding"
        )


def backup_night(world: World, rng: random.Random, d: int) -> None:
    # The nightly job lists (never deletes) shadow copies: the benign side of s04.
    bkp = world.host("BKP-01")
    agent = world.system["BKP-01"]["BackupAgent.exe"]
    t = at(d, 1) + secs(rng.randrange(600))
    world.start(t, "BKP-01", "svc_backup", "vssadmin.exe", agent, rng, "list shadows")
    for offset, target, size in [(60, "FS-01", 40_000_000_000), (5400, "SQL-01", 4_000_000_000)]:
        server = world.host(target)
        world.logon(t + secs(offset), target, "svc_backup", "network", bkp.ip)
        world.connect(
            t + secs(offset + 2),
            agent,
            "svc_backup",
            server.ip,
            445,
            rng.randint(2_000_000, 9_000_000),
            int(size * rng.uniform(0.02, 0.06)),
        )


def sql_night(world: World, rng: random.Random, d: int) -> None:
    sql = world.system["SQL-01"]["sqlservr.exe"]
    t = at(d, 2) + secs(rng.randrange(900))
    stamp = day(d).strftime("%Y%m%d")
    path = rf"D:\SQLBackups\FinanceDB_{stamp}.bak"
    world.write_file(t, sql, "svc_sql", path, rng.randint(3_200_000_000, 3_600_000_000))


def web_day(world: World, rng: random.Random, d: int) -> None:
    netsvcs = world.system["WEB-01"]["svchost_netsvcs"]
    t = at(d, 6) + secs(rng.randrange(1800))
    world.start(t, "WEB-01", "svc_iis", "w3wp.exe", netsvcs, rng, '-ap "Intranet" -v "v4.0"')
