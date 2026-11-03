"""The fake company: 25 hosts and 40 accounts (34 people, 6 service accounts)."""

import random

from app.telemetry.models import Host, User
from scripts.gen.core import Proc, World
from scripts.gen.infra import HOME_NET

WORKSTATION_OS = "Windows 11 Enterprise 23H2"
SERVER_OS = "Windows Server 2022 Standard"

# hostname, department, number of assigned people. Shared desks are hot-desked: whoever
# isn't at the desk that day works from home over the VPN.
DESKS: list[tuple[str, str, int]] = [
    ("FIN-WS-01", "Finance", 1),
    ("FIN-WS-02", "Finance", 1),
    ("FIN-WS-03", "Finance", 2),
    ("FIN-WS-04", "Finance", 3),
    ("HR-WS-01", "HR", 1),
    ("HR-WS-02", "HR", 2),
    ("ENG-WS-01", "Engineering", 1),
    ("ENG-WS-02", "Engineering", 1),
    ("ENG-WS-03", "Engineering", 1),
    ("ENG-WS-04", "Engineering", 2),
    ("ENG-WS-05", "Engineering", 3),
    ("SALES-WS-01", "Sales", 3),
    ("SALES-WS-02", "Sales", 3),
    ("SALES-WS-03", "Sales", 3),
    ("SALES-WS-04", "Sales", 3),
    ("IT-WS-01", "IT", 1),
    ("IT-WS-02", "IT", 1),
    ("IT-WS-03", "IT", 1),
    ("EXEC-WS-01", "Executive", 1),
]

# hostname, role, criticality, last octet of 10.20.0.x
SERVERS: list[tuple[str, str, int, int]] = [
    ("DC-01", "domain_controller", 5, 10),
    ("FS-01", "file_server", 4, 20),
    ("SQL-01", "database_server", 5, 30),
    ("WEB-01", "web_server", 3, 40),
    ("BKP-01", "backup_server", 4, 50),
    ("VPN-01", "vpn_gateway", 4, 5),
]

SERVICE_ACCOUNTS: list[tuple[str, bool]] = [
    ("svc_backup", True),
    ("svc_sql", False),
    ("svc_iis", False),
    ("svc_sccm", True),
    ("svc_monitor", False),
    ("svc_adsync", True),
]

TITLES: dict[str, list[str]] = {
    "Finance": ["Finance Manager", "Accountant", "Accounts Payable Clerk", "Payroll Specialist"],
    "HR": ["HR Manager", "HR Advisor", "Recruiter"],
    "Engineering": ["Software Engineer", "Senior Software Engineer", "QA Engineer", "Tech Lead"],
    "Sales": ["Account Executive", "Sales Manager", "Sales Development Rep"],
    "IT": ["IT Systems Administrator", "IT Support Engineer", "Infrastructure Lead"],
    "Executive": ["Chief Operating Officer"],
}

FIRST_NAMES = [
    "priya", "tom", "aisha", "liam", "mei", "oliver", "fatima", "jack", "sofia", "daniel",
    "chloe", "kwame", "emma", "ravi", "hannah", "lucas", "zara", "noah", "grace", "omar",
    "isla", "arjun", "ella", "mateo", "amara", "ben", "yuki", "sam", "nadia", "leo",
    "ruby", "kofi", "maya", "ethan", "lena", "felix",
]  # fmt: skip
LAST_NAMES = [
    "Nair", "Walsh", "Khan", "Murphy", "Chen", "Hughes", "Ahmed", "Taylor", "Rossi", "Okafor",
    "Evans", "Mensah", "Clarke", "Patel", "Brooks", "Silva", "Malik", "Turner", "Kim", "Haddad",
    "Fraser", "Gupta", "Price", "Lopez", "Obi", "Wright", "Sato", "Reid", "Hassan", "Byrne",
    "Doyle", "Owusu", "Shah", "Ward", "Novak", "Berg",
]  # fmt: skip

# Long-running processes started at boot, before the week of telemetry begins.
BOOT_PROCESSES = ["winlogon.exe", "services.exe", "lsass.exe", "MsMpEng.exe"]
SVCHOST_GROUPS = ["svchost_dcom", "svchost_schedule", "svchost_netsvcs", "svchost_wuauserv"]
ROLE_PROCESSES: dict[str, list[str]] = {
    "workstation": ["OfficeClickToRun.exe"],
    "database_server": ["sqlservr.exe"],
    "backup_server": ["BackupAgent.exe"],
}


def _people(rng: random.Random) -> list[tuple[str, str]]:
    firsts = FIRST_NAMES[:]
    lasts = LAST_NAMES[:]
    rng.shuffle(firsts)
    rng.shuffle(lasts)
    count = sum(n for _, _, n in DESKS)
    pairs = zip(firsts[:count], lasts[:count], strict=True)
    return [(f"{first}.{last[0].lower()}", f"{first.title()} {last}") for first, last in pairs]


def build_world(rng: random.Random) -> World:
    people = iter(_people(rng))
    users: list[User] = []
    hosts: list[Host] = []
    desk_users: dict[str, list[str]] = {}

    for index, (hostname, department, seats) in enumerate(DESKS):
        assigned = []
        for _ in range(seats):
            username, display = next(people)
            is_it = department == "IT"
            travels = department in ("Executive", "Sales") and rng.random() < 0.5
            users.append(
                User(
                    username=username,
                    display_name=display,
                    department=department,
                    title=rng.choice(TITLES[department]),
                    is_admin=is_it,
                    is_service_account=False,
                    usual_countries=["GB", "IE"] if travels else ["GB"],
                )
            )
            assigned.append(username)
        desk_users[hostname] = assigned
        criticality = 3 if department in ("IT", "Executive", "Finance") else 2
        hosts.append(
            Host(
                hostname=hostname,
                role="workstation",
                department=department,
                owner=assigned[0],
                os=WORKSTATION_OS,
                ip=f"10.20.1.{11 + index}",
                criticality=criticality,
            )
        )

    for hostname, role, criticality, octet in SERVERS:
        hosts.append(
            Host(
                hostname=hostname,
                role=role,
                department="IT",
                owner="IT Operations",
                os="VPN appliance" if role == "vpn_gateway" else SERVER_OS,
                ip=f"10.20.0.{octet}",
                criticality=criticality,
            )
        )

    for username, is_admin in SERVICE_ACCOUNTS:
        users.append(
            User(
                username=username,
                display_name=username,
                department="IT",
                title="Service account",
                is_admin=is_admin,
                is_service_account=True,
                usual_countries=["GB"],
            )
        )

    people_names = [u.username for u in users if not u.is_service_account]
    home_hosts = list(HOME_NET.hosts())[9:]
    world = World(
        hosts=hosts,
        users=users,
        desk_users=desk_users,
        browsers={u: rng.choice(["chrome.exe", "msedge.exe"]) for u in people_names},
        home_ips={u: str(home_hosts[i]) for i, u in enumerate(people_names)},
    )
    for host in hosts:
        if host.role != "vpn_gateway":
            world.system[host.hostname] = _boot_processes(world, host, rng)
    return world


def _boot_processes(world: World, host: Host, rng: random.Random) -> dict[str, Proc]:
    names = BOOT_PROCESSES + SVCHOST_GROUPS + ROLE_PROCESSES.get(host.role, [])
    procs = {"System": Proc(4, "System", host.hostname)}
    for key in names:
        name = "svchost.exe" if key.startswith("svchost") else key
        procs[key] = Proc(world.new_pid(host.hostname, rng), name, host.hostname)
    return procs
