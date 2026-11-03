"""s04: ransomware prep. From an IT admin's workstation, someone RDPs to a server with the
admin's account and wipes every recovery option: shadow copies (vssadmin and WMI), boot
recovery, and the backup catalog. The admin's daily RDP and BKP-01's nightly
`vssadmin list shadows` are the benign look-alikes in the background."""

from scripts.gen.core import secs
from scripts.gen.scenario import AlertDraft, Context, ScenarioResult

SCENARIO_ID = "s04"

COMMANDS = [
    ("vssadmin.exe", "delete shadows /all /quiet"),
    ("wmic.exe", "shadowcopy delete /nointeractive"),
    ("bcdedit.exe", "/set {default} recoveryenabled No"),
    ("wbadmin.exe", "delete catalog -quiet"),
]


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    workstation, user = ctx.pick_desk(("IT",))
    server = ctx.pick(["FS-01", "SQL-01"])
    d = rng.choice([1, 2, 3])
    s = ctx.session(workstation, d)
    t = s.end - secs(rng.randint(40 * 60, 90 * 60))

    mstsc = w.start(t, workstation, user, "mstsc.exe", s.procs["explorer.exe"], rng, f"/v:{server}")
    rdp = w.connect(
        t + secs(2),
        mstsc,
        user,
        w.host(server).ip,
        3389,
        rng.randint(400_000, 2_000_000),
        rng.randint(5_000_000, 30_000_000),
    )
    logon = w.logon(t + secs(4), server, user, "remote_interactive", w.host(workstation).ip)
    boot = w.system[server]
    userinit = w.start(t + secs(6), server, user, "userinit.exe", boot["winlogon.exe"], rng)
    explorer = w.start(t + secs(8), server, user, "explorer.exe", userinit, rng)
    cmd_at = t + secs(rng.randint(120, 240))
    cmd = w.start(cmd_at, server, user, "cmd.exe", explorer, rng)
    wipes = []
    for i, (name, args) in enumerate(COMMANDS, start=1):
        proc = w.start(cmd_at + secs(i * rng.randint(12, 25)), server, user, name, cmd, rng, args)
        wipes.append(proc.started())

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Ransomware prep: shadow copies deleted",
        verdict="malicious",
        expected_techniques=["T1490"],
        events=ctx.emitted(),
        key_events=[mstsc.started(), rdp, logon, cmd.started(), *wipes],
        alert=AlertDraft(
            ts=wipes[0].ts + secs(3),
            rule="Shadow copy deletion",
            severity="critical",
            host=server,
            user=user,
            description="vssadmin.exe deleted all volume shadow copies.",
            triggers=[wipes[0]],
        ),
        indicators=[],
    )
