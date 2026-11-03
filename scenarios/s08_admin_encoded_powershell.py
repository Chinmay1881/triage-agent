"""s08 (benign): an IT admin's signed toolkit runs its weekly maintenance script as encoded
PowerShell. Same alert rule as s12 ("Encoded PowerShell"); the difference is all in the
evidence: the parent is a signed, allow-listed vendor tool the admin started from the
desktop, the script decodes to routine clean-up, and it only writes its own log."""

from scripts.gen.core import secs
from scripts.gen.scenario import AlertDraft, Context, ScenarioResult, encode_powershell

SCENARIO_ID = "s08"
LOG_PATH = r"C:\ProgramData\Northbeam\maint.log"
SCRIPT = (
    f"$log='{LOG_PATH}';"
    "Get-ChildItem $env:TEMP -Recurse -File | "
    "Where-Object LastWriteTime -lt (Get-Date).AddDays(-14) | "
    "Remove-Item -Force -ErrorAction SilentlyContinue;"
    "Clear-DnsClientCache;"
    'Add-Content $log "$(Get-Date -Format s) weekly maintenance done"'
)


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("IT",))
    d = rng.choice([1, 2, 3])
    s = ctx.session(hostname, d)
    t = s.start + secs(rng.randint(2 * 3600, 5 * 3600))

    toolkit = w.start(
        t,
        hostname,
        user,
        "AdminToolkit.exe",
        s.procs["explorer.exe"],
        rng,
        '/task "Weekly workstation maintenance"',
    )
    ps = w.start(
        t + secs(rng.randint(8, 20)),
        hostname,
        user,
        "powershell.exe",
        toolkit,
        rng,
        f"-NoProfile -NonInteractive -EncodedCommand {encode_powershell(SCRIPT)}",
    )
    log = w.write_file(
        ps.started().ts + secs(rng.randint(20, 60)),
        ps,
        user,
        LOG_PATH,
        rng.randint(2_000, 9_000),
        action="modify",
    )

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="IT admin runs a signed maintenance script with encoded PowerShell",
        verdict="benign",
        expected_techniques=[],
        events=ctx.emitted(),
        key_events=[toolkit.started(), ps.started(), log],
        alert=AlertDraft(
            ts=ps.started().ts + secs(2),
            rule="Encoded PowerShell",
            severity="medium",
            host=hostname,
            user=user,
            description="powershell.exe started with -EncodedCommand.",
            triggers=[ps.started()],
        ),
        indicators=[],
    )
