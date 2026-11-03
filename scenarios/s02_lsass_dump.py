"""s02: an admin's session is used to dump LSASS memory with the built-in comsvcs.dll
MiniDump export. Story: interactive PowerShell, tasklist to find lsass's PID, rundll32 opens
lsass with full access and writes a ~50 MB dump to C:\\Windows\\Temp under a bland name."""

from scripts.gen.core import secs
from scripts.gen.scenario import AlertDraft, Context, ScenarioResult

SCENARIO_ID = "s02"


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("IT",))
    d = rng.choice([1, 2, 3])
    s = ctx.session(hostname, d)
    lsass = w.system[hostname]["lsass.exe"]
    t = s.start + secs(rng.randint(4 * 3600, 6 * 3600))

    ps = w.start(t, hostname, user, "powershell.exe", s.procs["explorer.exe"], rng)
    tasklist = w.start(
        t + secs(rng.randint(20, 50)),
        hostname,
        user,
        "tasklist.exe",
        ps,
        rng,
        '/fi "imagename eq lsass.exe"',
    )
    dump_path = rf"C:\Windows\Temp\wct{ctx.token(4, '0123456789ABCDEF')}.tmp"
    rundll = w.start(
        t + secs(rng.randint(70, 110)),
        hostname,
        user,
        "rundll32.exe",
        ps,
        rng,
        rf"C:\Windows\System32\comsvcs.dll, MiniDump {lsass.pid} {dump_path} full",
    )
    started = rundll.started().ts
    access = w.open_process(started + secs(1), rundll, user, lsass, "0x1fffff")
    dump = w.write_file(started + secs(4), rundll, user, dump_path, rng.randint(48, 64) * 1_048_576)

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Tool reads LSASS memory to steal passwords",
        verdict="malicious",
        expected_techniques=["T1003.001"],
        events=ctx.emitted(),
        key_events=[tasklist.started(), rundll.started(), access, dump],
        alert=AlertDraft(
            ts=access.ts + secs(1),
            rule="Suspicious LSASS access",
            severity="high",
            host=hostname,
            user=user,
            description="rundll32.exe opened lsass.exe with PROCESS_ALL_ACCESS (0x1fffff).",
            triggers=[access],
        ),
        indicators=[],
    )
