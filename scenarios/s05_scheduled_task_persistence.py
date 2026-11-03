"""s05: a fake PDF viewer installer adds a logon scheduled task that runs its dropped
updater. Story: the browser downloads the installer from a .example site, the user runs it,
it drops pdfupd.exe and registers a task through cmd and schtasks; at the next morning's
logon the task starts pdfupd.exe, which beacons to a second address."""

from datetime import timedelta

from scripts.gen.core import fake_sha256, secs
from scripts.gen.scenario import AlertDraft, Context, Indicator, ScenarioResult

SCENARIO_ID = "s05"
SITES = ["pdfview-free.example", "getpdfreader.example", "pdf-tools-download.example"]
C2_DOMAINS = ["cdn.pdfview-update.example", "telemetry.readerupd.example", "api.pdfsync.example"]
TASK_NAME = "PDFViewer Update"


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("Finance", "HR", "Engineering", "Executive"))
    d = rng.choice([0, 1, 2, 3])  # Mon-Thu, so the next day has a morning logon
    s = ctx.session(hostname, d)
    next_morning = ctx.session(hostname, d + 1)
    site = SITES[(ctx.variant - 1) % len(SITES)]
    c2_domain = C2_DOMAINS[(ctx.variant - 1) % len(C2_DOMAINS)]
    site_ip, c2_ip = ctx.bad_ip(0), ctx.bad_ip(1)
    setup_hash = fake_sha256("s05-setup", ctx.variant, site_ip)
    implant_hash = fake_sha256("s05-implant", ctx.variant, c2_ip)
    browser = s.procs[w.browsers[user]]
    t = s.start + secs(rng.randint(2 * 3600, 5 * 3600))

    lookup = w.dns(t, browser, user, site, site_ip)
    size = rng.randint(2_800_000, 3_600_000)
    fetch = w.connect(t + secs(1), browser, user, site_ip, 443, rng.randint(3_000, 6_000), size)
    setup_path = rf"C:\Users\{user}\Downloads\PDFViewer_Setup.exe"
    saved = w.write_file(t + secs(9), browser, user, setup_path, size, sha256=setup_hash)
    setup = w.start(
        t + secs(rng.randint(30, 70)),
        hostname,
        user,
        "PDFViewer_Setup.exe",
        s.procs["explorer.exe"],
        rng,
        path=setup_path,
        sha256=setup_hash,
    )
    t2 = setup.started().ts
    implant_path = rf"C:\Users\{user}\AppData\Roaming\PDFViewer\pdfupd.exe"
    dropped = w.write_file(t2 + secs(6), setup, user, implant_path, 412_160, sha256=implant_hash)
    schtasks_args = f'/create /tn "{TASK_NAME}" /tr "{implant_path}" /sc onlogon /rl highest /f'
    cmd = w.start(
        t2 + secs(9), hostname, user, "cmd.exe", setup, rng, f"/c schtasks {schtasks_args}"
    )
    schtasks = w.start(t2 + secs(10), hostname, user, "schtasks.exe", cmd, rng, schtasks_args)
    task = w.create_task(t2 + secs(10), schtasks, user, f"\\{TASK_NAME}", implant_path, "At logon")

    run_at = next_morning.start + secs(rng.randint(30, 60))
    schedule = w.system[hostname]["svchost_schedule"]
    implant = w.start(
        run_at, hostname, user, "pdfupd.exe", schedule, rng, path=implant_path, sha256=implant_hash
    )
    beacon_lookup = w.dns(run_at + secs(3), implant, user, c2_domain, c2_ip)
    beacons = []
    beacon_at = run_at + secs(4)
    for _ in range(4):
        beacons.append(
            w.connect(beacon_at, implant, user, c2_ip, 443, rng.randint(600, 2_000), 450)
        )
        beacon_at += timedelta(minutes=15) + secs(rng.randint(-40, 40))

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Persistence through a new scheduled task",
        verdict="malicious",
        expected_techniques=["T1053.005"],
        events=ctx.emitted(),
        key_events=[
            lookup,
            fetch,
            saved,
            setup.started(),
            dropped,
            cmd.started(),
            schtasks.started(),
            task,
            implant.started(),
            beacon_lookup,
            *beacons,
        ],
        alert=AlertDraft(
            ts=task.ts + secs(2),
            rule="Scheduled task created",
            severity="medium",
            host=hostname,
            user=user,
            description=f"New scheduled task '\\{TASK_NAME}' runs a binary from AppData at logon.",
            triggers=[task],
        ),
        indicators=[
            Indicator(site, "domain", False, "Fake software download site"),
            Indicator(site_ip, "ip", False, "Fake software download site"),
            Indicator(c2_ip, "ip", True, "Command-and-control server (loader family)"),
            Indicator(c2_domain, "domain", False, "Command-and-control domain"),
            Indicator(implant_hash, "hash", False, "Implant"),
        ],
    )
