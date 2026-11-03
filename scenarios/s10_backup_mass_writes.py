"""s10 (benign): the nightly backup job writes a burst of files into its own store on
BKP-01. Fires "Mass file modification", the alert ransomware would also trip. What makes
it benign: svc_backup, a signed Vaultline binary started by the backup agent, inside the
01:00 window the job runs in every night (the same agent's `vssadmin list shadows` is in
the background each night), and writes only under the backup store.

Every event stays on BKP-01, so FS-01 (claimed by s07) is never touched.
"""

from scripts.gen.core import at, day, secs
from scripts.gen.scenario import AlertDraft, Context, ScenarioResult

SCENARIO_ID = "s10"
BACKUP_HOST = "BKP-01"
ACCOUNT = "svc_backup"
STORE = r"D:\VaultlineStore"
FILES = 60
ALERT_AFTER = 10
FOLDERS = ["Finance", "HR", "Projects", "Sales", "Shared"]


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    host = ctx.pick([BACKUP_HOST])
    d = rng.choice([1, 2, 3, 4])
    agent = w.system[host]["BackupAgent.exe"]
    t = at(d, 1, 20) + secs(rng.randrange(600))

    job = w.start(
        t,
        host,
        ACCOUNT,
        "BackupJob.exe",
        agent,
        rng,
        f'--job "Nightly FS-01 file-level" --schedule "daily 01:00" --target {STORE}',
    )
    stamp = day(d).strftime("%Y-%m-%d")
    writes = []
    write_at = t + secs(5)
    for i in range(FILES):
        path = rf"{STORE}\FS-01\{stamp}\{FOLDERS[i % len(FOLDERS)]}\chunk_{i:04d}.vlb"
        writes.append(w.write_file(write_at, job, ACCOUNT, path, rng.randint(50_000, 40_000_000)))
        write_at += secs(rng.randint(20, 60))

    triggers = writes[:ALERT_AFTER]
    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Backup agent touches thousands of files overnight",
        verdict="benign",
        expected_techniques=[],
        events=ctx.emitted(),
        key_events=[job.started(), *triggers],
        alert=AlertDraft(
            ts=triggers[-1].ts + secs(5),
            rule="Mass file modification",
            severity="medium",
            host=host,
            user=ACCOUNT,
            description=f"{ALERT_AFTER} files written by one process within minutes.",
            triggers=triggers,
        ),
        indicators=[],
    )
