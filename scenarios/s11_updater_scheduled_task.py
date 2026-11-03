"""s11 (benign): Adobe's signed updater registers its logon task when Acrobat starts.
Same alert rule as s05 ("Scheduled task created") with the same "At logon" trigger; the
difference is the evidence: a signed, allow-listed creator launched by Acrobat, a task that
runs a binary from Program Files as SYSTEM, and a check-in to Adobe's own domain."""

from scripts.gen.core import image, secs
from scripts.gen.infra import BENIGN_DOMAINS
from scripts.gen.scenario import AlertDraft, Context, ScenarioResult

SCENARIO_ID = "s11"
TASK_NAME = r"\Adobe Acrobat Update Task"
UPDATE_DOMAIN = "acrobat.adobe.com"


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("Finance", "HR", "Engineering", "Executive"))
    d = rng.choice([1, 2, 3])
    s = ctx.session(hostname, d)
    t = s.start + secs(rng.randint(3600, 4 * 3600))

    acrobat = w.start(t, hostname, user, "Acrobat.exe", s.procs["explorer.exe"], rng)
    updater = w.start(
        t + secs(rng.randint(30, 90)), hostname, user, "AdobeARM.exe", acrobat, rng, "/ArmUpdate"
    )
    t2 = updater.started().ts
    ip = BENIGN_DOMAINS[UPDATE_DOMAIN]
    lookup = w.dns(t2 + secs(2), updater, user, UPDATE_DOMAIN, ip)
    check = w.connect(t2 + secs(3), updater, user, ip, 443, rng.randint(2_000, 6_000), 48_000)
    task = w.create_task(
        t2 + secs(rng.randint(20, 60)),
        updater,
        user,
        TASK_NAME,
        f'"{image("AdobeARM.exe")}"',
        "At logon",
        run_as="SYSTEM",
    )

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Software updater creates a scheduled task",
        verdict="benign",
        expected_techniques=[],
        events=ctx.emitted(),
        key_events=[acrobat.started(), updater.started(), lookup, check, task],
        alert=AlertDraft(
            ts=task.ts + secs(2),
            rule="Scheduled task created",
            severity="medium",
            host=hostname,
            user=user,
            description=f"New scheduled task '{TASK_NAME}' runs at logon.",
            triggers=[task],
        ),
        indicators=[],
    )
