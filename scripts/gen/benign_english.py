"""Benign command lines with natural English in them, for the injection classifier's training.

The prompt-injection dataset's benign rows are questions and the generated telemetry's command
lines hold almost no English, so a command line containing a plain English phrase used to
look like an injection: commit messages, installer titles, echo text. These templates use
words that injections also use ("instructions", "prompt", "system", "ignore", "override") in
their ordinary IT sense, so the classifier has to learn the difference.

Seeded and deterministic. The hard-negative files in evals/data/ are held out: a test checks
that no generated line appears in them.
"""

import random
from collections.abc import Callable

VERBS = [
    "Update", "Fix", "Add", "Remove", "Rename", "Clean up", "Document", "Refactor", "Move",
    "Rewrite", "Simplify", "Revert", "Clarify", "Reorder", "Shorten",
]  # fmt: skip
OBJECTS = [
    "the setup instructions", "the system tray icon", "the login prompt", "the ignore list",
    "the override settings", "the README", "the release notes", "the system requirements page",
    "the prompt text on the search box", "the gitignore rules", "the config override for staging",
    "the onboarding checklist", "the installation instructions for Windows",
    "the error message on the upload page", "the system clock sync job", "the default theme",
    "the printer driver instructions", "the command prompt shortcut",
    "the ignore patterns for logs", "the password reset instructions",
    "the system health dashboard", "the override for dark mode",
    "the welcome email template", "the build instructions for the API", "the date picker",
]  # fmt: skip
QUALIFIERS = [
    "", "", " for the finance team", " after review feedback", " so tests pass on Windows",
    " before the release", " to match the style guide", " for new starters", " (closes #{n})",
    " in the admin portal", " for the mobile app",
]  # fmt: skip
FEATURES = [
    "you can now ignore archived projects in search",
    "the system prompt for passwords is shorter",
    "admins can override the default language",
    "clearer instructions on the sign-up page",
    "faster start-up on older laptops",
    "reports can be exported to Excel",
    "the system status page shows planned maintenance",
]
STATUSES = [
    "Backup complete", "Updates installed", "Sync finished", "Patch window starts at 21:00",
    "The system will reboot after the update", "Printer queue cleared",
    "Antivirus definitions are up to date", "Deployment finished without errors",
    "Disk check done", "New system fonts installed", "The shared drive is back online",
]  # fmt: skip
ADVICE = [
    "Please save your work", "You can ignore the warning about the old drive",
    "Follow the instructions in the email from IT", "No action is needed",
    "Press any key at the prompt to continue", "The override for your account has been removed",
    "Call the service desk if anything looks wrong", "Do not turn off the system",
    "Close Outlook before you continue", "Ignore this message if you already restarted",
]  # fmt: skip
TEAMS = ["Finance", "HR", "Sales", "IT", "Engineering", "Facilities", "System"]
TASKS = [
    "nightly report", "health check", "ignore list refresh", "override cache cleanup",
    "weekly reminder to update the instructions page", "system restore point",
    "prompt users to restart", "clear temp files", "send the rota", "check free disk space",
]  # fmt: skip
PRODUCTS = [
    "Corp VPN Client", "Expense Portal", "Desk Planner", "Timesheet App", "Print Helper",
    "Help Desk Agent", "Inventory Agent", "Meeting Room Display", "Badge Reader Tools",
]  # fmt: skip
INSTALL_TEXT = [
    "follow the instructions on each page", "please wait while the system is updated",
    "setup will prompt you before it restarts", "this may override your current settings",
    "you can ignore the restart request until tonight", "read the instructions before you start",
]  # fmt: skip
LOG_TEXT = [
    "copy of the projects share - ignore errors on locked files",
    "system state backup - keep for 90 days",
    "sync of the instructions folder",
    "nightly mirror of the HR share",
    "override run requested by the service desk",
    "migration of old home folders to the new system",
]
SHARES = [r"\\FS-01\Projects", r"\\FS-01\HR", r"\\FS-01\Finance", r"C:\Users\Public\Documents"]
TARGETS = [r"\\BKP-01\Mirror", r"D:\Archive", r"E:\Backups"]


def _message(rng: random.Random) -> str:
    qualifier = rng.choice(QUALIFIERS).format(n=rng.randint(100, 999))
    return f"{rng.choice(VERBS)} {rng.choice(OBJECTS)}{qualifier}"


def _notice(rng: random.Random) -> str:
    return f"{rng.choice(STATUSES)}. {rng.choice(ADVICE)}."


def _version(rng: random.Random) -> str:
    return f"{rng.randint(1, 6)}.{rng.randint(0, 12)}.{rng.randint(0, 9)}"


def _git_commit(rng: random.Random) -> str:
    return f'git commit {rng.choice(["-m", "-am"])} "{_message(rng)}"'


def _pr(rng: random.Random) -> str:
    return f'gh.exe pr create --title "{_message(rng)}" --body "{_message(rng)}."'


def _tag(rng: random.Random) -> str:
    v = _version(rng)
    return f'git tag -a v{v} -m "Release {v}: {rng.choice(FEATURES)}"'


def _installer(rng: random.Random) -> str:
    product = rng.choice(PRODUCTS)
    exe = product.replace(" ", "") + "Setup.exe"
    return f'"C:\\Installers\\{exe}" /S /title="{product} - {rng.choice(INSTALL_TEXT)}"'


def _msi(rng: random.Random) -> str:
    product = rng.choice(PRODUCTS)
    return (
        f'msiexec.exe /i "C:\\Installers\\{product.replace(" ", "_")}.msi" /qn /norestart '
        f'/l*v "C:\\Logs\\{product} - {rng.choice(INSTALL_TEXT)}.log"'
    )


def _echo(rng: random.Random) -> str:
    return f"cmd.exe /c echo {_notice(rng)}"


def _write_host(rng: random.Random) -> str:
    cmdlet = rng.choice(["Write-Host", "Write-Output"])
    return f"powershell.exe -NoProfile -Command \"{cmdlet} '{_notice(rng)}'\""


def _msg(rng: random.Random) -> str:
    return f'msg.exe * /time:{rng.choice([60, 120, 300])} "{_notice(rng)}"'


def _schtasks(rng: random.Random) -> str:
    name = f"{rng.choice(TEAMS)} - {rng.choice(TASKS)}"
    script = rng.choice(TASKS).split()[0]
    schedule = rng.choice(["daily", "weekly"])
    start = f"{rng.randint(0, 23):02d}:{rng.choice(['00', '30'])}"
    return (
        f'schtasks.exe /create /tn "{name}" /tr "C:\\Scripts\\{script}.cmd" '
        f"/sc {schedule} /st {start}"
    )


def _robocopy(rng: random.Random) -> str:
    return (
        f"robocopy.exe {rng.choice(SHARES)} {rng.choice(TARGETS)} /MIR /R:{rng.randint(1, 3)} "
        f'/W:5 /LOG:"C:\\Logs\\{rng.choice(LOG_TEXT)}.log"'
    )


TEMPLATES: list[Callable[[random.Random], str]] = [
    _git_commit, _git_commit, _pr, _tag, _installer, _msi, _echo, _write_host, _msg,
    _schtasks, _robocopy,
]  # fmt: skip


def benign_english_cmdlines(seed: int, n: int = 400) -> list[str]:
    """`n` distinct benign command lines, the same for the same seed."""
    rng = random.Random(f"{seed}:benign_english")
    lines: set[str] = set()
    out: list[str] = []
    for _ in range(n * 50):
        if len(out) == n:
            return out
        line = rng.choice(TEMPLATES)(rng)
        if line not in lines:
            lines.add(line)
            out.append(line)
    raise RuntimeError(f"templates produced only {len(out)} distinct lines")
