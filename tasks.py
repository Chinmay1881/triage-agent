"""Task runner: `python tasks.py <task>`. Standard library only, so it works on a bare Windows
Python before any dependency is installed (replaces a Makefile, since Windows has no make)."""

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
MODELS = ROOT / "data" / "models"
ARTIFACTS = ("anomaly.joblib", "injection.joblib")
# Scripts run in the backend's environment (they share its models and pymongo).
SCRIPT = ["uv", "run", "--project", str(BACKEND), "python"]


def run(cmd: Sequence[str], cwd: Path = ROOT, env: dict[str, str] | None = None) -> int:
    # Resolve the executable explicitly: on Windows, subprocess won't find .exe/.cmd shims
    # reliably without a shell, and we never want shell=True.
    exe = shutil.which(cmd[0])
    if exe is None:
        print(f"error: '{cmd[0]}' not found on PATH", file=sys.stderr)
        return 127
    try:
        return subprocess.run([exe, *cmd[1:]], cwd=cwd, env=env, check=False).returncode
    except KeyboardInterrupt:
        return 130


def up(args: argparse.Namespace) -> int:
    if not (ROOT / ".env").exists():
        print("error: no .env; copy .env.example to .env and set passwords", file=sys.stderr)
        return 1
    # --wait blocks until the healthcheck passes, so `up` returning 0 means Mongo answers.
    return run(["docker", "compose", "up", "-d", "--wait"])


def down(args: argparse.Namespace) -> int:
    # --volumes wipes the data, which is the only way to re-run the Mongo init scripts.
    return run(["docker", "compose", "down", *(["--volumes"] if args.volumes else [])])


def seed(args: argparse.Namespace) -> int:
    generate = run([*SCRIPT, "scripts/generate.py", "--seed", "42", "--variant", "1"])
    loaded = generate or run([*SCRIPT, "scripts/load.py"])
    if loaded or all((MODELS / name).exists() for name in ARTIFACTS):
        return loaded
    print("model artifacts missing; training them")
    return train(args)


def train(args: argparse.Namespace) -> int:
    # The baseline is seed 7, background only: never the seed-42 eval week.
    return run([*SCRIPT, "scripts/train.py", "--seed", "7"])


def test(args: argparse.Namespace) -> int:
    env = {**os.environ, "LLM_MODE": "mock"}
    # -rs prints the reason for every skipped test, e.g. Mongo not running.
    return run(["uv", "run", "pytest", "-rs", *args.extra], cwd=BACKEND, env=env)


def lint(args: argparse.Namespace) -> int:
    ruff = ["uv", "run", "--project", str(BACKEND), "ruff"]
    check = run([*ruff, "check", "."])
    fmt = run([*ruff, "format", "--check", "."])
    return check or fmt


def dev_api(args: argparse.Namespace) -> int:
    uvicorn = ["uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000"]
    # An environment variable beats .env, so --mock can't reach Groq whatever .env says.
    env = {**os.environ, "LLM_MODE": "mock"} if args.mock else None
    return run(["uv", "run", *uvicorn], cwd=BACKEND, env=env)


def dev_web(args: argparse.Namespace) -> int:
    if not (FRONTEND / "node_modules").exists():
        installed = run(["npm", "install"], cwd=FRONTEND)
        if installed != 0:
            return installed
    return run(["npm", "run", "dev"], cwd=FRONTEND)


TASKS: dict[str, tuple[Callable[[argparse.Namespace], int], str]] = {
    "up": (up, "start MongoDB and wait until it is healthy"),
    "down": (down, "stop MongoDB (--volumes also deletes its data)"),
    "seed": (seed, "generate and load telemetry (seed 42, variant 1); train if models missing"),
    "train": (train, "train the anomaly model (baseline seed 7) and injection classifier"),
    "test": (test, "run backend tests with LLM_MODE=mock (extra args go to pytest)"),
    "lint": (lint, "ruff check + format check"),
    "dev-api": (dev_api, "FastAPI with reload on http://127.0.0.1:8000"),
    "dev-web": (dev_web, "Next.js on http://localhost:3000"),
}


def main() -> int:
    parser = argparse.ArgumentParser(prog="python tasks.py")
    sub = parser.add_subparsers(dest="task", required=True)
    for name, (_, help_text) in TASKS.items():
        p = sub.add_parser(name, help=help_text)
        if name == "down":
            p.add_argument("--volumes", action="store_true")
        if name == "dev-api":
            p.add_argument("--mock", action="store_true", help="scripted model; no Groq calls")
    # parse_known_args so `test -k health -v` reaches pytest; argparse.REMAINDER drops
    # arguments that start with "-".
    args, extra = parser.parse_known_args()
    if extra and args.task != "test":
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    args.extra = extra
    return TASKS[args.task][0](args)


if __name__ == "__main__":
    sys.exit(main())
