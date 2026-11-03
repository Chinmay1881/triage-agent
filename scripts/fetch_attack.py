"""Download the pinned Enterprise ATT&CK STIX bundle into data/attack/.

Standard library only. Stores the bundle gzipped (55 MB raw is over GitHub's 50 MB warning,
about 9 MB compressed) and writes manifest.json with SHA-256 hashes that catalog.py verifies
on load. `--check-latest` reports whether MITRE has published a newer version than the pin.

    python scripts/fetch_attack.py [--check-latest]
"""

import argparse
import gzip
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

VERSION = "20.0"
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
BUNDLE_URL = f"{BASE}/enterprise-attack/enterprise-attack-{VERSION}.json"
INDEX_URL = f"{BASE}/index.json"

OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "attack"
BUNDLE_PATH = OUT_DIR / f"enterprise-attack-{VERSION}.json.gz"
MANIFEST_PATH = OUT_DIR / "manifest.json"


def fetch(url: str) -> bytes:
    # Fixed https URLs above, never user input.
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
        return resp.read()


def bundle_version(raw: bytes) -> str | None:
    objects = json.loads(raw)["objects"]
    return next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), None
    )


def latest_enterprise_version() -> str:
    index = json.loads(fetch(INDEX_URL))
    enterprise = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    versions = [v["version"] for v in enterprise["versions"]]
    return max(versions, key=lambda v: tuple(int(p) for p in v.split(".")))


def download() -> int:
    print(f"downloading {BUNDLE_URL}")
    raw = fetch(BUNDLE_URL)
    found = bundle_version(raw)
    if found != VERSION:
        print(f"error: bundle says version {found!r}, expected {VERSION}", file=sys.stderr)
        return 1
    # mtime=0 makes the gzip bytes reproducible, so re-fetching gives the same hash.
    packed = gzip.compress(raw, compresslevel=9, mtime=0)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    BUNDLE_PATH.write_bytes(packed)
    manifest = {
        "version": VERSION,
        "source_url": BUNDLE_URL,
        "file": BUNDLE_PATH.name,
        "json_sha256": hashlib.sha256(raw).hexdigest(),
        "gz_sha256": hashlib.sha256(packed).hexdigest(),
    }
    text = json.dumps(manifest, indent=2) + "\n"
    MANIFEST_PATH.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {BUNDLE_PATH} ({len(packed) / 1e6:.1f} MB), sha256 {manifest['gz_sha256']}")
    return 0


def check_latest() -> int:
    latest = latest_enterprise_version()
    if latest == VERSION:
        print(f"pinned {VERSION} is the latest Enterprise ATT&CK release")
    else:
        print(f"newer Enterprise ATT&CK release available: {latest} (pinned {VERSION})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check-latest", action="store_true", help="only compare versions")
    args = parser.parse_args()
    return check_latest() if args.check_latest else download()


if __name__ == "__main__":
    sys.exit(main())
