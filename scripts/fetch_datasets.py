"""Download deepset/prompt-injections into data/datasets/prompt_injections/.

    python scripts/fetch_datasets.py

Standard library only. Rows come from the Hugging Face datasets-server JSON API, 100 at a
time, and are written as train.jsonl / test.jsonl ({"text", "label"}, label 1 = injection),
plus manifest.json (revision, row counts, sha256 per file, licence) and the Apache-2.0
licence text the dataset is published under, which redistribution requires. The rows are
untrusted text: they are parsed as JSON and never printed; only counts are.
"""

import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "datasets" / "prompt_injections"
DATASET = "deepset/prompt-injections"
SPLITS = ("train", "test")
PAGE = 100
HUB_API = f"https://huggingface.co/api/datasets/{DATASET}"
ROWS_API = "https://datasets-server.huggingface.co/rows"
LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
EXPECTED_LICENSE = "apache-2.0"


def get(url: str) -> bytes:
    # Fixed https URLs above, never user input.
    request = urllib.request.Request(url, headers={"User-Agent": "triage-agent-fetch/1"})  # noqa: S310
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                return response.read()
        except OSError:
            if attempt == 3:
                raise
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def get_json(url: str) -> Any:
    return json.loads(get(url))


def fetch_split(split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total = None
    while total is None or len(rows) < total:
        query = urllib.parse.urlencode(
            {
                "dataset": DATASET,
                "config": "default",
                "split": split,
                "offset": len(rows),
                "length": PAGE,
            }
        )
        page = get_json(f"{ROWS_API}?{query}")
        total = page["num_rows_total"]
        if not page["rows"]:
            raise RuntimeError(f"{split}: server returned no rows at offset {len(rows)}")
        for item in page["rows"]:
            if item.get("truncated_cells"):
                raise RuntimeError(f"{split}: row {item['row_idx']} was truncated by the server")
            row = item["row"]
            if not isinstance(row.get("text"), str) or row.get("label") not in (0, 1):
                raise RuntimeError(f"{split}: row {item['row_idx']} has an unexpected shape")
            rows.append({"text": row["text"], "label": row["label"]})
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> str:
    data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows).encode("utf-8")
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def read_manifest() -> dict[str, Any]:
    return json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))


def read_split(split: str) -> tuple[list[str], list[int]]:
    """Texts and labels of one split, checked against the manifest's sha256."""
    path = OUT / f"{split}.jsonl"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != read_manifest()["splits"][split]["sha256"]:
        raise RuntimeError(f"{path} does not match its manifest; re-run fetch_datasets.py")
    rows = [json.loads(line) for line in data.decode("utf-8").splitlines()]
    return [r["text"] for r in rows], [r["label"] for r in rows]


def is_fetched() -> bool:
    return all((OUT / name).exists() for name in ("manifest.json", "train.jsonl", "test.jsonl"))


def main() -> int:
    info = get_json(HUB_API)
    license_id = (info.get("cardData") or {}).get("license")
    if license_id != EXPECTED_LICENSE:
        print(f"error: licence is {license_id!r}, expected {EXPECTED_LICENSE}", file=sys.stderr)
        return 1

    OUT.mkdir(parents=True, exist_ok=True)
    splits = {}
    for split in SPLITS:
        rows = fetch_split(split)
        sha = write_jsonl(OUT / f"{split}.jsonl", rows)
        positives = sum(r["label"] for r in rows)
        splits[split] = {"rows": len(rows), "injections": positives, "sha256": sha}
        print(f"{split}: {len(rows)} rows, {positives} injections")
    (OUT / "LICENSE").write_bytes(get(LICENSE_URL))

    manifest = {
        "dataset": DATASET,
        "source": f"https://huggingface.co/datasets/{DATASET}",
        # datasets-server always serves the latest revision; this is the one live at fetch time.
        "revision": info["sha"],
        "license": license_id,
        "fetched": datetime.now(UTC).strftime("%Y-%m-%d"),
        "label": "1 = prompt injection, 0 = benign",
        "splits": splits,
    }
    text = json.dumps(manifest, indent=2) + "\n"
    (OUT / "manifest.json").write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT} at revision {info['sha'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
