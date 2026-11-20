"""The daily token budget. Groq's headers report tokens per minute and requests per day, never the
tokens left today, so the harness keeps its own count in runs/spend.jsonl.

Every real run adds its tokens, including runs that were thrown away: Groq counted those too. Other
use of the same API key is invisible here, so a daily-limit 429 is the backstop: Groq's own "Used"
figure replaces whatever the log had added up, and its wait time sets when to resume.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from evals.common import append_jsonl, read_jsonl
from evals.configs import Tier
from evals.scoring import RunRecord

# The docs don't define Groq's daily window; a rolling 24 hours is the cautious reading.
WINDOW = timedelta(hours=24)
FIRST_RUN_TOKENS = 75_000


def next_run_tokens(records: list[RunRecord], models: set[str]) -> dict[str, int]:
    """The largest run seen per model for this config, or a cautious guess before any data."""
    return {
        model: max(
            (r.tokens_by_model[model] for r in records if model in r.tokens_by_model),
            default=FIRST_RUN_TOKENS,
        )
        for model in models
    }


@dataclass
class SpendLog:
    path: Path
    tier: Tier

    def _rows(self) -> list[dict[str, Any]]:
        return read_jsonl(self.path)

    def add_run(self, now: datetime, run: str, tokens_by_model: dict[str, int], kept: bool) -> None:
        for model, tokens in tokens_by_model.items():
            append_jsonl(
                self.path,
                {"ts": now.isoformat(), "model": model, "tokens": tokens, "run": run, "kept": kept},
            )

    def add_limit_hit(
        self, now: datetime, model: str, used: int | None, retry_after_s: float
    ) -> datetime:
        """Record Groq's 429. Returns when Groq says to resume."""
        resume = now + timedelta(seconds=retry_after_s)
        row = {"ts": now.isoformat(), "model": model, "used": used, "resume": resume.isoformat()}
        append_jsonl(self.path, row)
        return resume

    def _counted(self, model: str, now: datetime) -> list[tuple[datetime, int]]:
        """(time, tokens) still inside the window. Rows are in time order, and a 429's "Used"
        replaces everything before it."""
        rows: list[tuple[datetime, int]] = []
        for row in self._rows():
            ts = datetime.fromisoformat(row["ts"])
            if row["model"] != model or ts <= now - WINDOW:
                continue
            if "tokens" in row:
                rows.append((ts, row["tokens"]))
            elif row["used"] is not None:
                rows = [(ts, row["used"])]
        return rows

    def spent(self, model: str, now: datetime) -> int:
        return sum(tokens for _, tokens in self._counted(model, now))

    def _groq_resume(self, model: str, now: datetime) -> datetime | None:
        times = [
            datetime.fromisoformat(row["resume"])
            for row in self._rows()
            if row["model"] == model and "resume" in row
        ]
        return max((t for t in times if t > now), default=None)

    def resume_time(self, needed: dict[str, int], now: datetime) -> datetime | None:
        """None if the next run fits; otherwise the earliest time it will, across its models."""
        waits = []
        for model, tokens in needed.items():
            groq = self._groq_resume(model, now)
            if groq is not None:
                waits.append(groq)
            rows = self._counted(model, now)
            # A run larger than the whole limit could never fit; wait for an empty window instead.
            room = self.tier.daily_tokens - min(tokens, self.tier.daily_tokens)
            total = sum(spent for _, spent in rows)
            for ts, spent in rows:
                if total <= room:
                    break
                total -= spent
                waits.append(ts + WINDOW)
        return max(waits, default=None)
