"""Rules every investigation tool follows (spec: "Investigation tools").

- Inputs are Pydantic models; bad input becomes {"error": ...}, never an exception.
- Time windows are at most 24 h. Give `start` and `end`, or `around` for around ± 2 h
  (the agent passes the alert time as `around`).
- At most 25 rows, command lines cut to 300 characters, and every event row has event_id.
- Log content is returned under "untrusted_log_data", so prompts can label it as evidence
  and never as instructions.
- Results are capped at about 1,500 tokens. Tokens are estimated as len(compact JSON) / 4,
  which avoids a tokenizer dependency; English text and JSON average roughly four characters
  per token in common BPE tokenizers, close enough for a budget guard. Over the cap, rows
  are dropped from the end and the result says how many matched and to narrow the search.
"""

import json
import math
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StringConstraints,
    ValidationError,
    model_validator,
)
from pymongo.asynchronous.database import AsyncDatabase

MAX_ROWS = 25
CMDLINE_CHARS = 300
TOKEN_CAP = 1500
# fit() trims rows to this, leaving room for the total/shown/note fields added afterwards.
ENVELOPE_RESERVE = 100
MAX_WINDOW = timedelta(hours=24)
DEFAULT_HALF_WINDOW = timedelta(hours=2)
NARROW = "narrow your search (shorter time window or a filter)"


class ToolError(Exception):
    """A clear, agent-facing reason a call can't be answered (unknown host, missing event)."""


def _utc(ts: datetime) -> datetime:
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_utc)]
HostName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,31}$", to_upper=True)
]
UserName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", to_lower=True)
]
EventId = Annotated[str, StringConstraints(pattern=r"^evt_\d{6}$")]
TextFilter = Annotated[str, StringConstraints(min_length=1, max_length=100)]


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WindowInput(ToolInput):
    around: UtcDatetime | None = Field(
        default=None, description="Center of a ±2 h window, usually the alert time (UTC)."
    )
    start: UtcDatetime | None = Field(default=None, description="Window start (UTC).")
    end: UtcDatetime | None = Field(default=None, description="Window end (UTC), ≤ 24 h later.")

    _start: datetime = PrivateAttr()
    _end: datetime = PrivateAttr()

    @model_validator(mode="after")
    def _valid_window(self) -> Self:
        if (self.start is None) != (self.end is None):
            raise ValueError("give both start and end, or neither")
        if self.start is not None and self.end is not None:
            self._start, self._end = self.start, self.end
        elif self.around is not None:
            self._start = self.around - DEFAULT_HALF_WINDOW
            self._end = self.around + DEFAULT_HALF_WINDOW
        else:
            raise ValueError("give start and end, or around (usually the alert time)")
        if self._end <= self._start:
            raise ValueError("end must be after start")
        if self._end - self._start > MAX_WINDOW:
            hours = (self._end - self._start).total_seconds() / 3600
            raise ValueError(f"time window is {hours:.0f} h; the maximum is 24 h")
        return self

    def bounds(self) -> tuple[datetime, datetime]:
        return self._start, self._end


def format_validation_error(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        msg = err["msg"].removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return "invalid arguments: " + "; ".join(parts)


def iso(ts: datetime) -> str:
    return _utc(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def cap_text(text: str, limit: int = CMDLINE_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def contains(text: str) -> dict[str, str]:
    """Case-insensitive substring match. Escaped, so agent input is never a regex."""
    return {"$regex": re.escape(text), "$options": "i"}


def exact(text: str) -> dict[str, str]:
    """Case-insensitive whole-string match, also escaped."""
    return {"$regex": f"^{re.escape(text)}$", "$options": "i"}


def estimate_tokens(obj: Any) -> int:
    return math.ceil(len(json.dumps(obj, separators=(",", ":"), default=str)) / 4)


def fit(result: dict[str, Any], *lists: list[Any]) -> bool:
    """Drop items from the end of the longest of `lists` (all inside `result`) until the
    result fits TOKEN_CAP minus the envelope reserve. Returns True if anything was dropped."""
    dropped = False
    while estimate_tokens(result) > TOKEN_CAP - ENVELOPE_RESERVE:
        longest = max(lists, key=len, default=[])
        if not longest:
            break
        longest.pop()
        dropped = True
    return dropped


def list_result(rows: list[dict[str, Any]], total: int) -> dict[str, Any]:
    """Envelope for tools that return a list of rows; applies the token cap."""
    result: dict[str, Any] = {"untrusted_log_data": rows, "total": total}
    fit(result, rows)
    result["shown"] = len(rows)
    if len(rows) < total:
        result["note"] = f"showing {len(rows)} of {total}; {NARROW}"
    return result


def enforce_cap(result: dict[str, Any]) -> dict[str, Any]:
    """Last line of defence: nothing over the cap ever reaches the model."""
    if estimate_tokens(result) <= TOKEN_CAP:
        return result
    return {"total": result.get("total"), "note": f"result too large; {NARROW}"}


async def ensure_host(db: AsyncDatabase, host: str) -> None:
    if await db.hosts.find_one({"hostname": host}, {"_id": 1}) is None:
        raise ToolError(f"no host named {host}; hostnames look like FIN-WS-01 or DC-01")
