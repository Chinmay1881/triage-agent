"""score_anomaly: how unusual up to 10 events are, from the anomaly model in app.ml.

The model and its baseline counts are loaded by app.ml; this module only fetches the events
from the read-only telemetry db and shapes the result.
"""

from typing import Any, Self

from pydantic import Field, model_validator
from pymongo.asynchronous.database import AsyncDatabase

from app.ml import ModelMissingError, anomaly
from app.tools._common import EventId, ToolError, ToolInput

MAX_EVENTS = 10
NOT_SCORED = "not scored: the model covers process_start and network_conn only"


class AnomalyInput(ToolInput):
    event_ids: list[EventId] = Field(
        min_length=1,
        max_length=MAX_EVENTS,
        description=f"1-{MAX_EVENTS} event_ids of process_start or network_conn events.",
    )

    @model_validator(mode="after")
    def _unique(self) -> Self:
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("event_ids must not repeat")
        return self


def readable(value: float) -> float | int:
    return int(value) if value.is_integer() else round(value, 3)


def score_row(score: anomaly.EventScore) -> dict[str, Any]:
    return {
        "event_id": score.event_id,
        "event_type": score.event_type,
        "score": round(score.score, 3),
        "percentile": round(100 * score.percentile, 1),
        "stood_out": [
            {
                "feature": s.feature,
                "value": readable(s.value),
                "baseline_share": round(s.baseline_share, 4),
            }
            for s in score.stood_out
        ],
    }


async def score_anomaly(params: AnomalyInput, db: AsyncDatabase) -> dict[str, Any]:
    try:
        model = anomaly.load()
    except ModelMissingError as exc:
        raise ToolError(str(exc)) from None
    docs = await db.events.find({"event_id": {"$in": params.event_ids}}).to_list(MAX_EVENTS)
    by_id = {d["event_id"]: d for d in docs}
    found = [by_id[e] for e in params.event_ids if e in by_id]
    rows = []
    for doc, score in zip(found, model.score_events(found), strict=True):
        if score is None:
            rows.append(
                {"event_id": doc["event_id"], "event_type": doc["event_type"], "note": NOT_SCORED}
            )
        else:
            rows.append(score_row(score))
    result: dict[str, Any] = {"untrusted_log_data": rows}
    missing = [e for e in params.event_ids if e not in by_id]
    if missing:
        result["not_found"] = missing
    return result
