"""The HTTP API with a scripted MockLLM and an in-memory store: starting runs, the report, SSE
replay, and the analyst's decisions. The last tests use the real MongoStore as the `app` user."""

import asyncio
import json
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from pymongo import AsyncMongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

from app import blocklist
from app.agent.case import Case
from app.api.routes import Services, event_stream
from app.api.runner import Runner, dump_case
from app.api.store import InMemoryStore, MongoStore, now
from app.config import get_settings
from app.llm import LLMError, MockLLM
from app.main import create_app, llm_for
from app.ml.injection import InjectionModel
from app.telemetry.models import Alert
from scripts.gen.scenario import encode_powershell
from tests.test_agent_graph import (
    ALERT,
    PLANTED,
    REOPEN,
    TRIGGER,
    FakeTelemetry,
    deps,
    process_doc,
)

BLOCKED = "alt_0099"
BLOCKED_ALERT = ALERT.model_copy(update={"alert_id": BLOCKED, "severity": "low"})


class FakeSource(FakeTelemetry):
    """Telemetry for the agents plus the alert queue for the routes."""

    def __init__(self, docs: list[dict[str, Any]], alerts: list[Alert]) -> None:
        super().__init__(docs)
        self._alerts = {a.alert_id: a for a in alerts}

    async def alert(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    async def alerts(self) -> list[Alert]:
        return list(self._alerts.values())


class Harness:
    def __init__(
        self,
        script: dict[str, list[Any]] | None = None,
        docs: list[dict[str, Any]] | None = None,
        llm_for: Callable[..., Any] | None = None,
        results_dir: Path = Path("does-not-exist"),
        **settings: Any,
    ) -> None:
        d, llm, self.calls = deps(script, **settings)
        self.llm = llm
        self.store = InMemoryStore()
        source = FakeSource(
            docs or [process_doc(TRIGGER, "powershell.exe -nop")], [ALERT, BLOCKED_ALERT]
        )
        self.seen_settings: list[Any] = []

        def default_llm_for(s: Any, _: Alert) -> MockLLM:
            self.seen_settings.append(s)
            return llm

        self.runner = Runner(
            self.store, source, d.call_tool, d.settings, llm_for or default_llm_for
        )
        services = Services(self.store, source, self.runner, d.settings, results_dir)
        self.app = create_app(lambda: services)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        )

    async def start(self, alert_id: str = "alt_0001", **body: Any) -> str:
        response = await self.client.post("/investigations", json={"alert_id": alert_id} | body)
        assert response.status_code == 202, response.text
        return response.json()["investigation_id"]

    async def finished_run(self, **body: Any) -> str:
        investigation_id = await self.start(**body)
        await self.runner.tasks[investigation_id]
        return investigation_id

    async def view(self, investigation_id: str) -> dict[str, Any]:
        return (await self.client.get(f"/investigations/{investigation_id}")).json()

    async def decide(self, investigation_id: str, **body: Any) -> httpx.Response:
        return await self.client.post(f"/investigations/{investigation_id}/decision", json=body)

    async def report(self, investigation_id: str) -> httpx.Response:
        return await self.client.get(f"/investigations/{investigation_id}/report.md")


@pytest.fixture(autouse=True)
def _environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, trained_classifier: InjectionModel
) -> None:
    path = tmp_path / "cli_blocklist.json"
    path.write_text(json.dumps({"alert_ids": [BLOCKED]}), encoding="utf-8")
    monkeypatch.setattr(blocklist, "BLOCKLIST", path)


def parse_sse(text: str) -> list[dict[str, Any]]:
    events = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "event" in fields:
            events.append(
                {
                    "id": int(fields["id"]),
                    "kind": fields["event"],
                    "data": json.loads(fields["data"]),
                }
            )
    return events


# --- basics and alerts -----------------------------------------------------------------------


async def test_health_needs_no_services() -> None:
    def no_services() -> Services:
        raise AssertionError("/health must answer without Mongo")

    app = create_app(no_services)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.json() == {"status": "ok"}


async def test_cors_allows_the_dashboard() -> None:
    h = Harness()

    response = await h.client.options(
        "/alerts",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


async def test_alert_queue_filters_by_severity_and_status() -> None:
    h = Harness()
    await h.finished_run()

    everything = (await h.client.get("/alerts")).json()
    high = (await h.client.get("/alerts", params={"severity": "high"})).json()
    fresh = (await h.client.get("/alerts", params={"status": "new"})).json()

    assert {a["alert_id"]: a["status"] for a in everything} == {
        "alt_0001": "awaiting_decision",
        BLOCKED: "blocked",
    }
    assert [a["alert_id"] for a in high] == ["alt_0001"]
    assert fresh == []


async def test_one_alert_comes_with_host_and_user_info() -> None:
    h = Harness()

    alert = (await h.client.get("/alerts/alt_0001")).json()

    assert alert["host_info"]["hostname"] == "FIN-WS-01"
    assert alert["user_info"]["username"] == "a.b"
    assert (await h.client.get("/alerts/alt_9999")).status_code == 404


# --- starting a run --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"alert_id": "alt_9999"}, 404),
        ({"alert_id": "alt_0001", "model": "gpt-9"}, 422),
        ({"alert_id": "alt_0001", "rm": "-rf"}, 422),
        ({}, 422),
    ],
)
async def test_bad_start_requests_are_refused(body: dict[str, Any], status: int) -> None:
    h = Harness()

    response = await h.client.post("/investigations", json=body)

    assert response.status_code == status
    assert h.runner.tasks == {} and h.store.investigations == {}


async def test_blocked_alert_is_refused_before_anything_runs() -> None:
    h = Harness()

    response = await h.client.post("/investigations", json={"alert_id": BLOCKED})

    assert response.status_code == 403 and "eval harness" in response.json()["detail"]
    assert h.runner.tasks == {} and h.store.investigations == {}


async def test_a_setting_allows_blocked_alerts() -> None:
    h = Harness(allow_blocked_alerts=True)

    investigation_id = await h.finished_run(alert_id=BLOCKED)

    assert (await h.view(investigation_id))["status"] == "awaiting_decision"


async def test_a_run_ends_waiting_for_the_analyst() -> None:
    h = Harness()

    view = await h.view(await h.finished_run())

    assert view["status"] == "awaiting_decision" and view["decisions"] == []
    assert view["verdict"] == "malicious" and isinstance(view["risk_score"], int)
    assert view["findings"][0]["status"] == "confirmed" and view["findings"][0]["reportable"]
    assert view["recommendations"][0]["requires_approval"] is True
    assert view["attack_mappings"][0]["technique_id"] == "T1059.001"
    assert view["handoffs"][-1]["to_agent"] == "analyst"
    assert "Report & Human Review" in view["token_use"]
    assert view["token_totals"]["llm_calls"] > 0


async def test_the_requested_model_is_used_for_that_run_only() -> None:
    h = Harness(llm_mode="real")

    investigation_id = await h.finished_run(model="openai/gpt-oss-20b")

    assert h.seen_settings[0].llm_model == "openai/gpt-oss-20b"
    assert h.runner.settings.llm_model != "openai/gpt-oss-20b"
    assert (await h.view(investigation_id))["model"] == "openai/gpt-oss-20b"


async def test_runs_go_one_at_a_time() -> None:
    h = Harness()

    first, second = await h.start(), await h.start()
    await asyncio.gather(h.runner.tasks[first], h.runner.tasks[second])

    a, b = h.store.investigations[first], h.store.investigations[second]
    assert a["finished_at"] <= b["started_at"]


async def test_a_run_that_dies_ends_as_failed_with_a_reason() -> None:
    def broken(settings: Any, alert: Any) -> Any:
        raise LLMError("GROQ_API_KEY is not set in .env")

    h = Harness(llm_for=broken)

    investigation_id = await h.finished_run()

    view = await h.view(investigation_id)
    assert view["status"] == "failed" and "GROQ_API_KEY" in view["error"]
    assert (await h.report(investigation_id)).status_code == 409
    events = await h.store.events_after(investigation_id, 0)
    assert [e["kind"] for e in events][-2:] == ["error", "done"]


async def test_a_failed_plan_call_ends_as_failed() -> None:
    h = Harness({"plan": [LLMError("Groq asks to wait 900s")]})

    view = await h.view(await h.finished_run())

    assert view["status"] == "failed" and "900s" in view["error"]


async def test_a_timed_out_run_ends_as_failed() -> None:
    h = Harness(run_timeout_s=0)

    view = await h.view(await h.finished_run())

    assert view["status"] == "failed" and "timed out" in view["error"]


async def test_restart_marks_active_runs_failed() -> None:
    store = InMemoryStore()
    await store.create_investigation(
        {"investigation_id": "i", "alert_id": "a", "status": "running", "created_at": now()}
    )

    assert await store.mark_interrupted() == 1

    assert store.investigations["i"]["status"] == "failed"


async def test_unknown_investigation_is_a_404() -> None:
    h = Harness()

    for path in ("", "/report.md", "/events"):
        assert (await h.client.get(f"/investigations/nope{path}")).status_code == 404
    assert (await h.decide("nope", verdict_decision="agree")).status_code == 404


# --- what leaves the API ---------------------------------------------------------------------


async def test_withheld_claims_and_raw_triggers_stay_out_of_the_view() -> None:
    cmdline = f"cmd /c echo {PLANTED}"
    h = Harness(docs=[process_doc(TRIGGER, cmdline)])

    investigation_id = await h.finished_run()

    view = await h.view(investigation_id)
    assert "trigger_events" not in view
    assert PLANTED[:30] not in json.dumps(view, default=str)
    assert view["injection_flags"][0].keys() == {"event_id", "method"}
    report = (await h.report(investigation_id)).text
    assert PLANTED[:30] not in report


async def test_stored_state_has_no_conversation_or_raw_ledger() -> None:
    h = Harness()

    doc = h.store.investigations[await h.finished_run()]

    assert "messages" not in doc["state"] and "answers" not in doc["state"]["evidence"]
    assert Case.model_validate(doc["state"]).verdict == "malicious"


# --- SSE -------------------------------------------------------------------------------------


async def test_events_replay_a_whole_run_in_order() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    response = await h.client.get(f"/investigations/{investigation_id}/events")

    events = parse_sse(response.text)
    kinds = [e["kind"] for e in events]
    assert kinds[-1] == "done" and [e["id"] for e in events] == sorted(e["id"] for e in events)
    assert {
        "node_step",
        "handoff",
        "tool_result",
        "finding_added",
        "mapping_checked",
        "verdict",
        "report_ready",
    } <= set(kinds)
    hops = [(e["data"]["from"], e["data"]["to"]) for e in events if e["kind"] == "handoff"]
    assert hops[0] == ("alert", "Sentinel-Triage")
    assert ("Reviewer-Agent", "Report & Human Review") in hops
    assert hops[-1] == ("Report & Human Review", "analyst")
    steps = [e["data"]["node"] for e in events if e["kind"] == "node_step"]
    assert steps[0] == "sentinel_triage" and "plan" in steps and steps[-1] == "report"


async def test_events_resume_after_last_event_id() -> None:
    h = Harness()
    investigation_id = await h.finished_run()
    url = f"/investigations/{investigation_id}/events"
    everything = parse_sse((await h.client.get(url)).text)

    rest = parse_sse((await h.client.get(url, headers={"Last-Event-ID": "5"})).text)

    assert [e["id"] for e in rest] == [e["id"] for e in everything if e["id"] > 5]


async def test_the_stream_follows_new_events_until_done() -> None:
    store = InMemoryStore()
    await store.append_event("i", 1, "node_step", {"node": "plan"})
    seen: list[str] = []

    async def read() -> None:
        async for event in event_stream(store, "i", 0, poll_seconds=0.01):
            seen.append(event["event"])

    reader = asyncio.create_task(read())
    await asyncio.sleep(0.03)
    assert seen == ["node_step"]
    await store.append_event("i", 2, "done", {"status": "awaiting_decision"})
    await asyncio.wait_for(reader, timeout=1)

    assert seen == ["node_step", "done"]


async def test_events_carry_no_raw_log_text() -> None:
    cmdline = f"cmd /c echo {PLANTED}"
    h = Harness(docs=[process_doc(TRIGGER, cmdline)])

    investigation_id = await h.finished_run()

    text = json.dumps([e["data"] for e in await h.store.events_after(investigation_id, 0)])
    assert PLANTED[:30] not in text and "powershell.exe -nop" not in text


# --- the analyst's decision ------------------------------------------------------------------


async def test_approving_and_rejecting_actions_is_recorded_with_a_timestamp() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    response = await h.decide(
        investigation_id, action_id="A1", decision="reject", note="Host is in use."
    )

    assert response.status_code == 201
    (record,) = (await h.view(investigation_id))["decisions"]
    assert record["kind"] == "action" and record["action_id"] == "A1"
    assert record["action"] == "isolate_host" and record["target"] == "FIN-WS-01"
    assert record["decision"] == "reject" and record["note"] == "Host is in use."
    assert datetime.fromisoformat(record["ts"]).tzinfo == UTC


@pytest.mark.parametrize(
    ("body", "agreed", "analyst"),
    [
        ({"verdict_decision": "agree"}, True, "malicious"),
        ({"verdict_decision": "override", "override_verdict": "benign"}, False, "benign"),
    ],
)
async def test_the_case_verdict_decision_is_flat_and_countable(
    body: dict[str, Any], agreed: bool, analyst: str
) -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    assert (await h.decide(investigation_id, note="n", **body)).status_code == 201

    (record,) = [d for d in h.store.decision_log if d["kind"] == "verdict"]
    assert record["agent_verdict"] == "malicious" and record["analyst_verdict"] == analyst
    assert record["agreed"] is agreed and record["agent_confidence"] == 0.9
    assert record["alert_id"] == "alt_0001" and record["model"] and record["ts"]


async def test_agreement_can_be_counted_from_the_records() -> None:
    h = Harness()
    first, second = await h.finished_run(), await h.finished_run()
    await h.decide(first, verdict_decision="agree")
    await h.decide(second, verdict_decision="override", override_verdict="suspicious", note="n")

    verdicts = [d for d in h.store.decision_log if d["kind"] == "verdict"]

    assert sum(d["agreed"] for d in verdicts) / len(verdicts) == 0.5
    pairs = {(d["agent_verdict"], d["analyst_verdict"]) for d in verdicts}
    assert pairs == {("malicious", "malicious"), ("malicious", "suspicious")}


async def test_one_request_can_decide_an_action_and_the_verdict() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    response = await h.decide(
        investigation_id, action_id="A1", decision="approve", verdict_decision="agree"
    )

    assert response.status_code == 201
    assert response.json()["status"] == "decided"
    assert [d["kind"] for d in h.store.decision_log] == ["action", "verdict"]


async def test_decided_needs_the_verdict_and_every_action() -> None:
    two = {
        "recommendations": [
            {"action": "isolate_host", "target": "FIN-WS-01", "reason": "r"},
            {"action": "escalate", "target": "SOC", "reason": "r"},
        ]
    }
    h = Harness({"recommend": [two]})
    investigation_id = await h.finished_run()

    statuses = [
        (await h.decide(investigation_id, verdict_decision="agree")).json()["status"],
        (await h.decide(investigation_id, action_id="A1", decision="approve")).json()["status"],
        (await h.decide(investigation_id, action_id="A2", decision="reject")).json()["status"],
    ]

    assert statuses == ["awaiting_decision", "awaiting_decision", "decided"]
    assert (await h.view(investigation_id))["status"] == "decided"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"note": "only a note"},
        {"action_id": "A1"},
        {"decision": "approve"},
        {"action_id": "A1", "decision": "maybe"},
        {"verdict_decision": "override"},
        {"verdict_decision": "agree", "override_verdict": "benign"},
        {"verdict_decision": "override", "override_verdict": "harmless"},
        {"verdict_decision": "agree", "execute": True},
    ],
)
async def test_malformed_decisions_are_refused(body: dict[str, Any]) -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    assert (await h.decide(investigation_id, **body)).status_code == 422
    assert h.store.decision_log == []


async def test_decisions_are_never_rewritten() -> None:
    h = Harness()
    investigation_id = await h.finished_run()
    await h.decide(investigation_id, action_id="A1", decision="approve")
    await h.decide(investigation_id, verdict_decision="agree")

    again_action = await h.decide(investigation_id, action_id="A1", decision="reject")
    again_verdict = await h.decide(
        investigation_id, verdict_decision="override", override_verdict="benign", note="n"
    )

    assert again_action.status_code == 409 and again_verdict.status_code == 409
    assert [d.get("decision") for d in h.store.decision_log] == ["approve", None]


async def test_unknown_action_is_a_404_and_records_nothing() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    response = await h.decide(
        investigation_id, action_id="A9", decision="approve", verdict_decision="agree"
    )

    assert response.status_code == 404 and h.store.decision_log == []


async def test_overriding_to_the_same_verdict_is_refused() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    response = await h.decide(
        investigation_id, verdict_decision="override", override_verdict="malicious", note="n"
    )

    assert response.status_code == 422


async def test_nothing_can_be_decided_before_the_run_finishes() -> None:
    h = Harness()
    await h.store.create_investigation(
        {"investigation_id": "q", "alert_id": "alt_0001", "status": "queued", "created_at": now()}
    )

    assert (await h.decide("q", verdict_decision="agree")).status_code == 409
    assert (await h.report("q")).status_code == 409


async def test_a_decision_executes_nothing() -> None:
    h = Harness()
    investigation_id = await h.finished_run()
    calls_before, prompts_before = len(h.calls), sum(len(p) for p in h.llm.prompts.values())

    await h.decide(investigation_id, action_id="A1", decision="approve", verdict_decision="agree")

    assert len(h.calls) == calls_before
    assert sum(len(p) for p in h.llm.prompts.values()) == prompts_before


async def test_the_report_shows_decisions_once_recorded() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    before = (await h.report(investigation_id)).text
    await h.decide(
        investigation_id,
        action_id="A1",
        decision="approve",
        verdict_decision="override",
        override_verdict="suspicious",
        note="Could be a pentest.",
    )
    after = (await h.report(investigation_id)).text

    assert "Pending. The analyst has not recorded" in before
    assert "| A1 | isolate_host | FIN-WS-01 | Contain the host. | pending |" in before
    assert "**overrode**" in after and "**suspicious**" in after
    assert "Could be a pentest." in after
    assert "| A1 | isolate_host | FIN-WS-01 | Contain the host. | approved: Could be" in after


async def test_a_report_rebuilt_from_storage_keeps_the_new_sections() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    report = (await h.report(investigation_id)).text

    assert "| Sentinel-Triage | mock | 1 | 1 |" in report
    assert "not run" not in report
    assert f"| {TRIGGER} | process_start | 99.0 |" in report
    assert "Injection scan: 0 flags across" in report


# --- evals -----------------------------------------------------------------------------------


async def test_evals_latest_returns_the_newest_file_per_kind(tmp_path: Path) -> None:
    (tmp_path / "anomaly_2026-11-03.json").write_text('{"v": 1}', encoding="utf-8")
    (tmp_path / "anomaly_2026-11-04.json").write_text('{"v": 2}', encoding="utf-8")
    (tmp_path / "injection_2026-11-04.json").write_text('{"v": 3}', encoding="utf-8")
    h = Harness(results_dir=tmp_path)

    latest = (await h.client.get("/evals/latest")).json()

    assert latest["anomaly"] == {"file": "anomaly_2026-11-04.json", "results": {"v": 2}}
    assert latest["injection"]["results"] == {"v": 3}


async def test_evals_latest_is_empty_without_results() -> None:
    assert (await Harness().client.get("/evals/latest")).json() == {}


# --- the real store, as the `app` user --------------------------------------------------------


@pytest.fixture
async def mongo_store() -> AsyncIterator[tuple[MongoStore, str]]:
    uri = get_settings().triage_mongo_uri.get_secret_value()
    client: AsyncMongoClient = AsyncMongoClient(uri, tz_aware=True, serverSelectionTimeoutMS=2000)
    db = client.get_default_database()
    try:
        await db.command("ping")
    except (ServerSelectionTimeoutError, OperationFailure):
        await client.close()
        pytest.skip("triage db not reachable; run `python tasks.py up`")
    store = MongoStore(db)
    await store.ensure_indexes()
    investigation_id = f"test-{uuid.uuid4().hex}"
    yield store, investigation_id
    for collection in ("investigations", "investigation_events", "decisions"):
        await db[collection].delete_many({"investigation_id": investigation_id})
    await client.close()


@pytest.mark.mongo
async def test_mongo_store_round_trip(mongo_store: tuple[MongoStore, str]) -> None:
    store, investigation_id = mongo_store

    await store.create_investigation(
        {
            "investigation_id": investigation_id,
            "alert_id": "alt_test",
            "status": "queued",
            "created_at": now(),
        }
    )
    await store.update_investigation(investigation_id, {"status": "awaiting_decision"})
    await store.append_event(investigation_id, 1, "node_step", {"node": "plan"})
    await store.append_event(investigation_id, 2, "done", {})
    await store.add_decision(
        {
            "investigation_id": investigation_id,
            "kind": "verdict",
            "agreed": True,
            "agent_verdict": "benign",
            "analyst_verdict": "benign",
            "ts": now(),
        }
    )

    doc = await store.get_investigation(investigation_id)
    assert doc is not None and doc["status"] == "awaiting_decision" and "_id" not in doc
    assert [e["seq"] for e in await store.events_after(investigation_id, 1)] == [2]
    (decision,) = await store.decisions(investigation_id)
    assert decision["agreed"] is True and "_id" not in decision
    assert (await store.latest_runs_by_alert())["alt_test"]["status"] == "awaiting_decision"


@pytest.mark.mongo
async def test_mongo_store_marks_interrupted_runs(mongo_store: tuple[MongoStore, str]) -> None:
    store, investigation_id = mongo_store
    await store.create_investigation(
        {
            "investigation_id": investigation_id,
            "alert_id": "alt_test",
            "status": "running",
            "created_at": now(),
        }
    )

    assert await store.mark_interrupted() >= 1

    doc = await store.get_investigation(investigation_id)
    assert doc is not None and doc["status"] == "failed"


@pytest.mark.mongo
async def test_a_stored_case_survives_mongo(mongo_store: tuple[MongoStore, str]) -> None:
    store, investigation_id = mongo_store
    h = Harness()
    source = h.store.investigations[await h.finished_run()]["state"]

    await store.create_investigation(
        {
            "investigation_id": investigation_id,
            "alert_id": "alt_test",
            "status": "awaiting_decision",
            "created_at": now(),
            "state": source,
        }
    )

    doc = await store.get_investigation(investigation_id)
    assert doc is not None
    assert Case.model_validate(doc["state"]).verdict == "malicious"


def test_dump_case_is_json_ready() -> None:
    assert json.dumps(dump_case(Case(alert=ALERT)))


# --- the dashboard's data --------------------------------------------------------------------


async def test_a_mock_run_says_so_on_its_record_and_its_view() -> None:
    h = Harness()

    investigation_id = await h.finished_run()

    view = await h.view(investigation_id)
    assert view["mock"] is True and view["model"] == "mock"
    assert (await h.client.get("/meta")).json() == {"mock": True}


async def test_a_real_run_is_not_marked_mock() -> None:
    h = Harness(llm_mode="real")

    view = await h.view(await h.finished_run())

    assert view["mock"] is False and view["model"] == "openai/gpt-oss-120b"
    assert (await h.client.get("/meta")).json() == {"mock": False}


async def test_the_app_factory_uses_the_scripted_model_only_in_mock_mode() -> None:
    settings = get_settings()

    assert isinstance(llm_for(settings.model_copy(update={"llm_mode": "mock"}), ALERT), MockLLM)
    assert not isinstance(
        llm_for(
            settings.model_copy(update={"llm_mode": "real", "groq_api_key": SecretStr("x")}),
            ALERT,
        ),
        MockLLM,
    )


async def test_a_queue_row_has_the_latest_run_and_no_description() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    rows = {a["alert_id"]: a for a in (await h.client.get("/alerts")).json()}

    row = rows["alt_0001"]
    assert row["investigation_id"] == investigation_id and row["priority"] == "P2"
    assert row["blocked"] is False and row["mock"] is True and "description" not in row


async def test_a_blocked_alert_shows_only_that_it_is_blocked() -> None:
    h = Harness()

    rows = {a["alert_id"]: a for a in (await h.client.get("/alerts")).json()}

    assert rows[BLOCKED] == {
        "alert_id": BLOCKED,
        "severity": "low",
        "status": "blocked",
        "blocked": True,
        "priority": None,
        "investigation_id": None,
        "mock": False,
    }
    assert (await h.client.get(f"/alerts/{BLOCKED}")).status_code == 403
    assert (await h.client.post("/investigations", json={"alert_id": BLOCKED})).status_code == 403


async def test_the_priority_is_stored_as_soon_as_triage_decides() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    doc = await h.store.get_investigation(investigation_id)

    assert doc is not None and doc["priority"] == "P2"


async def test_finished_runs_are_listed_newest_first_without_their_state() -> None:
    h = Harness()
    first = await h.finished_run()
    second = await h.finished_run()

    rows = (await h.client.get("/investigations")).json()

    assert [r["investigation_id"] for r in rows] == [second, first]
    assert rows[0]["verdict"] == "malicious" and rows[0]["rule"] == ALERT.rule
    assert rows[0]["risk_score"] is not None and "state" not in rows[0]


async def test_each_stage_ticks_in_over_sse_with_its_output() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    events = await h.store.events_after(investigation_id, 0)

    stages = [e["data"] for e in events if e["kind"] == "stage_done"]
    assert [s["stage"] for s in stages] == [
        "Sentinel-Triage",
        "CyberIntel-Agent",
        "Investigator-Agent",
        "Reviewer-Agent",
        "Report & Human Review",
    ]
    assert stages[0]["output"] == "P2 endpoint" and stages[0]["duration"].endswith(" s")
    assert stages[2]["output"] == "1 finding"
    assert stages[3]["output"] == "1 confirmed, 0 disputed"
    assert stages[4]["output"].startswith("malicious, risk ")


async def test_a_reopen_sends_a_second_row_for_the_same_stage() -> None:
    h = Harness({"review_verdict": [REOPEN]})
    investigation_id = await h.finished_run()

    events = await h.store.events_after(investigation_id, 0)

    stages = [e["data"]["stage"] for e in events if e["kind"] == "stage_done"]
    assert stages.count("Investigator-Agent") == 2 and stages.count("Reviewer-Agent") == 2


async def test_the_view_has_the_trail_and_the_scan_line() -> None:
    h = Harness()

    view = await h.view(await h.finished_run())

    assert view["agent_trail"][0]["stage"] == "Sentinel-Triage"
    assert view["agent_trail"][0]["models"] == "mock"
    assert view["texts_scanned"] > 0 and view["injection_line"].startswith(
        "Injection scan: 0 flags"
    )


async def test_the_drawer_serves_a_cited_event_and_nothing_else() -> None:
    h = Harness()
    investigation_id = await h.finished_run()
    url = f"/investigations/{investigation_id}/raw-event"

    cited = await h.client.get(f"{url}/{TRIGGER}")
    uncited = await h.client.get(f"{url}/evt_999999")

    assert cited.status_code == 200 and cited.json()["injection_flagged"] is False
    assert cited.json()["untrusted_log_data"]["event_id"] == TRIGGER
    assert uncited.status_code == 404


async def test_the_drawer_withholds_a_flagged_events_log_text() -> None:
    h = Harness(docs=[process_doc(TRIGGER, f"cmd /c echo {PLANTED}")])
    investigation_id = await h.finished_run()

    response = await h.client.get(f"/investigations/{investigation_id}/raw-event/{TRIGGER}")

    body = response.json()
    assert body["injection_flagged"] is True and "withheld" in body["withheld"]
    assert PLANTED[:30] not in response.text and "untrusted_log_data" not in body


async def test_the_drawer_decodes_an_encoded_command() -> None:
    cmdline = f"powershell.exe -enc {encode_powershell('Write-Output hello')}"
    h = Harness(docs=[process_doc(TRIGGER, cmdline)])
    investigation_id = await h.finished_run()

    response = await h.client.get(f"/investigations/{investigation_id}/raw-event/{TRIGGER}")

    assert response.json()["decoded_cmdline"] == "Write-Output hello"


async def test_the_drawer_waits_for_a_finished_run() -> None:
    h = Harness()
    await h.store.create_investigation(
        {"investigation_id": "x", "alert_id": "alt_0001", "status": "running", "created_at": now()}
    )

    response = await h.client.get(f"/investigations/x/raw-event/{TRIGGER}")

    assert response.status_code == 409


async def test_an_override_needs_a_note() -> None:
    h = Harness()
    investigation_id = await h.finished_run()

    without = await h.decide(
        investigation_id, verdict_decision="override", override_verdict="benign", note="  "
    )
    agree = await h.decide(investigation_id, verdict_decision="agree")

    assert without.status_code == 422 and agree.status_code == 201


@pytest.mark.mongo
async def test_a_finished_run_stays_in_mongo_with_its_events(
    mongo_store: tuple[MongoStore, str],
) -> None:
    store, investigation_id = mongo_store
    await store.create_investigation(
        {
            "investigation_id": investigation_id,
            "alert_id": "alt_test",
            "status": "awaiting_decision",
            "mock": True,
            "created_at": now(),
        }
    )
    await store.append_event(investigation_id, 1, "stage_done", {"stage": "Sentinel-Triage"})

    listed = await store.list_investigations(50)

    assert investigation_id in [d["investigation_id"] for d in listed]
    assert (await store.events_after(investigation_id, 0))[0]["kind"] == "stage_done"
