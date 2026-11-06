"""app/llm.py without any network: pacing, 429 retries, structured-output retries, the mock."""

from typing import Any

import groq
import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage
from pydantic import BaseModel

from app.config import get_settings
from app.llm import GroqLLM, InvalidToolCallError, LLMError, MockLLM, TokenBucket, get_model


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def rate_limited(headers: dict[str, str]) -> groq.RateLimitError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(429, headers=headers, request=request)
    return groq.RateLimitError("rate limited", response=response, body=None)


class FakeRunnable:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    async def ainvoke(self, messages: list[Any]) -> Any:
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeChat:
    def __init__(self, runnable: FakeRunnable) -> None:
        self.runnable = runnable

    def bind_tools(self, tools: list[dict[str, Any]]) -> FakeRunnable:
        return self.runnable

    def with_structured_output(self, schema: Any, **kwargs: Any) -> FakeRunnable:
        return self.runnable


def reply(tokens_in: int = 100, tokens_out: int = 20) -> AIMessage:
    usage = {"input_tokens": tokens_in, "output_tokens": tokens_out, "total_tokens": 0}
    return AIMessage(content="ok", usage_metadata=usage)


def groq_llm(
    runnable: FakeRunnable,
    clock: FakeClock,
    efforts: dict[str, str] | None = None,
    built: list[str | None] | None = None,
    **settings: Any,
) -> GroqLLM:
    s = get_settings().model_copy(update=settings)

    def chat_for(effort: str | None) -> FakeChat:
        if built is not None:
            built.append(effort)
        return FakeChat(runnable)

    return GroqLLM(chat_for, s, efforts, clock=clock, sleep=clock.sleep)  # type: ignore[arg-type]


async def test_reasoning_effort_is_per_node_and_recorded() -> None:
    built: list[str | None] = []
    efforts = {"plan": "low", "investigate": "medium"}
    llm = groq_llm(FakeRunnable([reply()]), FakeClock(), efforts, built)

    await llm.invoke_tools("investigate", [HumanMessage("a")], [])
    await llm.invoke_tools("investigate", [HumanMessage("b")], [])
    await llm.invoke_tools("plan", [HumanMessage("c")], [])

    # One chat model per effort, built once and reused.
    assert built == ["medium", "low"]
    by_node = llm.usage.by_node()
    assert by_node["investigate"]["effort"] == "medium" and by_node["investigate"]["calls"] == 2
    assert by_node["plan"]["effort"] == "low"


def test_default_efforts_think_harder_where_checks_are_chosen() -> None:
    efforts = get_settings().llm_reasoning_effort

    assert efforts == {
        "plan": "low",
        "investigate": "medium",
        "summarize_findings": "low",
        "critic": "medium",
    }


async def test_bucket_waits_only_for_the_missing_tokens() -> None:
    clock = FakeClock()
    bucket = TokenBucket(6000, clock, clock.sleep)  # refills 100 tokens a second
    bucket.record(5000)

    waited = await bucket.wait_for(4000)

    assert waited == pytest.approx(30.0)
    assert bucket.available() == pytest.approx(4000)


async def test_bucket_refills_over_time_and_caps_at_the_limit() -> None:
    clock = FakeClock()
    bucket = TokenBucket(6000, clock, clock.sleep)
    bucket.record(3000)
    clock.now = 600.0

    assert await bucket.wait_for(2000) == 0.0
    assert bucket.available() == 6000


async def test_bucket_never_waits_for_more_than_the_whole_limit() -> None:
    clock = FakeClock()
    bucket = TokenBucket(6000, clock, clock.sleep)
    bucket.record(6000)

    assert await bucket.wait_for(50_000) == pytest.approx(60.0)


async def test_429_waits_for_retry_after_then_succeeds() -> None:
    clock = FakeClock()
    runnable = FakeRunnable([rate_limited({"retry-after": "7"}), rate_limited({}), reply()])
    llm = groq_llm(runnable, clock)

    answer = await llm.invoke_tools("investigate", [HumanMessage("hi")], [])

    assert answer.content == "ok"
    # 7 s from retry-after, then exponential backoff (2**1) when the header is missing.
    assert clock.sleeps == [7.0, 2.0]
    (record,) = llm.usage.calls
    assert record.retries == 2 and record.input_tokens == 100 and record.output_tokens == 20


async def test_429_gives_up_after_max_retries() -> None:
    clock = FakeClock()
    llm = groq_llm(FakeRunnable([rate_limited({"retry-after": "1"})]), clock, llm_max_retries=2)

    with pytest.raises(LLMError, match="rate limited"):
        await llm.invoke_tools("investigate", [HumanMessage("hi")], [])
    assert clock.sleeps == [1.0, 1.0]


class Answer(BaseModel):
    value: int


async def test_structured_output_retried_once_with_parse_error() -> None:
    bad = {"raw": reply(), "parsed": None, "parsing_error": ValueError("not json")}
    good = {"raw": reply(), "parsed": Answer(value=3), "parsing_error": None}
    runnable = FakeRunnable([bad, good])
    llm = groq_llm(runnable, FakeClock())

    answer = await llm.invoke_structured("plan", [HumanMessage("hi")], Answer)

    assert answer == Answer(value=3)
    assert runnable.calls == 2 and len(llm.usage.calls) == 2


async def test_structured_output_fails_cleanly_after_second_bad_parse() -> None:
    bad = {"raw": reply(), "parsed": None, "parsing_error": ValueError("not json")}
    llm = groq_llm(FakeRunnable([bad]), FakeClock())

    with pytest.raises(LLMError, match="did not match Answer twice"):
        await llm.invoke_structured("plan", [HumanMessage("hi")], Answer)


async def test_usage_totals_add_up() -> None:
    llm = groq_llm(FakeRunnable([reply(100, 20), reply(50, 5)]), FakeClock())
    await llm.invoke_tools("investigate", [HumanMessage("a")], [])
    await llm.invoke_tools("investigate", [HumanMessage("b")], [])

    assert llm.usage.totals() == {
        "llm_calls": 2,
        "input_tokens": 150,
        "cached_tokens": 0,
        "output_tokens": 25,
        "total_tokens": 175,
        "billed_tokens": 175,
    }


async def test_cached_tokens_are_logged_and_not_billed_for_pacing() -> None:
    usage = {
        "input_tokens": 4000,
        "output_tokens": 100,
        "total_tokens": 4100,
        "input_token_details": {"cache_read": 3000},
    }
    llm = groq_llm(FakeRunnable([AIMessage("ok", usage_metadata=usage)]), FakeClock())

    await llm.invoke_tools("investigate", [HumanMessage("x")], [])

    (record,) = llm.usage.calls
    assert record.cached_tokens == 3000 and record.billed_tokens == 1100
    # Groq: cached tokens don't count towards rate limits, so pacing only spends 1,100.
    assert llm.window.available() == pytest.approx(8000 - 1100)


async def test_mock_repeats_last_answer_and_records_prompts() -> None:
    call = {"name": "get_host_info", "args": {"host": "DC-01"}, "id": "x", "type": "tool_call"}
    mock = MockLLM({"investigate": [AIMessage("", tool_calls=[call])]})

    first = await mock.invoke_tools("investigate", [HumanMessage("1")], [])
    second = await mock.invoke_tools("investigate", [HumanMessage("2")], [])

    assert first.tool_calls[0]["name"] == second.tool_calls[0]["name"] == "get_host_info"
    assert first.tool_calls[0]["id"] != second.tool_calls[0]["id"]
    assert len(mock.prompts["investigate"]) == 2


async def test_mock_without_script_for_node_is_an_error() -> None:
    with pytest.raises(LLMError, match="no answer scripted"):
        await MockLLM({}).invoke_structured("critic", [HumanMessage("x")], Answer)


def test_get_model_refuses_mock_mode() -> None:
    with pytest.raises(LLMError, match="MockLLM"):
        get_model(get_settings().model_copy(update={"llm_mode": "mock"}))


def bad_request(code: str = "tool_use_failed") -> groq.BadRequestError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(400, request=request)
    body = {"error": {"code": code, "message": "schema mismatch", "failed_generation": "SECRET"}}
    return groq.BadRequestError("bad request", response=response, body=body)


async def test_rejected_tool_call_raises_with_the_api_reason_only() -> None:
    runnable = FakeRunnable([bad_request()])
    llm = groq_llm(runnable, FakeClock())

    with pytest.raises(InvalidToolCallError) as raised:
        await llm.invoke_tools("investigate", [HumanMessage("x" * 400)], [])

    assert str(raised.value) == "schema mismatch" and "SECRET" not in str(raised.value)
    # The rejected request's ~100 estimated tokens still count for pacing.
    assert llm.window.available() == pytest.approx(8000 - 100)


async def test_other_bad_requests_are_plain_llm_errors() -> None:
    llm = groq_llm(FakeRunnable([bad_request("context_length_exceeded")]), FakeClock())

    with pytest.raises(LLMError, match="context_length_exceeded") as raised:
        await llm.invoke_tools("investigate", [HumanMessage("hi")], [])
    assert not isinstance(raised.value, InvalidToolCallError)


async def test_strict_schema_rejection_is_retried_once() -> None:
    good = {"raw": reply(), "parsed": Answer(value=1), "parsing_error": None}
    runnable = FakeRunnable([bad_request("json_validate_failed"), good])
    llm = groq_llm(runnable, FakeClock())

    answer = await llm.invoke_structured("summarize_findings", [HumanMessage("x")], Answer)

    assert answer == Answer(value=1) and runnable.calls == 2


async def test_rejection_errors_never_carry_failed_generation() -> None:
    llm = groq_llm(FakeRunnable([bad_request("json_validate_failed")]), FakeClock())

    with pytest.raises(LLMError) as raised:
        await llm.invoke_structured("critic", [HumanMessage("x")], Answer)

    assert "SECRET" not in str(raised.value)
    assert raised.value.__cause__ is None


async def test_long_retry_after_fails_fast_with_the_reason() -> None:
    clock = FakeClock()
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    body = {"error": {"code": "rate_limit_exceeded", "message": "tokens per day (TPD) reached"}}
    response = httpx.Response(429, headers={"retry-after": "1522"}, request=request)
    daily = groq.RateLimitError("rate limited", response=response, body=body)
    llm = groq_llm(FakeRunnable([daily]), clock)

    with pytest.raises(LLMError, match="wait 1522s: tokens per day"):
        await llm.invoke_tools("investigate", [HumanMessage("hi")], [])
    assert clock.sleeps == []
