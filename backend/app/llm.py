"""LLM access for the agent: one narrow interface, a Groq implementation and a mock.

Nodes only ever call `invoke_tools` (a turn with tools bound) or `invoke_structured` (output
parsed into a Pydantic model). Keeping the interface this small is what lets the mock replace
the real model completely in tests.

Groq's free tier allows about 8,000 tokens a minute, so `GroqLLM`:
- paces itself with a token bucket: before each call it waits until the estimated request
  fits, which avoids most 429s instead of reacting to them;
- retries HTTP 429 itself (the SDK's own retries are off), sleeping for `retry-after` when the
  server sends it and backing off exponentially when it doesn't;
- retries a structured output that fails to parse, or that Groq's strict schema check
  rejects, once with the error, then fails cleanly (spec: "Flaky output");
- logs tokens and latency for every call and keeps a per-run tally per node, agent and model.

Each agent has its own model (Settings.model_for) and Groq's limits are per model, so every
model gets its own token bucket.
"""

import asyncio
import json
import logging
import re
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar

import groq
from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from pydantic import BaseModel, ValidationError

from app.config import NODE_AGENT, Settings, get_settings

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)
# Expected completion size used for pacing; max_tokens would be far too pessimistic.
EXPECTED_OUTPUT_TOKENS = 600
# Groq's wording: "... on tokens per day (TPD): Limit 200000, Used 199657, Requested 1547."
TOKENS_USED_TODAY = re.compile(r"tokens per day.*?Used (\d+)", re.IGNORECASE | re.DOTALL)


class LLMError(RuntimeError):
    """The model could not produce a usable answer after retries."""


class InvalidToolCallError(LLMError):
    """The API rejected the model's tool call (bad JSON or arguments that fail the schema).
    The message is Groq's explanation, never its `failed_generation`."""


class DailyLimitError(LLMError):
    """A 429 asking for a longer wait than a run can sit through. Nodes treat it like any failed
    call; the eval harness also reads Groq's figures, since no header reports tokens left today."""

    def __init__(self, message: str, model: str, retry_after: float, groq_message: str) -> None:
        super().__init__(message)
        self.model = model
        self.retry_after = retry_after
        match = TOKENS_USED_TODAY.search(groq_message)
        self.used = int(match.group(1)) if match else None


@dataclass
class CallRecord:
    node: str
    input_tokens: int
    output_tokens: int
    seconds: float
    retries: int
    effort: str | None = None
    # Input tokens served from Groq's prompt cache. Groq: "Cached tokens do not count towards
    # your rate limits", so billed = input - cached + output is what the limits see.
    cached_tokens: int = 0
    model: str | None = None
    # Groq rejected the request (400): input_tokens is our estimate, and the output is unknown.
    rejected: bool = False

    @property
    def agent(self) -> str:
        return NODE_AGENT.get(self.node, self.node)

    @property
    def billed_tokens(self) -> int:
        return self.input_tokens - self.cached_tokens + self.output_tokens


@dataclass
class UsageLog:
    calls: list[CallRecord] = field(default_factory=list)

    def add(self, record: CallRecord) -> None:
        self.calls.append(record)
        log.info(
            "llm call node=%s model=%s effort=%s in=%d cached=%d out=%d billed=%d %.1fs "
            "retries=%d%s",
            record.node,
            record.model,
            record.effort,
            record.input_tokens,
            record.cached_tokens,
            record.output_tokens,
            record.billed_tokens,
            record.seconds,
            record.retries,
            " REJECTED" if record.rejected else "",
        )

    def _grouped(self, key: Callable[[CallRecord], str | None]) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for c in self.calls:
            row = out.setdefault(
                str(key(c)),
                {
                    "calls": 0,
                    "rejected_calls": 0,
                    "input_tokens": 0,
                    "cached_tokens": 0,
                    "output_tokens": 0,
                    "billed_tokens": 0,
                },
            )
            row["calls"] += 1
            row["rejected_calls"] += int(c.rejected)
            row["input_tokens"] += c.input_tokens
            row["cached_tokens"] += c.cached_tokens
            row["output_tokens"] += c.output_tokens
            row["billed_tokens"] += c.billed_tokens
        return out

    def by_node(self) -> dict[str, dict[str, Any]]:
        """Calls and tokens per node with its model and reasoning effort."""
        rows: dict[str, dict[str, Any]] = dict(self._grouped(lambda c: c.node))
        for c in self.calls:
            rows[c.node] |= {"effort": c.effort, "model": c.model}
        return rows

    def by_agent(self) -> dict[str, dict[str, int]]:
        return self._grouped(lambda c: c.agent)

    def by_model(self) -> dict[str, dict[str, int]]:
        return self._grouped(lambda c: c.model)

    def models_by_agent(self) -> dict[str, list[str]]:
        """The models each agent's calls really went to, in first-use order."""
        out: dict[str, list[str]] = {}
        for c in self.calls:
            models = out.setdefault(c.agent, [])
            if c.model and c.model not in models:
                models.append(c.model)
        return out

    def totals(self) -> dict[str, int]:
        return {
            "llm_calls": len(self.calls),
            "rejected_calls": sum(c.rejected for c in self.calls),
            "input_tokens": sum(c.input_tokens for c in self.calls),
            "cached_tokens": sum(c.cached_tokens for c in self.calls),
            "output_tokens": sum(c.output_tokens for c in self.calls),
            "total_tokens": sum(c.input_tokens + c.output_tokens for c in self.calls),
            "billed_tokens": sum(c.billed_tokens for c in self.calls),
        }


class LLM(Protocol):
    usage: UsageLog

    async def invoke_tools(
        self, node: str, messages: Sequence[BaseMessage], tools: list[dict[str, Any]]
    ) -> AIMessage: ...

    async def invoke_structured(
        self, node: str, messages: Sequence[BaseMessage], schema: type[T]
    ) -> T: ...


def estimate_tokens(messages: Sequence[BaseMessage], tools: list[dict[str, Any]] | None) -> int:
    """len/4, the same rough estimate the tool caps use."""
    text = "".join(str(m.content) for m in messages)
    text += "".join(json.dumps(m.tool_calls) for m in messages if isinstance(m, AIMessage))
    if tools:
        text += json.dumps(tools, separators=(",", ":"))
    return len(text) // 4


class TokenBucket:
    """Pacing for a tokens-per-minute limit. Groq's limit refills continuously rather than once
    a minute (its x-ratelimit-reset-tokens header counts down in seconds), so the model is a
    bucket of `limit` tokens refilling at limit/60 per second. A rolling 60-second window made a
    4,700-token call block the next one for a full minute even with room to spare."""

    def __init__(
        self,
        limit: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.limit = limit
        self._rate = limit / 60.0
        self._clock = clock
        self._sleep = sleep
        self._level = float(limit)
        self._updated = clock()

    def available(self) -> float:
        now = self._clock()
        self._level = min(self.limit, self._level + (now - self._updated) * self._rate)
        self._updated = now
        return self._level

    async def wait_for(self, tokens: int) -> float:
        """Sleep until `tokens` are available (at most the whole bucket); returns seconds."""
        missing = min(tokens, self.limit) - self.available()
        if missing <= 0:
            return 0.0
        delay = missing / self._rate
        await self._sleep(delay)
        return delay

    def record(self, tokens: int) -> None:
        # May go below zero after an underestimate; the next wait_for then waits longer.
        self._level = self.available() - tokens


def error_text(exc: groq.APIStatusError) -> tuple[str | None, str]:
    """Groq's error code and message without `failed_generation`: that field echoes the
    model's output, which can quote log text, so it never goes into logs or exceptions."""
    body = exc.body if isinstance(exc.body, dict) else {}
    error = body.get("error", body)
    if not isinstance(error, dict):
        return None, f"HTTP {exc.status_code}"
    return error.get("code"), str(error.get("message", f"HTTP {exc.status_code}"))[:300]


def retry_after(exc: groq.RateLimitError) -> float | None:
    """Seconds the server asked us to wait, from retry-after or Groq's reset header."""
    headers = exc.response.headers
    for name in ("retry-after", "x-ratelimit-reset-tokens"):
        value = headers.get(name)
        if not value:
            continue
        try:
            return float(value.removesuffix("s"))
        except ValueError:
            continue
    return None


ChatFactory = Callable[[str, str | None], BaseChatModel]


class GroqLLM:
    """`chat_for(model, effort)` builds a chat model (effort None = provider default); one per
    pair is built lazily and reused. `efforts` maps node -> effort."""

    def __init__(
        self,
        chat_for: ChatFactory,
        settings: Settings,
        efforts: dict[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._chat_for = chat_for
        self._chats: dict[tuple[str, str | None], BaseChatModel] = {}
        self._buckets: dict[str, TokenBucket] = {}
        self._efforts = efforts or {}
        self._settings = settings
        self._sleep = sleep
        self._clock = clock
        self.usage = UsageLog()

    def bucket_for(self, node: str) -> TokenBucket:
        model = self._settings.model_for(node)
        if model not in self._buckets:
            self._buckets[model] = TokenBucket(
                self._settings.llm_tpm_limit, self._clock, self._sleep
            )
        return self._buckets[model]

    def _chat(self, node: str) -> tuple[BaseChatModel, str | None]:
        key = (self._settings.model_for(node), self._efforts.get(node))
        if key not in self._chats:
            self._chats[key] = self._chat_for(*key)
        return self._chats[key], key[1]

    async def _call(
        self,
        node: str,
        runnable: Any,
        messages: Sequence[BaseMessage],
        estimate: int,
        effort: str | None,
    ) -> Any:
        retries = 0
        bucket = self.bucket_for(node)
        model = self._settings.model_for(node)
        while True:
            await bucket.wait_for(estimate + EXPECTED_OUTPUT_TOKENS)
            started = self._clock()
            try:
                result = await runnable.ainvoke(list(messages))
            except groq.BadRequestError:
                # A rejected request still spent tokens on Groq's side: pace for them and count
                # them, so a run's totals don't hide its failed attempts.
                bucket.record(estimate)
                self.usage.add(
                    CallRecord(
                        node,
                        estimate,
                        0,
                        self._clock() - started,
                        retries,
                        effort,
                        model=model,
                        rejected=True,
                    )
                )
                raise
            except groq.RateLimitError as exc:
                if retries >= self._settings.llm_max_retries:
                    raise LLMError(f"{node}: still rate limited after {retries} retries") from exc
                delay = retry_after(exc) or 2.0**retries
                if delay > self._settings.llm_max_wait_s:
                    # Minutes, not seconds: a daily limit (tokens or requests per day), which no
                    # wait inside one run can fix. Fail now with Groq's reason instead of
                    # sleeping until the run times out.
                    _, message = error_text(exc)
                    raise DailyLimitError(
                        f"{node}: Groq asks to wait {delay:.0f}s: {message}", model, delay, message
                    ) from None
                log.warning("429 on %s; retrying in %.1fs", node, delay)
                retries += 1
                await self._sleep(delay)
                continue
            raw = result["raw"] if isinstance(result, dict) else result
            usage = getattr(raw, "usage_metadata", None) or {}
            details = usage.get("input_token_details") or {}
            record = CallRecord(
                node,
                usage.get("input_tokens", estimate),
                usage.get("output_tokens", 0),
                self._clock() - started,
                retries,
                effort,
                details.get("cache_read") or 0,
                model,
            )
            bucket.record(record.billed_tokens)
            self.usage.add(record)
            return result

    async def invoke_tools(
        self, node: str, messages: Sequence[BaseMessage], tools: list[dict[str, Any]]
    ) -> AIMessage:
        chat, effort = self._chat(node)
        runnable = chat.bind_tools(tools)
        try:
            return await self._call(
                node, runnable, messages, estimate_tokens(messages, tools), effort
            )
        except groq.BadRequestError as exc:
            code, message = error_text(exc)
            # Groq validates tool-call arguments against the schema itself, so a bad argument
            # comes back as a 400 instead of a tool call. The node decides how to recover.
            if code == "tool_use_failed":
                log.warning("%s: tool call rejected by the API", node)
                raise InvalidToolCallError(message) from None
            raise LLMError(f"{node}: request rejected ({code}): {message}") from None

    async def invoke_structured(
        self, node: str, messages: Sequence[BaseMessage], schema: type[T]
    ) -> T:
        chat, effort = self._chat(node)
        runnable = chat.with_structured_output(
            schema, method="json_schema", strict=True, include_raw=True
        )
        attempt = list(messages)
        for _ in range(2):
            error: Any
            try:
                result = await self._call(
                    node, runnable, attempt, estimate_tokens(attempt, None), effort
                )
            except groq.BadRequestError as exc:
                code, message = error_text(exc)
                # Groq checks strict output against the schema itself and rejects a mismatch
                # with json_validate_failed: the same failure as a parse error, so retry it.
                if code != "json_validate_failed":
                    raise LLMError(f"{node}: request rejected ({code}): {message}") from None
                error = message
                # Groq's message names the schema path that failed and never the output.
                log.warning("%s: Groq rejected the output: %s", node, message)
            else:
                parsed = result.get("parsed")
                error = result.get("parsing_error")
                if parsed is not None and error is None:
                    return parsed
                log.warning("%s: output did not parse as %s", node, schema.__name__)
            attempt = [
                *messages,
                HumanMessage(f"Your last answer did not match the schema: {error}. Try again."),
            ]
        raise LLMError(f"{node}: output did not match {schema.__name__} twice")


Scripted = (
    AIMessage
    | BaseModel
    | dict[str, Any]
    | Exception
    | Callable[[Sequence[BaseMessage]], "AIMessage | BaseModel | dict[str, Any]"]
)


class MockLLM:
    """Replays scripted answers per node, in order; the last one repeats once the script
    runs out, so "always call a tool" is a one-item script. An answer can be a function of
    the prompt, for citing a ref the run assigned. Records every prompt and tool list it gets."""

    def __init__(self, script: dict[str, list[Scripted]]) -> None:
        self._script = {node: list(answers) for node, answers in script.items()}
        self.prompts: dict[str, list[list[BaseMessage]]] = defaultdict(list)
        self.tools: dict[str, list[str]] = {}
        self.usage = UsageLog()

    def _next(self, node: str, messages: Sequence[BaseMessage]) -> Scripted:
        self.prompts[node].append(list(messages))
        answers = self._script.get(node)
        if not answers:
            raise LLMError(f"mock has no answer scripted for node {node!r}")
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            answer = answer(messages)
        self.usage.add(CallRecord(node, estimate_tokens(messages, None), 10, 0.0, 0, model="mock"))
        return answer

    async def invoke_tools(
        self, node: str, messages: Sequence[BaseMessage], tools: list[dict[str, Any]]
    ) -> AIMessage:
        self.tools[node] = [t["function"]["name"] for t in tools]
        answer = self._next(node, messages)
        if not isinstance(answer, AIMessage):
            raise TypeError(f"{node}: scripted answer must be an AIMessage")
        # A fresh copy each time: a repeated answer must not reuse tool_call ids.
        calls = [
            c | {"id": f"call_{len(self.prompts[node])}_{i}"}
            for i, c in enumerate(answer.tool_calls)
        ]
        return AIMessage(content=answer.content, tool_calls=calls)

    async def invoke_structured(
        self, node: str, messages: Sequence[BaseMessage], schema: type[T]
    ) -> T:
        answer = self._next(node, messages)
        try:
            return schema.model_validate(answer)
        except ValidationError as exc:
            raise LLMError(f"{node}: scripted answer does not match {schema.__name__}") from exc


def get_model(settings: Settings | None = None) -> GroqLLM:
    """The real model from settings. Tests build a MockLLM directly instead."""
    settings = settings or get_settings()
    if settings.llm_mode == "mock":
        raise LLMError("LLM_MODE=mock: build a MockLLM with a script instead of the real model")
    kwargs: dict[str, Any] = {
        "temperature": 0,
        "max_tokens": settings.llm_max_tokens,
        # Our wrapper does the retrying, so it can respect retry-after and log each attempt.
        "max_retries": 0,
    }
    efforts: dict[str, str] = {}
    if settings.llm_provider == "groq":
        if settings.groq_api_key is None:
            raise LLMError("GROQ_API_KEY is not set in .env")
        kwargs["api_key"] = settings.groq_api_key.get_secret_value()
        # reasoning_effort is a Groq/gpt-oss parameter; other providers get their default.
        efforts = dict(settings.llm_reasoning_effort)

    def chat_for(model: str, effort: str | None) -> BaseChatModel:
        extra = {"reasoning_effort": effort} if effort else {}
        return init_chat_model(model, model_provider=settings.llm_provider, **kwargs, **extra)

    return GroqLLM(chat_for, settings, efforts)
