from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Effort = Literal["low", "medium", "high"]

# One .env at the repo root is shared by docker compose and the backend.
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    # extra="ignore": .env also holds compose-only values (MONGO_ROOT_*, user passwords).
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    groq_api_key: SecretStr | None = None
    llm_provider: str = "groq"
    llm_model: str = "openai/gpt-oss-120b"
    llm_mode: Literal["real", "mock"] = "real"
    # Per node: the nodes that decide what to check (investigate, critic) think harder; the
    # ones that write structure from given material (plan, summarize_findings) stay cheap.
    # Reasoning tokens count against the per-minute limit. Env: a JSON object.
    llm_reasoning_effort: dict[str, Effort] = {
        "plan": "low",
        "investigate": "medium",
        "summarize_findings": "low",
        "critic": "medium",
    }
    llm_max_tokens: int = 2048
    # Groq free tier for gpt-oss-120b: 8,000 tokens a minute (x-ratelimit-limit-tokens).
    llm_tpm_limit: int = 8000
    llm_max_retries: int = 5
    # A 429 asking for a longer wait is a daily limit, not the per-minute one: fail fast.
    llm_max_wait_s: float = 120.0

    # Agent loop bounds (hard rule 8).
    tool_budget: int = 12
    run_timeout_s: int = 900
    recursion_limit: int = 60

    # SecretStr because the URIs embed passwords; they never show up in logs or reprs.
    telemetry_mongo_uri: SecretStr
    triage_mongo_uri: SecretStr


@lru_cache
def get_settings() -> Settings:
    return Settings()
