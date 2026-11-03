from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# One .env at the repo root is shared by docker compose and the backend.
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    # extra="ignore": .env also holds compose-only values (MONGO_ROOT_*, user passwords).
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    groq_api_key: SecretStr | None = None
    llm_provider: str = "groq"
    llm_model: str = "openai/gpt-oss-120b"
    llm_mode: Literal["real", "mock"] = "real"

    # SecretStr because the URIs embed passwords; they never show up in logs or reprs.
    telemetry_mongo_uri: SecretStr
    triage_mongo_uri: SecretStr


@lru_cache
def get_settings() -> Settings:
    return Settings()
