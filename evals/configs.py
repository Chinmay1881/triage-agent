"""What an eval run is set up with: a config (the model per agent) and a tier (Groq's limits).

EVAL_TIER=free|paid picks the tier and nothing else needs changing. Each tier's numbers can be
overridden in .env. Tiers apply only to the harness: the API and the CLI keep their own settings.
"""

from dataclasses import dataclass
from typing import Any, Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import (
    CYBERINTEL,
    ENV_FILE,
    NODE_AGENT,
    REPORT_AND_REVIEW,
    SENTINEL_TRIAGE,
    Settings,
)

BIG_MODEL = "openai/gpt-oss-120b"
SMALL_MODEL = "openai/gpt-oss-20b"


@dataclass(frozen=True)
class Tier:
    name: str
    tpm_limit: int
    daily_tokens: int
    # Off: the spend log is still written, but nothing stops a run in advance. A daily-limit 429
    # still ends the batch cleanly whatever this says.
    enforce_daily: bool


class EvalSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    eval_tier: Literal["free", "paid"] = "free"
    eval_free_tpm_limit: int = 8000
    eval_free_daily_tokens: int = 200_000
    eval_free_enforce_daily: bool = True
    # Groq's public pages don't confirm the Developer tier's limits: check the console's limits
    # page and set these. A limit set too high only costs short 429 retries.
    eval_paid_tpm_limit: int = 250_000
    eval_paid_daily_tokens: int = 200_000
    eval_paid_enforce_daily: bool = False

    def tier(self) -> Tier:
        if self.eval_tier == "paid":
            return Tier(
                "paid",
                self.eval_paid_tpm_limit,
                self.eval_paid_daily_tokens,
                self.eval_paid_enforce_daily,
            )
        return Tier(
            "free",
            self.eval_free_tpm_limit,
            self.eval_free_daily_tokens,
            self.eval_free_enforce_daily,
        )


@dataclass(frozen=True)
class EvalConfig:
    name: str
    # Set in full, so an LLM_MODEL or AGENT_MODELS left in .env can't change what a config means.
    models: dict[str, Any]

    def settings(self, base: Settings, tier: Tier) -> Settings:
        # allow_blocked_alerts is on only in this copy: s12 runs here and nowhere else.
        return base.model_copy(
            update=self.models | {"llm_tpm_limit": tier.tpm_limit, "allow_blocked_alerts": True}
        )

    def model_names(self, base: Settings, tier: Tier) -> set[str]:
        settings = self.settings(base, tier)
        return {settings.model_for(node) for node in NODE_AGENT}


CONFIGS = {
    "default": EvalConfig(
        "default",
        {
            "llm_model": BIG_MODEL,
            "agent_models": {
                SENTINEL_TRIAGE: SMALL_MODEL,
                CYBERINTEL: SMALL_MODEL,
                REPORT_AND_REVIEW: SMALL_MODEL,
            },
            "main_model_nodes": ["assess"],
        },
    ),
    "small": EvalConfig(
        "small",
        {"llm_model": SMALL_MODEL, "agent_models": {}, "main_model_nodes": []},
    ),
}
