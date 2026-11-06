from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Effort = Literal["low", "medium", "high"]

# One .env at the repo root is shared by docker compose and the backend.
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

SENTINEL_TRIAGE = "Sentinel-Triage"
CYBERINTEL = "CyberIntel-Agent"
INVESTIGATOR = "Investigator-Agent"
REVIEWER = "Reviewer-Agent"
# Step 5 of the flow: not a fifth agent but the code-checked closing stage after review.
REPORT_AND_REVIEW = "Report & Human Review"
# Which agent each LLM-calling node belongs to, for per-agent models and token accounting.
NODE_AGENT: dict[str, str] = {
    "triage": SENTINEL_TRIAGE,
    "intel": CYBERINTEL,
    "intel_brief": CYBERINTEL,
    "plan": INVESTIGATOR,
    "investigate": INVESTIGATOR,
    "summarize_findings": INVESTIGATOR,
    "review": REVIEWER,
    "review_verdict": REVIEWER,
    "map_attack": REPORT_AND_REVIEW,
    "assess": REPORT_AND_REVIEW,
    "recommend": REPORT_AND_REVIEW,
    "report_summary": REPORT_AND_REVIEW,
}


class Settings(BaseSettings):
    # extra="ignore": .env also holds compose-only values (MONGO_ROOT_*, user passwords).
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    groq_api_key: SecretStr | None = None
    llm_provider: str = "groq"
    # The model of every agent not listed in agent_models. Env LLM_MODEL overrides it, which is
    # how a smoke test moves the investigator and the reviewer to gpt-oss-20b.
    llm_model: str = "openai/gpt-oss-120b"
    # Env AGENT_MODELS: a JSON object.
    agent_models: dict[str, str] = {
        SENTINEL_TRIAGE: "openai/gpt-oss-20b",
        CYBERINTEL: "openai/gpt-oss-20b",
        REPORT_AND_REVIEW: "openai/gpt-oss-20b",
    }
    # Nodes that use llm_model whatever their agent's model is: assess is the judgement call,
    # while code checks protect the other closing steps.
    main_model_nodes: list[str] = ["assess"]
    llm_mode: Literal["real", "mock"] = "real"
    # Per node: the nodes that decide what to check or judge the evidence think harder; the ones
    # that write structure from given material stay cheap. Reasoning tokens count against the
    # per-minute limit. Env LLM_REASONING_EFFORT: a JSON object.
    llm_reasoning_effort: dict[str, Effort] = {
        "triage": "low",
        "intel": "low",
        "intel_brief": "low",
        "plan": "low",
        "investigate": "medium",
        "summarize_findings": "low",
        "review": "medium",
        "review_verdict": "medium",
        "map_attack": "low",
        "assess": "medium",
        "recommend": "low",
        "report_summary": "low",
    }
    llm_max_tokens: int = 2048
    # Groq free tier for the gpt-oss models: 8,000 tokens a minute, per model
    # (x-ratelimit-limit-tokens), so each model gets its own bucket.
    llm_tpm_limit: int = 8000
    llm_max_retries: int = 5
    # A 429 asking for a longer wait is a daily limit, not the per-minute one: fail fast.
    llm_max_wait_s: float = 120.0

    # Agent loop bounds (hard rule 8). The investigator's budget comes from Sentinel-Triage's
    # priority and counts across a reviewer reopen.
    investigator_budgets: dict[str, int] = {"P1": 12, "P2": 10, "P3": 8, "P4": 8}
    intel_tool_calls: int = 4
    reviewer_tool_calls: int = 3
    mapping_retries: int = 2
    run_timeout_s: int = 900
    recursion_limit: int = 80

    # Code-run lookups (no LLM choice, no token cost beyond the brief), capped so a noisy
    # process tree can't turn into hundreds of calls.
    intel_max_indicators: int = 20
    intel_max_hosts_users: int = 6
    intel_max_anomaly_events: int = 20
    auto_reputation_per_call: int = 5
    # Exact repeat calls are answered from the ledger for free this many times per agent, then
    # they cost budget again, so a model repeating itself can't loop on free calls (hard rule 8).
    free_repeats_per_agent: int = 3

    # Models POST /investigations may ask for.
    api_models: list[str] = [
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "qwen/qwen3.8-27b",
    ]
    # The API refuses blocklisted alerts unless this is on (the eval harness, a demo).
    allow_blocked_alerts: bool = False

    # SecretStr because the URIs embed passwords; they never show up in logs or reprs.
    telemetry_mongo_uri: SecretStr
    triage_mongo_uri: SecretStr

    def model_for(self, node: str) -> str:
        if node in self.main_model_nodes:
            return self.llm_model
        return self.agent_models.get(NODE_AGENT.get(node, ""), self.llm_model)


@lru_cache
def get_settings() -> Settings:
    return Settings()
