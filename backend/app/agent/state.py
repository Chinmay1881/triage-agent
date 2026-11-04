"""The investigation state (spec: "The LangGraph agent"), one Pydantic model saved per run.

Phase 3 fills alert context, the plan, the tool conversation, findings and injection flags.
The Phase 4 fields (mappings, verdict, risk, recommendations, report) are declared now so the
shape matches the spec from the start.

Every LLM-written field has a Pydantic model, and the structured-output schemas the nodes ask
for are separate `*Draft` / `*Review` models: what the model may return is narrower than what
the state stores (code adds the tool name, the withheld marker, validation results).
"""

from typing import Annotated, Any, Literal, Self

from langchain_core.messages import AnyMessage
from langgraph.graph import add_messages
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.telemetry.models import Alert

WITHHELD = "[withheld: matched injection pattern]"
MAX_FINDINGS = 15
MAX_CITED = 10
TEXT_CHARS = 300


def keep_first(n: int) -> AfterValidator:
    return AfterValidator(lambda items: items[:n])


# Upper limits on LLM output are applied by trimming, not as schema constraints: Groq's strict
# mode rejects the whole answer when one list is one item too long (a finding citing 11 event
# IDs lost every finding in a run). Only the limits that carry meaning stay in the schema: a
# non-empty text, at least 2 hypotheses, at least one cited event.
EventIdText = Annotated[str, Field(pattern=r"^evt_\d{6}$")]
ShortText = Annotated[str, Field(min_length=1), AfterValidator(lambda s: s[:TEXT_CHARS])]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- what the LLM returns (structured output) ----------------------------------------------


class Hypothesis(_Strict):
    kind: Literal["benign", "malicious"]
    statement: ShortText


class PlanDraft(_Strict):
    hypotheses: Annotated[list[Hypothesis], Field(min_length=2), keep_first(4)]
    first_checks: Annotated[list[ShortText], Field(min_length=1), keep_first(5)]

    @model_validator(mode="after")
    def _has_harmless_hypothesis(self) -> Self:
        # Spec: hypotheses always include a harmless one, so the benign path gets checked.
        if not any(h.kind == "benign" for h in self.hypotheses):
            raise ValueError("at least one hypothesis must be benign")
        return self


class FindingDraft(_Strict):
    claim: ShortText
    event_ids: Annotated[list[EventIdText], Field(min_length=1), keep_first(MAX_CITED)]


class FindingsDraft(_Strict):
    findings: Annotated[list[FindingDraft], keep_first(MAX_FINDINGS)]


class CriticReview(_Strict):
    harmless_explanation_ruled_out: bool
    missing_checks: Annotated[list[ShortText], keep_first(3)]
    reopen: bool
    reason: ShortText


# --- what the state stores -----------------------------------------------------------------


class Finding(_Strict):
    claim: str
    event_ids: list[str]
    tool: str
    # Which detectors the claim tripped (regex family names, "classifier"). Such a claim is kept
    # for the record, but prompts and the CLI show WITHHELD instead, so log text can't leave
    # untrusted_log_data through a claim. The names make false positives diagnosable without
    # printing the text.
    withheld_by: list[str] = []

    @property
    def withheld(self) -> bool:
        return bool(self.withheld_by)

    def shown_claim(self) -> str:
        return WITHHELD if self.withheld else self.claim


class InjectionFlag(_Strict):
    event_id: str | None
    field: str
    method: Literal["regex", "classifier"]
    score: float


class ToolCallRecord(_Strict):
    name: str
    args: dict[str, Any]
    ok: bool
    error: str | None = None
    event_ids: int = 0


class AttackMapping(_Strict):
    technique_id: str
    name: str
    tactics: list[str]
    event_ids: list[str]
    rationale: str


Action = Literal[
    "isolate_host",
    "disable_account",
    "reset_password",
    "block_indicator",
    "collect_forensics",
    "escalate",
    "close_as_benign",
]


class Recommendation(_Strict):
    action: Action
    target: str
    reason: str
    # Hard rule 7: nothing is executed; every recommendation waits for a human.
    requires_approval: Literal[True] = True


class AgentState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    alert: Alert
    host_info: dict[str, Any] | None = None
    user_info: dict[str, Any] | None = None
    trigger_events: list[dict[str, Any]] = []

    hypotheses: list[Hypothesis] = []
    first_checks: list[str] = []
    messages: Annotated[list[AnyMessage], add_messages] = []

    findings: list[Finding] = []
    findings_dropped: int = 0
    seen_event_ids: dict[str, str] = {}
    tool_calls_used: int = 0
    tool_log: list[ToolCallRecord] = []
    reopened: int = 0
    # Minimum-investigation rules that sent the run back (check_coverage), in order.
    coverage_nudges: list[str] = []
    critic: CriticReview | None = None
    injection_flags: list[InjectionFlag] = []
    stop_reason: str | None = None

    attack_mappings: list[AttackMapping] = []
    mapping_errors: list[str] = []
    mapping_retries: int = 0
    verdict: Literal["malicious", "suspicious", "benign"] | None = None
    confidence: float | None = None
    risk_score: int | None = None
    risk_factors: dict[str, Any] = {}
    recommendations: list[Recommendation] = []
    report_md: str | None = None
