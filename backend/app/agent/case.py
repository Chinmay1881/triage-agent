"""The Case: the one model passed along the agent chain (spec: "The agent chain").

Sentinel-Triage fills `triage`, CyberIntel-Agent `intel_brief`, Investigator-Agent `findings`,
Reviewer-Agent `review`. Every agent appends to the handoff log, its own tool log, and the
shared evidence ledger. The Phase 4 fields (mappings, verdict, risk, recommendations, report)
are declared now so the shape matches the spec from the start.

The structured-output schemas are separate `*Draft` models: what the model may return is
narrower than what the Case stores (code adds statuses, tool names and validation results).
"""

from typing import Annotated, Any, Literal, Self

from langchain_core.messages import AnyMessage
from langgraph.graph import add_messages
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.telemetry.models import Alert, UtcDatetime

WITHHELD = "[withheld: matched injection pattern]"
MAX_FINDINGS = 8
MAX_CITED = 10
TEXT_CHARS = 300

Priority = Literal["P1", "P2", "P3", "P4"]
Category = Literal["endpoint", "identity", "network", "data"]
FindingKind = Literal["observation", "absence"]
FindingStatus = Literal["pending", "confirmed", "unreviewed", "disputed"]


def keep_first(n: int) -> AfterValidator:
    return AfterValidator(lambda items: items[:n])


# Upper limits and formats on LLM output are enforced in code, not as schema constraints: Groq's
# strict mode rejects the whole answer over one list item too many or one badly formed citation.
# A finding citing 11 event IDs once cost a run all its findings; the baseline's s01 lost them
# the same way. Only the limits that carry meaning stay in the schema: at least 2 hypotheses.
ShortText = Annotated[str, AfterValidator(lambda s: s[:TEXT_CHARS])]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- what the LLM returns (structured output) ----------------------------------------------


class TriageDraft(_Strict):
    priority: Priority
    category: Category
    reason: ShortText


class IntelDraft(_Strict):
    assessment: ShortText
    notable: Annotated[list[ShortText], keep_first(5)]


class Hypothesis(_Strict):
    kind: Literal["benign", "malicious"]
    statement: ShortText


class PlanDraft(_Strict):
    hypotheses: Annotated[list[Hypothesis], Field(min_length=2), keep_first(4)]
    first_checks: Annotated[list[ShortText], keep_first(5)]

    @model_validator(mode="after")
    def _has_harmless_hypothesis(self) -> Self:
        # Spec: hypotheses always include a harmless one, so the benign path gets checked.
        if not any(h.kind == "benign" for h in self.hypotheses):
            raise ValueError("at least one hypothesis must be benign")
        return self


class FindingDraft(_Strict):
    claim: ShortText
    kind: FindingKind
    # Event IDs ("evt_000123") or tool results ("tool:get_host_info#3"), checked by grounding.py.
    citations: Annotated[list[str], keep_first(MAX_CITED)]


class FindingsDraft(_Strict):
    findings: Annotated[list[FindingDraft], keep_first(MAX_FINDINGS)]


class ConfirmDraft(_Strict):
    finding: str
    # The ref of the reviewer's own tool call that verifies it; required for absence findings.
    verified_by: str


class DisputeDraft(_Strict):
    finding: str
    reason: ShortText


class ReviewDraft(_Strict):
    confirmed: list[ConfirmDraft]
    disputed: list[DisputeDraft]
    reopen: bool
    missing_checks: Annotated[list[ShortText], keep_first(3)]
    reason: ShortText


# --- what the Case stores ------------------------------------------------------------------


class TriageDecision(_Strict):
    priority: Priority
    category: Category
    reason: str
    anomaly: list[dict[str, Any]] = []


class IntelBrief(_Strict):
    """`facts` are written by code from tool results, so the model can't invent or forget one.
    Only `assessment` and `notable` are LLM-written."""

    process_chain: list[dict[str, Any]] = []
    reputation: list[dict[str, Any]] = []
    hosts: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []
    anomaly: list[dict[str, Any]] = []
    assessment: str = ""
    notable: list[str] = []

    def facts(self) -> dict[str, Any]:
        return {
            "process_chain": self.process_chain,
            "reputation": self.reputation,
            "hosts": self.hosts,
            "users": self.users,
            "anomaly": self.anomaly,
        }


class Finding(_Strict):
    id: str
    claim: str
    kind: FindingKind
    citations: list[str]
    tool: str
    status: FindingStatus = "pending"
    dispute_reason: str | None = None
    # Which regex families the claim tripped. Such a claim is kept for the record, but prompts
    # and the CLI show WITHHELD instead, so log text can't leave untrusted_log_data through a
    # claim. The names make false positives diagnosable without printing the text.
    withheld_by: list[str] = []

    @property
    def withheld(self) -> bool:
        return bool(self.withheld_by)

    @property
    def event_ids(self) -> list[str]:
        return [c for c in self.citations if c.startswith("evt_")]

    def shown_claim(self) -> str:
        return WITHHELD if self.withheld else self.claim


class InjectionFlag(_Strict):
    event_id: str | None
    field: str
    method: Literal["regex", "classifier"]
    score: float


ToolSource = Literal["llm", "code", "intel_rule"]


class ToolCallRecord(_Strict):
    ref: str
    agent: str
    name: str
    args: dict[str, Any]
    ok: bool
    error: str | None = None
    event_ids: int = 0
    source: ToolSource = "llm"
    # run_tools filled in the alert time +-2 h because the call gave no window.
    defaulted_window: bool = False
    # An exact repeat answered from the ledger: no tool ran. Free up to a per-agent cap.
    repeat_of: str | None = None
    charged: bool = True


class ToolRef(_Strict):
    """What a `tool:name#n` citation points at."""

    tool: str
    ok: bool
    entities: list[str] = []
    args: dict[str, Any] = {}
    # A short view of the result, for the reviewer. Log content: goes under untrusted_log_data.
    digest: str = ""


class StoredAnswer(_Strict):
    ref: str
    agent: str
    result: dict[str, Any]


class Evidence(_Strict):
    """The ledger every agent's tool calls write to, and citation checks read."""

    calls: int = 0
    # Event ID -> the first agent tool that returned it. Findings may only cite these.
    seen_event_ids: dict[str, str] = {}
    # Event ID -> domains a tool resolved for it: a connection event only holds the IP.
    event_labels: dict[str, list[str]] = {}
    tool_refs: dict[str, ToolRef] = {}
    # sha256 -> process or file names seen with it, so a claim can name the file.
    aliases: dict[str, list[str]] = {}
    looked_up: list[str] = []
    # Successful calls by tool and arguments, to answer exact repeats without running them again.
    answers: dict[str, StoredAnswer] = {}
    free_repeats: dict[str, int] = {}
    injection_flags: list[InjectionFlag] = []


class Handoff(_Strict):
    from_agent: str
    to_agent: str
    ts: UtcDatetime
    note: str = ""


class Dispute(_Strict):
    finding: str
    reason: str


class Review(_Strict):
    confirmed: list[str] = []
    disputed: list[Dispute] = []
    unreviewed: list[str] = []
    reopen_requested: bool = False
    reason: str = ""
    passes: int = 0


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


class Case(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    alert: Alert
    trigger_events: list[dict[str, Any]] = []
    triage: TriageDecision | None = None
    intel_brief: IntelBrief | None = None
    findings: list[Finding] = []
    review: Review | None = None

    tool_logs: dict[str, list[ToolCallRecord]] = {}
    token_use: dict[str, dict[str, int]] = {}
    handoffs: list[Handoff] = []
    evidence: Evidence = Evidence()

    # Investigator-Agent's working state; other agents build their prompts from the fields above.
    investigator_budget: int = 0
    budget_reason: str = ""
    tool_calls_used: int = 0
    hypotheses: list[Hypothesis] = []
    first_checks: list[str] = []
    messages: Annotated[list[AnyMessage], add_messages] = []
    coverage_nudges: list[str] = []
    # Findings dropped for citing unseen or ungrounded evidence, and single citations removed.
    findings_dropped: int = 0
    citations_removed: int = 0

    review_calls_used: int = 0
    reopened: int = 0
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

    def reportable_findings(self) -> list[Finding]:
        """What the report may use: confirmed findings, and observations that passed grounding
        but the reviewer didn't list (status "unreviewed", shown as such). Disputed findings
        never get here. The only way later phases read findings."""
        return [f for f in self.findings if f.status in ("confirmed", "unreviewed")]
