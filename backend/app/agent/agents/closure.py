"""Report & Human Review: step 5 of the flow, after the reviewer concludes.

    map_attack <-> validate_mapping -> assess -> score -> recommend -> report

It sees only reportable_findings(), so disputed findings can't reach a mapping, a verdict or the
report. The LLM proposes; code decides what stands. The verdict can only move towards caution, and
if a model call fails the run still finishes, never with a benign verdict: a failed assess gives
suspicious at confidence 0, a failed recommend gives escalate, and a failed summary a written one.
Nothing is executed: the run ends waiting for the analyst.
"""

import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from app.agent.agents.common import alert_block, handoff, to_json
from app.agent.agents.reviewer import event_row
from app.agent.case import (
    MAX_RECOMMENDATIONS,
    WITHHELD,
    AssessDraft,
    AttackMapping,
    Case,
    Finding,
    MappingDraft,
    MappingsDraft,
    Recommendation,
    RecommendationDraft,
    RecommendationsDraft,
    SummaryDraft,
)
from app.agent.deps import Deps
from app.agent.grounding import event_entities
from app.agent.injection import regex_hits, screen
from app.agent.prompts.closure import ASSESS, MAP_ATTACK, RECOMMEND, REPORT_SUMMARY
from app.agent.prompts.system import SYSTEM
from app.agent.report import render_report
from app.agent.scoring import risk_score
from app.attack.catalog import get_catalog
from app.config import REPORT_AND_REVIEW
from app.llm import LLMError

log = logging.getLogger(__name__)

MAX_TIMELINE = 20
EVENT_ID = re.compile(r"evt_\d{6}")
SENTENCE = re.compile(r"(?<=[.!?])\s+")
NO_SUPPORT = (
    "benign changed to suspicious: no confirmed finding supporting the harmless hypothesis cites "
    "the trigger, its parent, a child, or an entity in the intel brief"
)
INJECTION_AND_BAD = (
    "benign not allowed: an injection flag exists and an indicator is known_bad; "
    "changed to suspicious"
)
LOW_CONFIDENCE_AFTER_CHANGE = 0.5


# --- validate_mapping ------------------------------------------------------------------------


def validate_mappings(
    drafts: list[MappingDraft], allowed_events: set[str]
) -> tuple[list[AttackMapping], list[str]]:
    """Mappings that stand, with name and tactics from the pinned bundle, and the errors of the
    rest. A mapping keeps only event IDs from reportable findings and needs at least one."""
    catalog = get_catalog()
    valid: dict[str, AttackMapping] = {}
    errors = []
    for draft in drafts:
        technique = catalog.get_technique(draft.technique_id)
        if technique is None:
            errors.append(f"{draft.technique_id} is not a technique in ATT&CK v20")
            continue
        if technique.revoked or technique.deprecated:
            status = "revoked" if technique.revoked else "deprecated"
            errors.append(f"{draft.technique_id} is {status}; use its current replacement")
            continue
        cited = [e for e in draft.event_ids if e in allowed_events]
        unknown = [e for e in draft.event_ids if e not in allowed_events]
        if unknown:
            errors.append(f"{draft.technique_id} cites events not in the findings: {unknown}")
        if not cited:
            continue
        if technique.id in valid:
            merged = valid[technique.id].event_ids + cited
            valid[technique.id].event_ids = list(dict.fromkeys(merged))
            continue
        valid[technique.id] = AttackMapping(
            technique_id=technique.id,
            name=technique.name,
            tactics=technique.tactics,
            event_ids=cited,
            rationale=draft.rationale,
        )
    return list(valid.values()), errors


# --- assess ----------------------------------------------------------------------------------


def brief_anchors(case: Case) -> tuple[set[str], set[str]]:
    """Event IDs of the trigger, parent and children, and the entities listed in the brief."""
    events = set(case.alert.trigger_event_ids)
    entities: set[str] = set()
    brief = case.intel_brief
    if brief is None:
        return events, entities
    for row in brief.process_chain:
        if row.get("event_id"):
            events.add(row["event_id"])
        entities |= {str(row[k]).lower() for k in ("name", "sha256") if row.get(k)}
    entities |= {str(r["indicator"]).lower() for r in brief.reputation if r.get("indicator")}
    entities |= {str(h["hostname"]).lower() for h in brief.hosts if h.get("hostname")}
    entities |= {str(u["username"]).lower() for u in brief.users if u.get("username")}
    return events, entities


def supports_harmless(finding: Finding, case: Case, docs: dict[str, dict[str, Any]]) -> bool:
    """A finding may support a benign verdict only if it is confirmed and tied to the case: it
    cites the trigger, its parent, a child, or an entity listed in the intel brief."""
    if finding.status != "confirmed":
        return False
    anchor_events, anchor_entities = brief_anchors(case)
    for citation in finding.citations:
        if citation in anchor_events:
            return True
        doc = docs.get(citation)
        if doc is not None:
            labels = case.evidence.event_labels.get(citation, [])
            if {e.lower() for e in event_entities(doc, labels)} & anchor_entities:
                return True
        info = case.evidence.tool_refs.get(citation)
        if info is not None and {e.lower() for e in info.entities} & anchor_entities:
            return True
    return False


def apply_verdict_rules(
    draft: AssessDraft, case: Case, docs: dict[str, dict[str, Any]]
) -> tuple[str, float, list[str]]:
    """The verdict that stands, its confidence and why it changed. Only benign is ever changed."""
    if draft.verdict != "benign":
        return draft.verdict, draft.confidence, []
    notes = []
    by_id = {f.id: f for f in case.findings}
    supporting = [by_id[i] for i in draft.supporting_benign if i in by_id]
    if not any(supports_harmless(f, case, docs) for f in supporting):
        notes.append(NO_SUPPORT)
    known_bad = [i for i, rep in case.evidence.reputations.items() if rep == "known_bad"]
    if case.evidence.injection_flags and known_bad:
        notes.append(INJECTION_AND_BAD)
    if notes:
        return "suspicious", min(draft.confidence, LOW_CONFIDENCE_AFTER_CHANGE), notes
    return "benign", draft.confidence, []


def asset_criticality(case: Case) -> int | None:
    brief = case.intel_brief
    if brief is None:
        return None
    for host in brief.hosts:
        if host.get("hostname") == case.alert.host:
            return host.get("criticality")
    return None


# --- recommend -------------------------------------------------------------------------------


def allowed_targets(case: Case) -> dict[str, set[str]]:
    """Entities each action may target, all taken from the case, compared case-insensitively."""
    hosts, users, indicators = {case.alert.host.lower()}, set(), set()
    if case.alert.user:
        users.add(case.alert.user.lower())
    brief = case.intel_brief
    if brief is not None:
        hosts |= {str(h["hostname"]).lower() for h in brief.hosts if h.get("hostname")}
        users |= {str(u["username"]).lower() for u in brief.users if u.get("username")}
    indicators |= {i.lower() for i in case.evidence.reputations}
    return {
        "isolate_host": hosts,
        "collect_forensics": hosts,
        "disable_account": users,
        "reset_password": users,
        "block_indicator": indicators,
    }


def check_recommendations(
    drafts: list[RecommendationDraft], case: Case
) -> tuple[list[Recommendation], list[str]]:
    targets = allowed_targets(case)
    kept: list[Recommendation] = []
    notes = []
    seen = set()
    for draft in drafts[:MAX_RECOMMENDATIONS]:
        key = (draft.action, draft.target.lower())
        if key in seen:
            continue
        seen.add(key)
        if draft.action == "close_as_benign" and case.verdict != "benign":
            notes.append(f"Dropped close_as_benign: the verdict is {case.verdict}.")
            continue
        allowed = targets.get(draft.action)
        if allowed is not None and draft.target.lower() not in allowed:
            notes.append(f"Dropped {draft.action}: its target is not an entity in this case.")
            continue
        kept.append(
            Recommendation(
                id=f"A{len(kept) + 1}",
                action=draft.action,
                target=draft.target,
                reason=draft.reason,
            )
        )
    return kept, notes


def fallback_recommendation(reason: str) -> Recommendation:
    return Recommendation(id="A1", action="escalate", target="SOC analyst", reason=reason)


# --- report ----------------------------------------------------------------------------------


def checked_summary(text: str, allowed_events: set[str]) -> tuple[str, list[str]]:
    """Drops sentences citing an event ID outside the reportable findings, as text the code can't
    stand behind. Returns the summary and notes for Limitations."""
    kept, notes = [], []
    for sentence in SENTENCE.split(text.strip()):
        unknown = sorted(set(EVENT_ID.findall(sentence)) - allowed_events)
        if unknown:
            notes.append(f"A summary sentence citing {', '.join(unknown)} was removed.")
        else:
            kept.append(sentence)
    return " ".join(kept), notes


def written_summary(case: Case) -> str:
    """Used when the model's summary is missing, or nothing of it survives the checks."""
    findings = case.reportable_findings()
    return (
        f"{case.alert.rule} on {case.alert.host}. Verdict: {case.verdict} (risk "
        f"{case.risk_score}), from {len(findings)} reportable finding(s). "
        "This summary was written by code: the model's was unavailable."
    )


def timeline_rows(docs: list[dict[str, Any]], flagged: set[str]) -> list[dict[str, Any]]:
    """Key events in time order. A row with an injection flag loses its log text: the report must
    not repeat what the logs tried to tell an AI."""
    rows = []
    for doc in sorted(docs, key=lambda d: (d["ts"], d["event_id"]))[:MAX_TIMELINE]:
        row = event_row(doc)
        if doc["event_id"] in flagged:
            row["target"] = WITHHELD
        rows.append(row)
    return rows


def findings_block(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "id": f.id,
            "status": f.status,
            "kind": f.kind,
            "claim": f.shown_claim(),
            "citations": f.citations,
        }
        for f in findings
    ]


def make_closure(deps: Deps) -> dict[str, Callable[[Case], Awaitable[dict[str, Any]]]]:
    llm = deps.llm

    def allowed_events(state: Case) -> set[str]:
        return {e for f in state.reportable_findings() for e in f.event_ids}

    async def map_attack(state: Case) -> dict[str, Any]:
        findings = [f for f in state.reportable_findings() if f.event_ids]
        if not findings:
            return {"mapping_drafts": []}
        prompt = {
            "findings": [
                {"id": f.id, "claim": f.shown_claim(), "event_ids": f.event_ids} for f in findings
            ],
            "errors": state.mapping_errors,
        }
        messages = [
            SystemMessage(f"{SYSTEM}\n\n{MAP_ATTACK}"),
            HumanMessage(to_json(prompt)),
        ]
        try:
            draft = await llm.invoke_structured("map_attack", messages, MappingsDraft)
        except LLMError as exc:
            log.warning("map_attack failed: %s", exc)
            return {
                "mapping_drafts": [],
                "closure_notes": [*state.closure_notes, "ATT&CK mapping failed: a model error."],
            }
        return {"mapping_drafts": draft.mappings}

    async def validate_mapping(state: Case) -> dict[str, Any]:
        valid, errors = validate_mappings(state.mapping_drafts, allowed_events(state))
        merged = {m.technique_id: m for m in [*state.attack_mappings, *valid]}
        update: dict[str, Any] = {
            "attack_mappings": list(merged.values()),
            "mapping_errors": errors,
            "mapping_rejections": [*state.mapping_rejections, *errors],
            "mapping_drafts": [],
        }
        if errors and state.mapping_retries < deps.settings.mapping_retries:
            log.info(
                "mapping rejected, retry %d: %d error(s)", state.mapping_retries + 1, len(errors)
            )
            return update | {"mapping_retries": state.mapping_retries + 1, "mapping_retry": True}
        notes = [f"ATT&CK mapping dropped: {e}" for e in errors]
        return update | {"mapping_retry": False, "closure_notes": [*state.closure_notes, *notes]}

    async def assess(state: Case) -> dict[str, Any]:
        findings = state.reportable_findings()
        known_bad = [i for i, r in state.evidence.reputations.items() if r == "known_bad"]
        statements = screen([h.statement for h in state.hypotheses])
        prompt = {
            "alert": alert_block(state.alert),
            "triage": state.triage.model_dump(exclude={"anomaly"}) if state.triage else None,
            "hypotheses": [
                {"kind": h.kind, "statement": s}
                for h, s in zip(state.hypotheses, statements, strict=True)
            ],
            "findings": findings_block(findings),
            "techniques": [
                {"id": m.technique_id, "name": m.name, "tactics": m.tactics}
                for m in state.attack_mappings
            ],
            "injection_flags": len(state.evidence.injection_flags),
            "untrusted_log_data": {"known_bad_indicators": known_bad},
        }
        messages = [SystemMessage(f"{SYSTEM}\n\n{ASSESS}"), HumanMessage(to_json(prompt))]
        try:
            draft = await llm.invoke_structured("assess", messages, AssessDraft)
        except LLMError as exc:
            log.warning("assess failed: %s", exc)
            note = "The verdict is suspicious because the assessment call failed."
            return {
                "verdict": "suspicious",
                "confidence": 0.0,
                "verdict_notes": [note],
            }
        cited = sorted({c for f in findings for c in f.event_ids})
        docs = {d["event_id"]: d for d in await deps.telemetry.events(cited)}
        verdict, confidence, notes = apply_verdict_rules(draft, state, docs)
        for note in notes:
            log.warning("verdict rule: %s", note)
        (reasoning,) = screen([draft.reasoning])
        return {
            "verdict_proposed": draft.verdict,
            "verdict": verdict,
            "confidence": confidence,
            "verdict_reasoning": reasoning,
            "verdict_notes": notes,
        }

    async def score(state: Case) -> dict[str, Any]:
        tactics = [t for m in state.attack_mappings for t in m.tactics]
        priority = state.triage.priority if state.triage else "P2"
        factors = risk_score(
            state.verdict or "suspicious",
            state.confidence or 0.0,
            priority,
            asset_criticality(state),
            tactics,
        )
        return {"risk_score": factors["score"], "risk_factors": factors}

    async def recommend(state: Case) -> dict[str, Any]:
        targets = {k: sorted(v) for k, v in allowed_targets(state).items()}
        prompt = {
            "alert": alert_block(state.alert),
            "verdict": state.verdict,
            "risk_score": state.risk_score,
            "findings": findings_block(state.reportable_findings()),
            "untrusted_log_data": {"targets": targets},
        }
        messages = [SystemMessage(f"{SYSTEM}\n\n{RECOMMEND}"), HumanMessage(to_json(prompt))]
        try:
            draft = await llm.invoke_structured("recommend", messages, RecommendationsDraft)
        except LLMError as exc:
            log.warning("recommend failed: %s", exc)
            fallback = fallback_recommendation("The recommendation call failed; a human must look.")
            return {"recommendations": [fallback]}
        kept, notes = check_recommendations(draft.recommendations, state)
        if not kept:
            kept = [fallback_recommendation("No valid recommendation survived the checks.")]
        return {"recommendations": kept, "closure_notes": [*state.closure_notes, *notes]}

    async def report(state: Case) -> dict[str, Any]:
        reportable = state.reportable_findings()
        allowed = allowed_events(state)
        wanted = list(dict.fromkeys([*state.alert.trigger_event_ids, *sorted(allowed)]))
        docs = await deps.telemetry.events(wanted)
        flagged = {f.event_id for f in state.evidence.injection_flags if f.event_id}
        timeline = timeline_rows(docs, flagged)
        prompt = {
            "alert": alert_block(state.alert),
            "verdict": state.verdict,
            "confidence": state.confidence,
            "risk_score": state.risk_score,
            "findings": findings_block(reportable),
            "techniques": [m.technique_id for m in state.attack_mappings],
        }
        messages = [
            SystemMessage(f"{SYSTEM}\n\n{REPORT_SUMMARY}"),
            HumanMessage(to_json(prompt)),
        ]
        notes = list(state.closure_notes)
        summary = ""
        try:
            draft = await llm.invoke_structured("report_summary", messages, SummaryDraft)
            summary, removed = checked_summary(draft.summary, allowed)
            notes += removed
            if regex_hits(summary):
                notes.append("The model's summary matched an injection pattern and was replaced.")
                summary = ""
        except LLMError as exc:
            log.warning("report summary failed: %s", exc)
            notes.append("The summary was written by code because the model call failed.")
        written = state.model_copy(
            update={
                "timeline": timeline,
                "report_summary": summary or written_summary(state),
                "closure_notes": notes,
            }
        )
        return {
            "timeline": written.timeline,
            "report_summary": written.report_summary,
            "closure_notes": notes,
            "report_md": render_report(written, []),
            "stop_reason": state.stop_reason or "complete",
            "token_use": llm.usage.by_agent(),
            "handoffs": [
                *state.handoffs,
                handoff(REPORT_AND_REVIEW, "analyst", "awaiting decision"),
            ],
        }

    return {
        "map_attack": map_attack,
        "validate_mapping": validate_mapping,
        "assess": assess,
        "score": score,
        "recommend": recommend,
        "report": report,
    }
