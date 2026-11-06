"""Report & Human Review with a scripted MockLLM: mapping and its retries, the verdict rules,
recommendations and the report. The LLM proposes; these tests are about what code lets stand."""

from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from app.agent.agents.closure import (
    NO_SUPPORT,
    apply_verdict_rules,
    check_recommendations,
    checked_summary,
    supports_harmless,
    timeline_rows,
    validate_mappings,
)
from app.agent.case import (
    AssessDraft,
    Case,
    Evidence,
    Finding,
    InjectionFlag,
    IntelBrief,
    MappingDraft,
    Recommendation,
    RecommendationDraft,
    ToolRef,
    TriageDecision,
)
from app.agent.report import attack_url, cell, render_report
from app.llm import LLMError
from app.ml.injection import InjectionModel
from tests.test_agent_graph import (
    ALERT,
    CHILD,
    OBSERVED,
    PARENT,
    PLANTED,
    TRIGGER,
    deps,
    process_doc,
    run,
    tool_call,
)

OTHER_EVENT = "evt_000050"
ALLOWED = {TRIGGER, OTHER_EVENT}


@pytest.fixture(autouse=True)
def _classifier(trained_classifier: InjectionModel) -> None:
    """The chain scans tool results, which needs the classifier."""


def mapping(technique: str, *events: str) -> MappingDraft:
    return MappingDraft(technique_id=technique, event_ids=list(events), rationale="r")


# --- validate_mapping ------------------------------------------------------------------------


def test_name_and_tactics_come_from_the_bundle() -> None:
    (m,), errors = validate_mappings([mapping("T1003.001", TRIGGER)], ALLOWED)

    assert errors == []
    assert m.name == "LSASS Memory" and m.tactics == ["Credential Access"]


@pytest.mark.parametrize(
    ("technique", "message"),
    [("T1999", "not a technique"), ("T1086", "revoked")],
)
def test_invented_and_revoked_techniques_are_rejected(technique: str, message: str) -> None:
    valid, errors = validate_mappings([mapping(technique, TRIGGER)], ALLOWED)

    assert valid == [] and message in errors[0]


def test_events_outside_the_reportable_findings_are_rejected() -> None:
    valid, errors = validate_mappings(
        [mapping("T1059.001", TRIGGER, "evt_999999"), mapping("T1003.001", "evt_999999")], ALLOWED
    )

    assert [m.technique_id for m in valid] == ["T1059.001"]
    assert valid[0].event_ids == [TRIGGER]
    assert len(errors) == 2 and "evt_999999" in errors[0]


def test_repeated_techniques_are_merged() -> None:
    (m,), _ = validate_mappings(
        [mapping("T1059.001", TRIGGER), mapping("T1059.001", OTHER_EVENT, TRIGGER)], ALLOWED
    )

    assert m.event_ids == [TRIGGER, OTHER_EVENT]


async def test_mapping_retries_twice_then_drops_and_notes() -> None:
    bad = {"mappings": [{"technique_id": "T1999", "event_ids": [TRIGGER], "rationale": "x"}]}
    d, llm, _ = deps({"map_attack": [bad]})

    state = (await run(d)).state

    assert len(llm.prompts["map_attack"]) == 3 and state.mapping_retries == 2
    assert state.attack_mappings == []
    assert any("T1999" in n for n in state.closure_notes)
    assert len(state.mapping_rejections) == 3
    assert "not a technique" in str(llm.prompts["map_attack"][1][-1].content)


async def test_a_good_retry_keeps_the_valid_mapping() -> None:
    bad = {"mappings": [{"technique_id": "T1999", "event_ids": [TRIGGER], "rationale": "x"}]}
    good = {"mappings": [{"technique_id": "T1059.001", "event_ids": [TRIGGER], "rationale": "y"}]}
    d, llm, _ = deps({"map_attack": [bad, good]})

    state = (await run(d)).state

    assert [m.technique_id for m in state.attack_mappings] == ["T1059.001"]
    assert len(llm.prompts["map_attack"]) == 2 and state.closure_notes == []
    # A corrected mistake still counts as caught, and the report says so.
    assert len(state.mapping_rejections) == 1
    assert "validator refused 1 proposal" in (state.report_md or "")


async def test_mapping_is_skipped_without_reportable_events() -> None:
    d, llm, _ = deps({"summarize_findings": [{"findings": []}]})

    state = (await run(d)).state

    assert llm.prompts["map_attack"] == [] and state.attack_mappings == []


async def test_disputed_findings_never_reach_later_steps() -> None:
    disputes = {
        "confirmed": [],
        "disputed": [{"finding": "F1", "reason": "wrong"}],
        "reopen": False,
        "missing_checks": [],
        "reason": "r",
    }
    d, llm, _ = deps({"review_verdict": [disputes]})

    state = (await run(d)).state

    assert state.reportable_findings() == [] and state.timeline[0]["event_id"] == TRIGGER
    for node in ("assess", "recommend", "report_summary"):
        assert OBSERVED["claim"] not in str(llm.prompts[node][0][-1].content), node
    assert OBSERVED["claim"] not in (state.report_md or "")


# --- the verdict rules -----------------------------------------------------------------------


def confirmed(*citations: str, status: str = "confirmed") -> Finding:
    return Finding(
        id="F1", claim="c", kind="observation", citations=list(citations), tool="x", status=status
    )  # type: ignore[arg-type]


BRIEF = IntelBrief(
    process_chain=[
        {"role": "parent", "event_id": PARENT, "name": "AdminToolkit.exe", "sha256": "a" * 64},
        {"role": "trigger", "event_id": TRIGGER, "name": "powershell.exe", "sha256": "b" * 64},
        {"role": "child", "event_id": CHILD, "name": "msupdate.exe", "sha256": "c" * 64},
    ],
    reputation=[{"indicator": "a" * 64, "reputation": "known_good"}],
    hosts=[{"hostname": "FIN-WS-01"}],
    users=[{"username": "a.b"}],
)


def case_with(finding: Finding, **fields: Any) -> Case:
    return Case(alert=ALERT, intel_brief=BRIEF, findings=[finding], **fields)


@pytest.mark.parametrize("anchor", [TRIGGER, PARENT, CHILD])
def test_benign_support_may_cite_the_trigger_parent_or_a_child(anchor: str) -> None:
    finding = confirmed(anchor)

    assert supports_harmless(finding, case_with(finding), {})


def test_benign_support_may_cite_an_event_with_an_entity_from_the_brief() -> None:
    finding = confirmed(OTHER_EVENT)
    doc = process_doc(OTHER_EVENT, "AdminToolkit.exe --task weekly")
    doc["process"] |= {
        "name": "AdminToolkit.exe",
        "parent_name": "explorer.exe",
        "sha256": "d" * 64,
    }

    assert supports_harmless(finding, case_with(finding), {OTHER_EVENT: doc})


def test_benign_support_may_cite_a_tool_result_about_a_brief_entity() -> None:
    finding = confirmed("tool:check_reputation#4")
    evidence = Evidence(
        tool_refs={
            "tool:check_reputation#4": ToolRef(
                tool="check_reputation", ok=True, entities=["a" * 64]
            )
        }
    )

    assert supports_harmless(finding, case_with(finding, evidence=evidence), {})


def test_a_finding_unrelated_to_the_case_cannot_support_benign() -> None:
    finding = confirmed(OTHER_EVENT)
    doc = process_doc(OTHER_EVENT, "notepad.exe C:\\notes.txt")
    doc["process"] |= {"name": "notepad.exe", "parent_name": "cmd.exe", "sha256": "e" * 64}

    assert not supports_harmless(finding, case_with(finding), {OTHER_EVENT: doc})


def test_an_unreviewed_finding_cannot_support_benign() -> None:
    finding = confirmed(TRIGGER, status="unreviewed")

    assert not supports_harmless(finding, case_with(finding), {})


def assessed(verdict: str = "benign", supporting: list[str] | None = None) -> AssessDraft:
    return AssessDraft(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=0.9,
        reasoning="r",
        supporting_benign=supporting if supporting is not None else ["F1"],
    )


def test_benign_with_a_tied_confirmed_finding_stands() -> None:
    finding = confirmed(TRIGGER)

    assert apply_verdict_rules(assessed(), case_with(finding), {}) == ("benign", 0.9, [])


def test_benign_without_support_becomes_suspicious_with_lower_confidence() -> None:
    finding = confirmed(TRIGGER)

    verdict, confidence, notes = apply_verdict_rules(
        assessed(supporting=[]), case_with(finding), {}
    )

    assert verdict == "suspicious" and confidence == 0.5 and notes == [NO_SUPPORT]


def test_benign_citing_an_invented_finding_id_becomes_suspicious() -> None:
    finding = confirmed(TRIGGER)

    verdict, _, _ = apply_verdict_rules(assessed(supporting=["F99"]), case_with(finding), {})

    assert verdict == "suspicious"


FLAG = InjectionFlag(event_id=TRIGGER, field="cmdline", method="regex", score=1.0)


@pytest.mark.parametrize(
    ("flags", "reputations", "expected"),
    [
        ([FLAG], {"bad.example": "known_bad"}, "suspicious"),
        ([], {"bad.example": "known_bad"}, "benign"),
        ([FLAG], {"good.example": "known_good"}, "benign"),
    ],
)
def test_injection_flag_with_a_known_bad_indicator_blocks_benign(
    flags: list[InjectionFlag], reputations: dict[str, str], expected: str
) -> None:
    finding = confirmed(TRIGGER)
    evidence = Evidence(injection_flags=flags, reputations=reputations)

    verdict, _, notes = apply_verdict_rules(assessed(), case_with(finding, evidence=evidence), {})

    assert verdict == expected
    assert bool(notes) == (expected == "suspicious")


@pytest.mark.parametrize("verdict", ["malicious", "suspicious"])
def test_rules_never_change_other_verdicts(verdict: str) -> None:
    evidence = Evidence(injection_flags=[FLAG], reputations={"x.example": "known_bad"})
    case = case_with(confirmed(TRIGGER), evidence=evidence)

    assert apply_verdict_rules(assessed(verdict), case, {}) == (verdict, 0.9, [])


async def test_failed_assessment_ends_suspicious_never_benign() -> None:
    d, _, _ = deps({"assess": [LLMError("down")]})

    state = (await run(d)).state

    assert state.verdict == "suspicious" and state.confidence == 0.0
    assert state.report_md is not None and "assessment call failed" in state.report_md


async def test_the_proposed_verdict_is_kept_when_a_rule_changes_it() -> None:
    d, _, _ = deps(
        {
            "assess": [
                {"verdict": "benign", "confidence": 0.9, "reasoning": "r", "supporting_benign": []}
            ]
        }
    )

    state = (await run(d)).state

    assert state.verdict_proposed == "benign" and state.verdict == "suspicious"
    assert state.report_md is not None and NO_SUPPORT.split(":")[0] in state.report_md


# --- score in the chain ----------------------------------------------------------------------


async def test_score_uses_triage_criticality_verdict_and_bundle_tactics() -> None:
    mappings = {
        "mappings": [{"technique_id": "T1003.001", "event_ids": [TRIGGER], "rationale": "dump"}]
    }
    hosts = {"get_host_info": {"untrusted_log_data": {"hostname": "FIN-WS-01", "criticality": 5}}}
    d, _, _ = deps({"map_attack": [mappings]}, hosts)

    state = (await run(d)).state

    factors = state.risk_factors
    assert factors["priority"] == "P2" and factors["criticality"] == 5
    assert factors["high_impact_tactics"] == ["Credential Access"]
    # 60 x 0.95 + 10 + 12 + 8
    assert state.risk_score == 87


# --- recommend -------------------------------------------------------------------------------


def draft(action: str, target: str) -> RecommendationDraft:
    return RecommendationDraft(action=action, target=target, reason="r")  # type: ignore[arg-type]


def verdict_case(verdict: str = "malicious") -> Case:
    evidence = Evidence(reputations={"bad.example": "known_bad"})
    return Case(alert=ALERT, intel_brief=BRIEF, verdict=verdict, evidence=evidence)  # type: ignore[arg-type]


def test_recommendations_get_ids_and_always_need_approval() -> None:
    kept, notes = check_recommendations(
        [draft("isolate_host", "fin-ws-01"), draft("block_indicator", "bad.example")],
        verdict_case(),
    )

    assert [r.id for r in kept] == ["A1", "A2"] and notes == []
    assert all(r.requires_approval is True for r in kept)


def test_requires_approval_cannot_be_turned_off() -> None:
    with pytest.raises(ValueError, match="requires_approval"):
        Recommendation(id="A1", action="escalate", target="x", reason="r", requires_approval=False)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("action", "target"),
    [
        ("isolate_host", "PROD-DB-99"),
        ("disable_account", "someone.else"),
        ("block_indicator", "unseen.example"),
    ],
)
def test_targets_outside_the_case_are_dropped_and_noted(action: str, target: str) -> None:
    kept, notes = check_recommendations([draft(action, target)], verdict_case())

    assert kept == [] and "not an entity in this case" in notes[0]


def test_close_as_benign_only_on_a_benign_verdict() -> None:
    closed, notes = check_recommendations([draft("close_as_benign", "alt_0001")], verdict_case())
    allowed, _ = check_recommendations(
        [draft("close_as_benign", "alt_0001")], verdict_case("benign")
    )

    assert closed == [] and "malicious" in notes[0]
    assert [r.action for r in allowed] == ["close_as_benign"]


def test_an_action_outside_the_enum_is_refused() -> None:
    with pytest.raises(ValueError, match="action"):
        draft("run_powershell", "FIN-WS-01")


async def test_failed_recommend_escalates() -> None:
    d, _, _ = deps({"recommend": [LLMError("down")]})

    state = (await run(d)).state

    (only,) = state.recommendations
    assert only.action == "escalate" and only.requires_approval is True


async def test_no_valid_recommendation_falls_back_to_escalate() -> None:
    bad = {"recommendations": [{"action": "isolate_host", "target": "NOT-IN-CASE", "reason": "r"}]}
    d, _, _ = deps({"recommend": [bad]})

    state = (await run(d)).state

    assert [r.action for r in state.recommendations] == ["escalate"]
    assert any("not an entity" in n for n in state.closure_notes)


# --- the report ------------------------------------------------------------------------------

SECTIONS = [
    "Summary",
    "Alert",
    "Triage decision",
    "Intel brief",
    "Key event timeline",
    "Findings",
    "ATT&CK mapping",
    "Verdict and risk",
    "Recommended actions pending analyst approval",
    "Analyst decision",
    "Limitations",
]


async def test_report_has_every_section_in_order() -> None:
    d, _, _ = deps()

    report = (await run(d)).state.report_md or ""

    positions = [report.index(f"## {name}\n") for name in SECTIONS]
    assert positions == sorted(positions)


async def test_report_shows_findings_links_formula_and_pending_decision() -> None:
    d, _, _ = deps()

    report = (await run(d)).state.report_md or ""

    assert "| F1 | confirmed | powershell.exe was started by WINWORD.EXE |" in report
    assert "(https://attack.mitre.org/techniques/T1059/001/)" in report
    assert "Risk score:" in report and "verdict base" in report
    assert "| A1 | isolate_host | FIN-WS-01 |" in report and "pending" in report
    assert "Pending. The analyst has not recorded a verdict decision yet." in report
    assert "Nothing has been executed." in report


async def test_only_the_summary_is_llm_written() -> None:
    d, llm, _ = deps()

    state = (await run(d)).state

    assert "PowerShell ran from Word." in (state.report_md or "")
    assert len(llm.prompts["report_summary"]) == 1


def test_summary_sentences_citing_unknown_events_are_removed() -> None:
    text = f"Word started PowerShell ({TRIGGER}). It then wiped the disk (evt_999999). Done."

    summary, notes = checked_summary(text, {TRIGGER})

    assert summary == f"Word started PowerShell ({TRIGGER}). Done."
    assert "evt_999999" in notes[0]


async def test_a_bad_event_id_in_the_summary_is_removed_and_noted_in_the_report() -> None:
    summary = {"summary": f"Word started PowerShell ({TRIGGER}). The disk was wiped (evt_999999)."}
    d, _, _ = deps({"report_summary": [summary]})

    report = (await run(d)).state.report_md or ""

    assert "disk was wiped" not in report and "evt_999999 was removed" in report


async def test_failed_or_empty_summary_falls_back_to_a_written_one() -> None:
    failed, _, _ = deps({"report_summary": [LLMError("down")]})
    emptied, _, _ = deps({"report_summary": [{"summary": "Disk wiped (evt_999999)."}]})

    for d in (failed, emptied):
        state = (await run(d)).state
        assert "written by code" in state.report_summary


async def test_a_summary_with_an_injection_pattern_is_replaced() -> None:
    d, _, _ = deps({"report_summary": [{"summary": PLANTED}]})

    report = (await run(d)).state.report_md or ""

    assert PLANTED not in report and "matched an injection pattern" in report


def test_flagged_events_lose_their_log_text_in_the_timeline() -> None:
    doc = process_doc(TRIGGER, f"cmd /c echo {PLANTED}")

    (row,) = timeline_rows([doc], {TRIGGER})
    (clean,) = timeline_rows([doc], set())

    assert PLANTED[:30] not in str(row) and "withheld" in row["target"]
    assert PLANTED[:30] in str(clean)


async def test_injection_in_a_trigger_never_reaches_the_report() -> None:
    cmdline = f"cmd /c echo {PLANTED}"
    d, _, _ = deps(docs=[process_doc(TRIGGER, cmdline)])

    report = (await run(d)).state.report_md or ""

    assert PLANTED[:30] not in report


def test_cell_keeps_log_text_from_breaking_the_markdown() -> None:
    assert cell("a|b\n`c`") == "a\\|b 'c'"
    assert len(cell("x" * 500)) == 160


def test_attack_url_only_takes_technique_ids() -> None:
    assert attack_url("T1059") == "https://attack.mitre.org/techniques/T1059/"
    with pytest.raises(ValueError, match="not a technique"):
        attack_url("javascript:alert(1)")


def report_case() -> Case:
    return Case(
        alert=ALERT,
        triage=TriageDecision(priority="P2", category="endpoint", reason="r"),
        verdict="malicious",
        confidence=0.9,
        report_summary="s",
        recommendations=[
            Recommendation(id="A1", action="escalate", target="SOC", reason="r"),
            Recommendation(id="A2", action="isolate_host", target="FIN-WS-01", reason="r"),
        ],
    )


def test_analyst_decisions_appear_in_the_report() -> None:
    decisions = [
        {"kind": "action", "action_id": "A1", "decision": "approve"},
        {"kind": "action", "action_id": "A2", "decision": "reject", "note": "Too soon."},
        {
            "kind": "verdict",
            "agreed": False,
            "agent_verdict": "malicious",
            "analyst_verdict": "suspicious",
            "ts": datetime(2026, 11, 6, 10, 0, 0, 123, tzinfo=UTC),
            "note": "Looks like a test.",
        },
    ]

    report = render_report(report_case(), decisions)

    assert "| A1 | escalate | SOC | r | approved |" in report
    assert "| A2 | isolate_host | FIN-WS-01 | r | rejected: Too soon. |" in report
    assert "at 2026-11-06T10:00:00Z." in report
    assert "**overrode**" in report and "**suspicious**" in report
    assert "Looks like a test." in report and "Pending." not in report


def test_limitations_keep_the_benign_gap() -> None:
    report = render_report(report_case(), [])

    assert "cannot check that the finding really supports the harmless explanation" in report


async def test_every_closure_model_output_passes_through_the_chain_with_tools() -> None:
    d, llm, _ = deps(
        {
            "investigate": [
                AIMessage("", tool_calls=[tool_call("get_dns_queries", host="FIN-WS-01")]),
                AIMessage("Done."),
            ]
        }
    )

    state = (await run(d)).state

    assert state.verdict == "malicious" and state.recommendations[0].action == "isolate_host"
    assert {"map_attack", "assess", "recommend", "report_summary"} <= set(llm.prompts)
