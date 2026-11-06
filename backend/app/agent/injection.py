"""Prompt-injection detection over log text: generic regex patterns plus the ML classifier.

The patterns are written from first principles about what an injection aimed at a triage
agent has to do, not from any scenario. Each family needs both a cue and a target, so
ordinary IT English ("follow the install instructions", "Help Desk Agent", "ignore the
warning") doesn't match:

- addressed_to_ai: text speaking to an AI, assistant or automated system ("note to the AI",
  "if you are an automated analyst", "dear assistant");
- override_instructions: telling the reader to ignore, disregard, forget or override its
  previous/prior/system instructions or rules;
- verdict_instruction: telling the reader to mark, classify or close an alert, event or
  activity as benign, safe or a false positive, or asserting that "this alert is benign".

The classifier (app.ml.injection) catches phrasings the patterns miss. A hit is a flag in
state, never a verdict: the text stays where it was, inside untrusted_log_data.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Literal

from app.agent.case import WITHHELD, InjectionFlag
from app.ml import injection as classifier_model

AI = (
    r"(?:ai|a\.i\.|llms?|(?:large\s+)?language\s+models?|chat\s?bots?|chat\s?gpt|gpt(?:-\d+)?|"
    r"copilot|(?:ai|virtual|digital)\s+assistants?|assistants?|"
    r"(?:automated|autonomous|ai)[\s-](?:systems?|analysts?|agents?|reviewers?|triage|scanners?)|"
    r"(?:security|soc|triage|analysis)\s+(?:bots?|agents?|assistants?|models?))"
)
PRIOR = (
    r"(?:previous|prior|preceding|above|earlier|former|original|initial|system|all|any|your|"
    r"these|those|my|our|its)"
)
RULES = (
    r"(?:instructions?|prompts?|rules|guidelines|directives|guidance|policies|policy|orders|"
    r"programming|constraints|context)"
)
VERB = (
    r"(?:mark|classify|label|flag|tag|treat|close|resolve|report|record|categori[sz]e|"
    r"consider|deem|rate|dismiss|set)"
)
TARGET = (
    r"(?:this|that|these|it|alerts?|events?|activity|activities|incidents?|detections?|"
    r"findings?|tickets?|cases?|entry|entries)"
)
VERDICT = (
    r"(?:benign|safe|harmless|clean|legitimate|legit|expected|authori[sz]ed|"
    r"false[\s-]?positives?|not\s+(?:malicious|suspicious|a\s+threat)|non[\s-]?malicious|"
    r"low[\s-]?risk|no\s+threat)"
)
GAP = r"(?:\s+\S+){0,4}?"

PATTERNS: dict[str, re.Pattern[str]] = {
    "addressed_to_ai": re.compile(
        rf"\b(?:note|message|instructions?|attention|notice|reminder|request)\s+(?:to|for)\s+"
        rf"(?:the\s+|any\s+|all\s+)?{AI}\b"
        rf"|\b(?:dear|hey|hello|hi)\s*,?\s+(?:the\s+)?{AI}\b"
        rf"|\bif\s+you\s+are\s+(?:an?\s+|the\s+)?{AI}\b"
        rf"|\byou\s+are\s+(?:now\s+)?(?:an?\s+|the\s+)?{AI}\b"
        rf"|(?:^|[\s\"'(\[])(?:ai|llm|assistant)\s*:\s*(?:you|please|ignore|do|mark|treat|"
        rf"classify|this)\b",
        re.IGNORECASE,
    ),
    "override_instructions": re.compile(
        rf"\b(?:ignore|disregard|forget|override|overrule|bypass)\b{GAP}\s+{PRIOR}\b"
        rf"(?:\s+\S+){{0,3}}?\s+{RULES}\b"
        rf"|\b(?:previous|prior|earlier|above)\s+{RULES}\s+(?:no\s+longer\s+apply|are\s+"
        rf"(?:void|cancell?ed|obsolete))\b",
        re.IGNORECASE,
    ),
    "verdict_instruction": re.compile(
        rf"\b{VERB}\b(?:\s+\S+){{0,3}}?\s+{TARGET}\b{GAP}\s+(?:as|is)\s+(?:an?\s+|being\s+)?"
        rf"{VERDICT}\b"
        rf"|\b(?:this|the)\s+(?:alert|detection|activity|event|incident)\s+(?:is|was)\s+"
        rf"(?:an?\s+|entirely\s+|completely\s+)?{VERDICT}\b",
        re.IGNORECASE,
    ),
}
# Hex hashes, IDs and timestamps can't carry an instruction; skipping them saves classifier
# time on every tool result.
MIN_TEXT = 12


@dataclass(frozen=True)
class Detection:
    method: Literal["regex", "classifier"]
    score: float
    pattern: str | None = None


def classifier_scores(texts: list[str]) -> tuple[list[float], float]:
    """Classifier probabilities and its threshold. Raises ModelMissingError if the
    artifact hasn't been built: a missing guardrail should stop the run, not go quiet."""
    model = classifier_model.load()
    return model.scores(texts).tolist(), model.threshold


def regex_hits(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS.items() if pattern.search(text)]


def detect_many(texts: list[str]) -> list[list[Detection]]:
    """detect() for several texts with one classifier call."""
    scores, threshold = classifier_scores(texts) if texts else ([], 0.0)
    out = []
    for text, score in zip(texts, scores, strict=True):
        hits = [Detection("regex", 1.0, name) for name in regex_hits(text)]
        if score >= threshold:
            hits.append(Detection("classifier", round(score, 4)))
        out.append(hits)
    return out


def detect(text: str) -> list[Detection]:
    return detect_many([text])[0]


def _strings(value: Any, path: str, event_id: str | None) -> Iterator[tuple[str, str, str | None]]:
    """(path, text, nearest event_id) for every string inside a tool result."""
    if isinstance(value, dict):
        own = value.get("event_id")
        if not isinstance(own, str):
            ids = value.get("event_ids")
            own = ids[0] if isinstance(ids, list) and ids and isinstance(ids[0], str) else None
        current = own or event_id
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}" if path else str(key), current)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]", event_id)
    elif isinstance(value, str) and len(value) >= MIN_TEXT:
        yield path, value, event_id


def screen(texts: list[str]) -> list[str]:
    """LLM-written texts as later prompts may show them: WITHHELD if a pattern matches. Regex
    only: the classifier's false positives on the model's own English cost real findings."""
    return [WITHHELD if regex_hits(text) else text for text in texts]


def scan_tool_result(result: dict[str, Any]) -> list[InjectionFlag]:
    """Flags for a tool result's log content only. attack_catalog is MITRE's text from the
    pinned bundle and errors are ours; flags there would be noise that later feeds a verdict
    guardrail."""
    if "untrusted_log_data" not in result:
        return []
    return scan(result["untrusted_log_data"], "untrusted_log_data")


def scan(value: Any, path: str = "", event_id: str | None = None) -> list[InjectionFlag]:
    """Injection flags for every text field in `value`, a block of log content."""
    found = list(_strings(value, path, event_id))
    flags: dict[tuple[str | None, str, str], InjectionFlag] = {}
    for (field, _, owner), hits in zip(found, detect_many([t for _, t, _ in found]), strict=True):
        for h in hits:
            # Several patterns on one field are one regex flag.
            flags.setdefault(
                (owner, field, h.method),
                InjectionFlag(event_id=owner, field=field, method=h.method, score=h.score),
            )
    return list(flags.values())
