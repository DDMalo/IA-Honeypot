"""Turning sessions into labels."""

from honeypot_ai.classify.facts import SessionFacts, facts_from_row, facts_from_session
from honeypot_ai.classify.llm import (
    LlmClassifier,
    LlmStats,
    Provider,
    ProviderError,
    SessionClassification,
)
from honeypot_ai.classify.rules import RULES, Rule, classify, classify_all, match_behaviours
from honeypot_ai.classify.taxonomy import (
    INTENT_PRECEDENCE,
    Behaviour,
    Intent,
    Label,
    Operator,
    intent_rank,
    resolve_intent,
)

__all__ = [
    "INTENT_PRECEDENCE",
    "RULES",
    "Behaviour",
    "Intent",
    "Label",
    "LlmClassifier",
    "LlmStats",
    "Operator",
    "Provider",
    "ProviderError",
    "Rule",
    "SessionClassification",
    "SessionFacts",
    "classify",
    "classify_all",
    "facts_from_row",
    "facts_from_session",
    "intent_rank",
    "match_behaviours",
    "resolve_intent",
]
