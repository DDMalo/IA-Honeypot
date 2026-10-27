"""Tests for the taxonomy.

A vocabulary cannot really be unit-tested for correctness — whether
`shell_probing` is a useful category is a judgement, argued in
`docs/taxonomy.md`. What these tests pin down is the part that *is*
mechanical: the precedence rule, which has to give the same answer every time
or the labelled set stops being consistent, and the invariants everything
downstream assumes.
"""

from __future__ import annotations

import dataclasses

import pytest

from honeypot_ai.classify.taxonomy import (
    INTENT_PRECEDENCE,
    Behaviour,
    Intent,
    Label,
    Operator,
    intent_rank,
    resolve_intent,
)


def test_every_ranked_intent_appears_exactly_once() -> None:
    assert len(INTENT_PRECEDENCE) == len(set(INTENT_PRECEDENCE))


def test_other_is_not_ranked() -> None:
    """`other` is a fallback, not a position on the kill chain."""
    assert Intent.OTHER not in INTENT_PRECEDENCE
    assert intent_rank(Intent.OTHER) == -1


def test_precedence_covers_every_intent_but_other() -> None:
    """A new intent added without a rank would silently never win."""
    assert set(INTENT_PRECEDENCE) == set(Intent) - {Intent.OTHER}


def test_the_furthest_point_reached_wins() -> None:
    reached = {Intent.FINGERPRINTING, Intent.SHELL_PROBING, Intent.PERSISTENCE}
    assert resolve_intent(reached) == Intent.PERSISTENCE


def test_a_single_candidate_is_itself() -> None:
    assert resolve_intent({Intent.STAGING}) == Intent.STAGING


def test_nothing_recognised_is_other_rather_than_an_error() -> None:
    """An unrecognised session is a finding, not a crash."""
    assert resolve_intent(set()) == Intent.OTHER


def test_other_alone_stays_other() -> None:
    assert resolve_intent({Intent.OTHER}) == Intent.OTHER


def test_other_never_outranks_a_real_intent() -> None:
    assert resolve_intent({Intent.OTHER, Intent.FINGERPRINTING}) == Intent.FINGERPRINTING


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        (Intent.CREDENTIAL_ACCESS, Intent.FINGERPRINTING),
        (Intent.FINGERPRINTING, Intent.SHELL_PROBING),
        (Intent.SHELL_PROBING, Intent.RESOURCE_PROFILING),
        (Intent.RESOURCE_PROFILING, Intent.STAGING),
        (Intent.STAGING, Intent.PERSISTENCE),
    ],
)
def test_the_documented_order_holds(lower: Intent, higher: Intent) -> None:
    """The order in docs/taxonomy.md and the order in code are the same order."""
    assert intent_rank(lower) < intent_rank(higher)
    assert resolve_intent({lower, higher}) == higher


def test_labels_serialise_as_their_own_strings() -> None:
    """Stored in the database and sent to a model as text, so the value is the name."""
    assert str(Intent.PERSISTENCE) == "persistence"
    assert str(Behaviour.AUTHORIZED_KEYS_WRITE) == "authorized_keys_write"
    assert str(Operator.AUTOMATED) == "automated"
    # And every member's value matches its own name, so none can drift.
    for member in (*Intent, *Behaviour, *Operator):
        assert member.value == member.name.lower()


def test_a_label_carries_intent_behaviours_and_operator() -> None:
    label = Label(
        session_id="abc123",
        intent=Intent.PERSISTENCE,
        behaviours=frozenset({Behaviour.SSH_DIR_RESET, Behaviour.AUTHORIZED_KEYS_WRITE}),
        operator=Operator.AUTOMATED,
        confidence=0.9,
    )
    assert label.intent is Intent.PERSISTENCE
    assert Behaviour.AUTHORIZED_KEYS_WRITE in label.behaviours
    assert label.operator is Operator.AUTOMATED


def test_a_label_needs_no_behaviours() -> None:
    """A session that only logged in has an intent and nothing to describe."""
    label = Label(session_id="abc123", intent=Intent.CREDENTIAL_ACCESS)
    assert label.behaviours == frozenset()
    assert label.operator is Operator.UNKNOWN


@pytest.mark.parametrize("bad", [-0.1, 1.1, 42.0])
def test_a_confidence_outside_zero_to_one_is_refused(bad: float) -> None:
    with pytest.raises(ValueError, match="confidence"):
        Label(session_id="abc123", intent=Intent.OTHER, confidence=bad)


def test_labels_are_frozen_so_a_classifier_cannot_edit_a_human_label() -> None:
    label = Label(session_id="abc123", intent=Intent.FINGERPRINTING)
    with pytest.raises(dataclasses.FrozenInstanceError):
        label.intent = Intent.PERSISTENCE  # type: ignore[misc]
