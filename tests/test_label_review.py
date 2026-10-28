"""Tests for the labelling loop and the files it writes.

The loop is tested by scripting the answers, which is why it takes its input
and output as arguments. The test that matters most is the blind one: a label
formed by looking at the rule engine's answer measures the labeller, not the
rules.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator
from honeypot_ai.label import __main__ as cli
from honeypot_ai.label.review import (
    HEAD_LINES,
    collapse,
    parse_behaviours,
    parse_intent,
    parse_operator,
    render,
    review,
)
from honeypot_ai.label.sample import DrawnBy, SampleItem
from honeypot_ai.label.store import (
    HumanLabel,
    append_label,
    latest,
    now,
    read_labels,
    read_sample,
    write_sample,
)


def item(
    sample_id: str = "abc123", *commands: str, stratum: Intent = Intent.PERSISTENCE
) -> SampleItem:
    return SampleItem(
        sample_id=sample_id,
        session_id=f"session-{sample_id}",
        stratum=stratum,
        weight=4242,
        drawn_by=DrawnBy.STRATUM,
        facts=SessionFacts(
            session_id=f"session-{sample_id}",
            commands=commands or ("cd /tmp", "chmod +x x"),
            command_gaps=(0.01,),
        ),
    )


def scripted(*answers: str) -> Iterator[str]:
    return iter(answers)


def run(items: list[SampleItem], answers: list[str], tmp_path: Path, done: set[str] | None = None):  # type: ignore[no-untyped-def]
    replies = iter(answers)
    said: list[str] = []
    labels = tmp_path / "labels.jsonl"
    stats = review(items, done or set(), "david", lambda _: next(replies), said.append, labels)
    return stats, "\n".join(said), labels


# --- Blind -----------------------------------------------------------------


def test_the_labeller_is_never_shown_the_rules_answer(tmp_path: Path) -> None:
    """The stratum is the rule engine's label. Showing it would anchor every
    answer to it, and the evaluation would measure persuadability."""
    _, shown, _ = run(
        [item("abc123", "uname -a", stratum=Intent.PERSISTENCE)], ["3", "", "a", ""], tmp_path
    )
    assert "persistence" not in shown


def test_the_labeller_is_never_shown_how_common_the_sequence_is(tmp_path: Path) -> None:
    """A big number suggests "just a bot", which is a judgement, not evidence."""
    _, shown, _ = run([item()], ["6", "", "a", ""], tmp_path)
    assert "4242" not in shown


# --- The loop --------------------------------------------------------------


def test_an_answer_is_saved_as_soon_as_it_is_given(tmp_path: Path) -> None:
    stats, _, labels = run(
        [item("one"), item("two")], ["6", "permission_change", "a", "", "q"], tmp_path
    )

    saved = read_labels(labels)
    assert stats.labelled == 1
    assert [label.sample_id for label in saved] == ["one"]
    assert saved[0].intent is Intent.STAGING
    assert saved[0].behaviours == frozenset({Behaviour.PERMISSION_CHANGE})
    assert saved[0].operator is Operator.AUTOMATED


def test_skipping_saves_nothing_and_moves_on(tmp_path: Path) -> None:
    stats, _, labels = run([item("one"), item("two")], ["s", "6", "", "a", ""], tmp_path)
    assert stats.skipped == 1
    assert [label.sample_id for label in read_labels(labels)] == ["two"]


def test_items_already_labelled_are_not_asked_again(tmp_path: Path) -> None:
    stats, _, labels = run([item("one"), item("two")], ["6", "", "a", ""], tmp_path, done={"one"})
    assert [label.sample_id for label in read_labels(labels)] == ["two"]
    assert stats.remaining == 0


def test_a_bad_answer_is_asked_again_rather_than_guessed(tmp_path: Path) -> None:
    _, shown, labels = run([item()], ["banana", "6", "", "a", ""], tmp_path)
    assert "not understood" in shown
    assert read_labels(labels)[0].intent is Intent.STAGING


def test_help_shows_the_definitions_the_model_is_given(tmp_path: Path) -> None:
    """Same words for both, or the evaluation compares wording."""
    from honeypot_ai.classify.llm.prompt import SYSTEM_PROMPT
    from honeypot_ai.classify.taxonomy import INTENT_DEFINITIONS

    _, shown, _ = run([item()], ["?", "6", "", "a", ""], tmp_path)
    for definition in INTENT_DEFINITIONS.values():
        assert definition in shown
        assert definition in SYSTEM_PROMPT


# --- Parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("1", Intent.PROTOCOL_PROBE),
        ("7", Intent.PERSISTENCE),
        ("8", Intent.OTHER),
        ("stag", Intent.STAGING),
        ("persistence", Intent.PERSISTENCE),
    ],
)
def test_an_intent_can_be_given_by_number_or_by_name(answer: str, expected: Intent) -> None:
    assert parse_intent(answer) is expected


@pytest.mark.parametrize("answer", ["", "0", "9", "zzz", "s"])
def test_an_ambiguous_or_unknown_intent_is_refused(answer: str) -> None:
    """`s` alone would match two intents; it is reserved for skip anyway."""
    assert parse_intent(answer) is None


def test_behaviours_may_be_numbers_names_or_nothing() -> None:
    assert parse_behaviours("") == frozenset()
    assert Behaviour.PERMISSION_CHANGE in (parse_behaviours("permission_change") or set())
    assert len(parse_behaviours("1, 2 3") or set()) == 3
    assert parse_behaviours("not_a_behaviour") is None


def test_operator_defaults_to_unknown_rather_than_guessing() -> None:
    assert parse_operator("") is Operator.UNKNOWN
    assert parse_operator("a") is Operator.AUTOMATED
    assert parse_operator("x") is None


# --- Showing a session -----------------------------------------------------


def test_repeated_commands_are_shown_once_with_a_count() -> None:
    assert collapse(["a", "a", "a", "b", "a"]) == [("a", 3), ("b", 1), ("a", 1)]


def test_a_very_long_session_is_shown_head_and_tail() -> None:
    commands = [f"cmd{n}" for n in range(500)]
    shown = render(SessionFacts(session_id="s", commands=tuple(commands)))
    assert "cmd0" in shown
    assert "cmd499" in shown
    assert f"cmd{HEAD_LINES + 5}" not in shown
    assert "more line(s)" in shown


# --- The files -------------------------------------------------------------


def test_the_sample_survives_a_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "sample.jsonl"
    original = [item("one", "uname -a"), item("two", "nproc", stratum=Intent.STAGING)]
    write_sample(original, path)
    assert read_sample(path) == original


def test_the_latest_answer_wins_and_the_history_is_kept(tmp_path: Path) -> None:
    """Changing your mind adds a line rather than editing one."""
    path = tmp_path / "labels.jsonl"
    for intent in (Intent.FINGERPRINTING, Intent.STAGING):
        append_label(HumanLabel("one", intent, frozenset(), Operator.UNKNOWN, "david", now()), path)

    assert len(read_labels(path)) == 2
    assert latest(read_labels(path))["one"].intent is Intent.STAGING


def test_one_labellers_answers_do_not_hide_anothers(tmp_path: Path) -> None:
    path = tmp_path / "labels.jsonl"
    append_label(
        HumanLabel("one", Intent.STAGING, frozenset(), Operator.UNKNOWN, "david", now()), path
    )
    append_label(HumanLabel("one", Intent.OTHER, frozenset(), Operator.UNKNOWN, "ana", now()), path)

    assert latest(read_labels(path), labeller="david")["one"].intent is Intent.STAGING
    assert latest(read_labels(path), labeller="ana")["one"].intent is Intent.OTHER


def test_an_existing_sample_is_not_overwritten_without_force(tmp_path: Path) -> None:
    """Redrawing the sample would orphan every label written against it."""
    path = tmp_path / "sample.jsonl"
    path.write_text("already here\n")

    code = cli.main(["sample", "--out", str(path), "--meta", str(tmp_path / "meta.json")])

    assert code == 2
    assert path.read_text() == "already here\n"
