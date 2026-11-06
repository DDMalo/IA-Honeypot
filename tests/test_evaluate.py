"""Tests for scoring classifiers against the evaluation set.

Every figure the report prints comes from a function checked here against a
case small enough to work out by hand. A metric that is subtly wrong is worse
than none: it produces a confident number for a comparison people will cite.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Intent, Label, Operator
from honeypot_ai.evaluate import __main__ as cli
from honeypot_ai.evaluate.metrics import (
    Pair,
    accuracy,
    cohen_kappa,
    confusion,
    macro_f1,
    majority_baseline,
    per_class,
    percentile,
)
from honeypot_ai.evaluate.predict import (
    Prediction,
    file_for,
    latest_predictions,
    predict,
    read_predictions,
)
from honeypot_ai.evaluate.report import Pricing, build_report
from honeypot_ai.label.sample import DrawnBy, SampleItem
from honeypot_ai.label.store import HumanLabel, append_label, write_sample

STAGING, PROBE, SHELL = Intent.STAGING, Intent.FINGERPRINTING, Intent.SHELL_PROBING


# --- Metrics ---------------------------------------------------------------


def test_accuracy_counts_items_or_sessions() -> None:
    pairs = [Pair(STAGING, STAGING, 1), Pair(PROBE, STAGING, 9)]
    assert accuracy(pairs) == 0.5
    assert accuracy(pairs, weighted=True) == 0.1


def test_precision_recall_and_f1_by_hand() -> None:
    # Reference: 2 staging, 2 probing. The classifier says staging three times.
    pairs = [
        Pair(STAGING, STAGING),
        Pair(STAGING, STAGING),
        Pair(PROBE, STAGING),
        Pair(PROBE, PROBE),
    ]
    scores = per_class(pairs)
    assert scores[STAGING].precision == pytest.approx(2 / 3)
    assert scores[STAGING].recall == 1.0
    assert scores[STAGING].f1 == pytest.approx(0.8)
    assert scores[PROBE].precision == 1.0
    assert scores[PROBE].recall == 0.5


def test_macro_f1_averages_only_the_classes_the_reference_contains() -> None:
    """Predicting a class nobody labelled costs the class it replaced, not a
    zero F1 for a class with nothing to recall."""
    pairs = [Pair(STAGING, STAGING), Pair(PROBE, SHELL)]
    # staging F1 = 1; fingerprinting F1 = 0; shell_probing is not in the reference.
    assert macro_f1(pairs) == 0.5


def test_a_class_never_predicted_is_flagged_rather_than_silently_zero() -> None:
    scores = per_class([Pair(STAGING, PROBE)])
    assert scores[STAGING].never_predicted
    assert scores[STAGING].precision == 0.0


def test_the_baseline_says_the_commonest_class_and_breaks_ties_by_name() -> None:
    pairs = [Pair(STAGING, PROBE), Pair(PROBE, PROBE)]
    assert {p.predicted for p in majority_baseline(pairs)} == {
        PROBE
    }  # tie: fingerprinting < staging
    weighted = majority_baseline([Pair(STAGING, PROBE, 5), Pair(PROBE, PROBE, 1)], weighted=True)
    assert {p.predicted for p in weighted} == {STAGING}


def test_kappa_by_hand() -> None:
    # Observed 0.75; expected 0.5·0.25 + 0.5·0.75 = 0.5; kappa (0.75−0.5)/(1−0.5).
    first = [STAGING, STAGING, PROBE, PROBE]
    second = [STAGING, PROBE, PROBE, PROBE]
    assert cohen_kappa(first, second) == pytest.approx(0.5)
    assert cohen_kappa(first, first) == 1.0


def test_confusion_rows_are_the_reference() -> None:
    matrix = confusion([Pair(STAGING, PROBE), Pair(STAGING, PROBE), Pair(PROBE, PROBE)])
    assert matrix[STAGING][PROBE] == 2
    assert matrix[PROBE][PROBE] == 1


def test_percentile_is_nearest_rank() -> None:
    values = [float(v) for v in range(1, 11)]
    assert percentile(values, 90) == 9.0
    assert percentile(values, 100) == 10.0
    assert percentile([], 50) == 0.0


# --- Predictions -----------------------------------------------------------


def item(sample_id: str, drawn_by: DrawnBy = DrawnBy.UNIFORM, weight: int = 1) -> SampleItem:
    return SampleItem(
        sample_id=sample_id,
        session_id=f"s-{sample_id}",
        stratum=Intent.OTHER,
        weight=weight,
        drawn_by=drawn_by,
        facts=SessionFacts(session_id=f"s-{sample_id}", commands=("uname -a",)),
    )


def answering(intent: Intent, notes: str | None = None):  # type: ignore[no-untyped-def]
    def classify(facts: SessionFacts) -> Label:
        return Label(session_id=facts.session_id, intent=intent, notes=notes)

    return classify


def test_a_run_resumes_where_it_stopped(tmp_path: Path) -> None:
    path = tmp_path / "p.jsonl"
    items = [item("a"), item("b"), item("c")]
    assert predict(items, answering(PROBE), "x", path, limit=2) == 2
    assert predict(items, answering(PROBE), "x", path) == 1
    assert [p.sample_id for p in read_predictions(path)] == ["a", "b", "c"]


def test_latency_and_prompt_size_are_recorded(tmp_path: Path) -> None:
    ticks = count(start=0, step=2)
    path = tmp_path / "p.jsonl"
    predict(
        [item("a")],
        answering(PROBE),
        "x",
        path,
        prompt_size=lambda _f: 400,
        clock=lambda: float(next(ticks)),
    )
    (saved,) = read_predictions(path)
    assert saved.latency_s == 2.0
    assert saved.prompt_chars == 400


def test_a_classifier_that_gave_up_is_marked_failed(tmp_path: Path) -> None:
    path = tmp_path / "p.jsonl"
    predict([item("a")], answering(Intent.OTHER, "unclassified: timeout"), "x", path)
    assert read_predictions(path)[0].failed


def test_the_file_name_is_safe_for_any_model_name() -> None:
    assert file_for("ollama:qwen2.5:1.5b", Path("d")) == Path("d/ollama_qwen2.5_1.5b.jsonl")


def test_predictions_under_another_taxonomy_are_ignored() -> None:
    old = Prediction(
        "a",
        "x",
        STAGING,
        frozenset(),
        Operator.UNKNOWN,
        None,
        None,
        0.0,
        0,
        datetime.now(UTC),
        taxonomy_version=TAXONOMY_VERSION - 1,
    )
    assert latest_predictions([old]) == {}


# --- Report ----------------------------------------------------------------


def label(
    sample_id: str, intent: Intent, labeller: str = "adjudicated", version: int = TAXONOMY_VERSION
) -> HumanLabel:
    return HumanLabel(
        sample_id,
        intent,
        None,
        Operator.UNKNOWN,
        labeller,
        datetime.now(UTC),
        taxonomy_version=version,
    )


def prediction(sample_id: str, intent: Intent, notes: str | None = None) -> Prediction:
    return Prediction(
        sample_id,
        "x",
        intent,
        frozenset(),
        Operator.UNKNOWN,
        None,
        notes,
        0.1,
        0,
        datetime.now(UTC),
    )


def test_failures_are_scored_as_wrong_not_left_out() -> None:
    items = [item("a"), item("b")]
    labels = [label("a", STAGING), label("b", STAGING)]
    runs = {
        "x": {
            "a": prediction("a", STAGING),
            "b": prediction("b", Intent.OTHER, "unclassified: no reply"),
        }
    }
    report = build_report(items, labels, runs)
    assert "| x | 2 | 1 | 0.50 |" in report


def test_labels_under_another_taxonomy_are_not_the_reference() -> None:
    items = [item("a")]
    labels = [label("a", STAGING, version=TAXONOMY_VERSION - 1)]
    with pytest.raises(ValueError, match="no labels"):
        build_report(items, labels, {"x": {"a": prediction("a", STAGING)}})


def test_recall_is_also_reported_on_the_uniform_part_alone() -> None:
    """The stratified part was drawn by the rules' label, which biases recall."""
    items = [item("u"), item("s", DrawnBy.STRATUM)]
    labels = [label("u", STAGING), label("s", STAGING)]
    runs = {"x": {"u": prediction("u", STAGING), "s": prediction("s", PROBE)}}
    report = build_report(items, labels, runs)
    # Overall staging recall 0.50; on the uniform part alone 1.00, from 1 item.
    assert "| staging | 1.00 | 0.50 | 0.67 | 2 | 1.00 | 1 |" in report


def test_items_without_a_prediction_are_announced() -> None:
    items = [item("a"), item("b")]
    labels = [label("a", STAGING), label("b", STAGING)]
    report = build_report(items, labels, {"x": {"a": prediction("a", STAGING)}})
    assert "1 reference item(s) have no prediction yet" in report


def test_the_labellers_agreement_is_reported_beside_the_scores() -> None:
    items = [item("a"), item("b")]
    labels = [
        label("a", STAGING),
        label("b", STAGING),
        label("a", STAGING, "david"),
        label("b", PROBE, "david"),
        label("a", STAGING, "claude"),
        label("b", STAGING, "claude"),
    ]
    report = build_report(items, labels, {"x": {"a": prediction("a", STAGING)}})
    assert "claude vs david: 1/2 intents agree" in report


def test_cost_is_estimated_only_when_a_price_is_given() -> None:
    items = [item("a")]
    labels = [label("a", STAGING)]
    p = Prediction(
        "a", "x", STAGING, frozenset(), Operator.UNKNOWN, None, None, 1.0, 4000, datetime.now(UTC)
    )
    unpriced = build_report(items, labels, {"x": {"a": p}})
    assert "1000 tokens per item" in unpriced
    assert "Estimated cost" not in unpriced
    priced = build_report(items, labels, {"x": {"a": p}}, pricing=Pricing(1.0, 0.0))
    assert "$0.001000 per item" in priced


def test_the_command_line_scores_the_rules_end_to_end(tmp_path: Path) -> None:
    sample, labels, out = tmp_path / "s.jsonl", tmp_path / "l.jsonl", tmp_path / "r.md"
    write_sample([item("a")], sample)
    append_label(label("a", Intent.FINGERPRINTING), labels)

    assert (
        cli.main(
            ["predict", "--classifier", "rules", "--sample", str(sample), "--dir", str(tmp_path)]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "report",
                str(tmp_path / "rules.jsonl"),
                "--sample",
                str(sample),
                "--labels",
                str(labels),
                "--meta",
                str(tmp_path / "none.json"),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert "| rules | 1 | 0 | 1.00 |" in out.read_text(encoding="utf-8")
