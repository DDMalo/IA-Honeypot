"""Score classifiers against the reference labels, as a Markdown report.

What the report holds, and why each part is there:

- **Distinct sequences and sessions, separately.** Each item is a distinct
  command sequence with a weight: how many sessions shared it. Unweighted, the
  accuracy says how often a classifier understands a *kind* of behaviour;
  weighted, how often it is right about a *session*. One sequence in the
  sample stands for about two-thirds of all traffic, so the weighted figure is
  close to "did it get that one right", and the report prints how much of the
  population the sample covers and how much the largest item weighs, so
  nobody mistakes it for more than it is.
- **The uniform and stratified parts apart.** The stratified part was drawn by
  the rules' own label, which makes it fair to the rules' precision and biased
  for their recall. Recall is therefore also reported on the uniform part
  alone, which was drawn without looking at any label.
- **A majority-class baseline beside every figure.** A classifier that cannot
  beat "always say the commonest class" has learned the class balance.
- **Failures counted as wrong.** A model that returns nothing for a hard item
  has not been shown to be right about it.
- **Agreement between the labellers.** The reference is only as good as the
  people who wrote it; their agreement is the ceiling worth comparing against.

Labels written under another taxonomy version are ignored, as the labelling
tool promises.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Intent
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
from honeypot_ai.evaluate.predict import Prediction
from honeypot_ai.label.sample import DrawnBy, SampleItem
from honeypot_ai.label.store import HumanLabel, latest

#: The labeller whose answers the evaluation is scored against.
DEFAULT_REFERENCE = "adjudicated"

#: Rough characters per token for English and shell text. Only used for the
#: cost estimate, which is labelled an estimate wherever it is printed.
CHARS_PER_TOKEN = 4


@dataclass(frozen=True)
class Pricing:
    """US dollars per million tokens. Zero means "not priced"."""

    input_per_mtok: float = 0.0
    output_per_mtok: float = 0.0
    output_tokens: int = 150

    @property
    def priced(self) -> bool:
        return self.input_per_mtok > 0 or self.output_per_mtok > 0


def reference_labels(labels: Sequence[HumanLabel], labeller: str) -> dict[str, HumanLabel]:
    current = [label for label in labels if label.taxonomy_version == TAXONOMY_VERSION]
    return latest(current, labeller=labeller)


def labeller_agreement(labels: Sequence[HumanLabel], reference: str) -> list[str]:
    """Pairwise intent agreement between every labeller except the reference."""
    current = [label for label in labels if label.taxonomy_version == TAXONOMY_VERSION]
    names = sorted({label.labeller for label in current} - {reference})
    lines = []
    for i, first in enumerate(names):
        for second in names[i + 1 :]:
            a, b = latest(current, first), latest(current, second)
            shared = sorted(a.keys() & b.keys())
            if not shared:
                continue
            x = [a[s].intent for s in shared]
            y = [b[s].intent for s in shared]
            same = sum(p is q for p, q in zip(x, y, strict=True))
            lines.append(
                f"- {first} vs {second}: {same}/{len(shared)} intents agree "
                f"({same / len(shared):.0%}), Cohen's kappa {cohen_kappa(x, y):.2f}"
            )
    return lines


def _pairs(
    items: Sequence[SampleItem],
    truth: dict[str, HumanLabel],
    predicted: dict[str, Prediction],
    part: DrawnBy | None = None,
) -> list[Pair]:
    return [
        Pair(truth[it.sample_id].intent, predicted[it.sample_id].intent, it.weight)
        for it in items
        if it.sample_id in truth
        and it.sample_id in predicted
        and (part is None or it.drawn_by is part)
    ]


def _fmt(value: float) -> str:
    return f"{value:.2f}"


def summary_rows(
    items: Sequence[SampleItem],
    truth: dict[str, HumanLabel],
    runs: dict[str, dict[str, Prediction]],
) -> list[str]:
    """One table comparing every classifier, baseline first."""
    header = [
        "| Classifier | Items | Failures | Accuracy | Macro-F1 | Accuracy, uniform | "
        "Macro-F1, uniform | Accuracy by session |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    rows = []
    reference = [
        Pair(truth[it.sample_id].intent, truth[it.sample_id].intent, it.weight)
        for it in items
        if it.sample_id in truth
    ]
    reference_uni = [
        Pair(truth[it.sample_id].intent, truth[it.sample_id].intent, it.weight)
        for it in items
        if it.sample_id in truth and it.drawn_by is DrawnBy.UNIFORM
    ]
    base, base_uni = majority_baseline(reference), majority_baseline(reference_uni)
    base_w = majority_baseline(reference, weighted=True)
    rows.append(
        f"| majority class | {len(reference)} | — | {_fmt(accuracy(base))} | "
        f"{_fmt(macro_f1(base))} | {_fmt(accuracy(base_uni))} | {_fmt(macro_f1(base_uni))} | "
        f"{_fmt(accuracy(base_w, weighted=True))} |"
    )
    for name, predicted in runs.items():
        pairs = _pairs(items, truth, predicted)
        uni = _pairs(items, truth, predicted, DrawnBy.UNIFORM)
        failures = sum(predicted[s].failed for s in predicted if s in truth)
        rows.append(
            f"| {name} | {len(pairs)} | {failures} | {_fmt(accuracy(pairs))} | "
            f"{_fmt(macro_f1(pairs))} | {_fmt(accuracy(uni))} | {_fmt(macro_f1(uni))} | "
            f"{_fmt(accuracy(pairs, weighted=True))} |"
        )
    return header + rows


def classifier_section(
    name: str,
    items: Sequence[SampleItem],
    truth: dict[str, HumanLabel],
    predicted: dict[str, Prediction],
    pricing: Pricing,
) -> list[str]:
    pairs = _pairs(items, truth, predicted)
    uniform = _pairs(items, truth, predicted, DrawnBy.UNIFORM)
    stratified = _pairs(items, truth, predicted, DrawnBy.STRATUM)
    missing = sum(1 for it in items if it.sample_id in truth and it.sample_id not in predicted)

    out = [f"## {name}", ""]
    if missing:
        out += [
            f"**{missing} reference item(s) have no prediction yet; scores cover the rest.**",
            "",
        ]

    out += [
        "| Part | Items | Accuracy | Macro-F1 | Baseline accuracy | Baseline macro-F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, part in (("all", pairs), ("uniform", uniform), ("stratified", stratified)):
        base = majority_baseline(part)
        out.append(
            f"| {label} | {len(part)} | {_fmt(accuracy(part))} | {_fmt(macro_f1(part))} | "
            f"{_fmt(accuracy(base))} | {_fmt(macro_f1(base))} |"
        )
    out += ["", f"Accuracy by session (weighted): {_fmt(accuracy(pairs, weighted=True))}.", ""]

    scores = per_class(pairs)
    uniform_scores = per_class(uniform)
    out += [
        "| Intent | Precision | Recall | F1 | Support | Recall, uniform | Support, uniform |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for intent, s in scores.items():
        u = uniform_scores.get(intent)
        precision = "never predicted" if s.never_predicted else _fmt(s.precision)
        u_recall = _fmt(u.recall) if u and u.support else "—"
        u_support = f"{u.support:.0f}" if u else "0"
        out.append(
            f"| {intent.value} | {precision} | {_fmt(s.recall)} | {_fmt(s.f1)} | "
            f"{s.support:.0f} | {u_recall} | {u_support} |"
        )

    out += ["", "Confusion matrix (rows: reference, columns: prediction):", ""]
    out += _confusion_table(pairs)

    latencies = [predicted[s].latency_s for s in predicted if s in truth]
    chars = [predicted[s].prompt_chars for s in predicted if s in truth]
    out += ["", _cost_line(latencies, chars, pricing), ""]
    return out


def _confusion_table(pairs: Sequence[Pair]) -> list[str]:
    matrix = confusion(pairs)
    classes = sorted({p.truth for p in pairs} | {p.predicted for p in pairs}, key=_order)
    short = [c.value.replace("_", " ") for c in classes]
    lines = ["| | " + " | ".join(short) + " |", "| --- |" + " ---: |" * len(classes)]
    for truth in classes:
        row = matrix.get(truth, Counter())
        lines.append(f"| {truth.value} | " + " | ".join(str(row.get(c, 0)) for c in classes) + " |")
    return lines


def _order(intent: Intent) -> int:
    return list(Intent).index(intent)


def _cost_line(latencies: Sequence[float], chars: Sequence[int], pricing: Pricing) -> str:
    if not latencies:
        return "No latency recorded."
    line = (
        f"Latency per item: median {statistics.median(latencies):.2f} s, "
        f"p90 {percentile(latencies, 90):.2f} s, total {sum(latencies):.1f} s."
    )
    if not any(chars):
        return line + " No model was called, so there is no token cost."
    tokens_in = statistics.mean(chars) / CHARS_PER_TOKEN
    line += f" Estimated input: {tokens_in:.0f} tokens per item (characters / {CHARS_PER_TOKEN})."
    if pricing.priced:
        cost = (
            tokens_in * pricing.input_per_mtok + pricing.output_tokens * pricing.output_per_mtok
        ) / 1_000_000
        line += (
            f" Estimated cost: ${cost:.6f} per item, ${cost * 1000:.2f} per thousand sessions, "
            f"assuming {pricing.output_tokens} output tokens."
        )
    return line


def build_report(
    items: Sequence[SampleItem],
    labels: Sequence[HumanLabel],
    runs: dict[str, dict[str, Prediction]],
    meta: dict[str, Any] | None = None,
    *,
    reference: str = DEFAULT_REFERENCE,
    pricing: Pricing | None = None,
) -> str:
    pricing = pricing or Pricing()
    truth = reference_labels(labels, reference)
    if not truth:
        raise ValueError(f"no labels by {reference!r} under taxonomy v{TAXONOMY_VERSION}")

    covered = sum(it.weight for it in items if it.sample_id in truth)
    largest = max((it.weight for it in items if it.sample_id in truth), default=0)
    population = (meta or {}).get("population", {}).get("sessions")

    out = ["# Evaluation", ""]
    out.append(
        f"Reference: `{reference}`, {len(truth)} of {len(items)} items, "
        f"taxonomy v{TAXONOMY_VERSION}."
    )
    if meta:
        out.append(
            f"Sample: seed {meta.get('seed')}, drawn {meta.get('created')}, "
            f"{meta.get('uniform')} uniform + {meta.get('per_class')} per class."
        )
    if population:
        out.append(
            f"The labelled items stand for {covered:,} of {population:,} sessions "
            f"({covered / population:.1%}); the largest single item is {largest:,} "
            f"({largest / covered:.0%} of them), so accuracy by session mostly says "
            "whether that one item is right."
        )
    agreement = labeller_agreement(labels, reference)
    if agreement:
        out += ["", "Agreement between labellers:", *agreement]

    out += ["", "## Summary", "", *summary_rows(items, truth, runs), ""]
    for name, predicted in runs.items():
        out += classifier_section(name, items, truth, predicted, pricing)
    return "\n".join(out).rstrip() + "\n"
