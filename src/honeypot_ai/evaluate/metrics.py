"""The numbers, as pure functions over (truth, prediction) pairs.

Nothing here reads a file or knows what a classifier is, which is what lets
every figure in the report be checked against a hand-worked example in the
tests. Three choices are made once, here, rather than wherever a number is
printed:

**Macro averages run over the classes in the reference.** A class nobody
labelled has no recall to measure, and averaging a zero for it in would punish
a classifier for the shape of the sample rather than for its answers. A class
a classifier predicts that the reference never contains still costs it, in the
precision of nothing and the recall of whatever it took the place of.

**Undefined is zero, and said so.** Precision for a class a classifier never
predicted is 0/0. It is scored as zero, the usual convention, and the report
marks it, because "0.00" and "never predicted it" are not the same finding.

**Weights are optional everywhere.** The same function answers "how often is
it right about a kind of behaviour" (each distinct sequence counts once) and
"how often is it right about a session" (each counts by how many sessions
shared it). Those are different numbers, and the report prints both.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from honeypot_ai.classify.taxonomy import Intent


@dataclass(frozen=True)
class Pair:
    """One item: what the reference says, what the classifier said."""

    truth: Intent
    predicted: Intent
    weight: float = 1.0


@dataclass(frozen=True)
class ClassScore:
    precision: float
    recall: float
    f1: float
    #: How many reference items (or how much weight) are in this class.
    support: float
    #: How many items the classifier put in this class.
    predicted: float

    @property
    def never_predicted(self) -> bool:
        return self.predicted == 0


def accuracy(pairs: Sequence[Pair], *, weighted: bool = False) -> float:
    total = sum(_w(p, weighted) for p in pairs)
    if total == 0:
        return 0.0
    return sum(_w(p, weighted) for p in pairs if p.truth is p.predicted) / total


def per_class(pairs: Sequence[Pair], *, weighted: bool = False) -> dict[Intent, ClassScore]:
    """Precision, recall and F1 for every class that appears on either side."""
    classes = {p.truth for p in pairs} | {p.predicted for p in pairs}
    scores: dict[Intent, ClassScore] = {}
    for intent in sorted(classes, key=lambda i: i.value):
        hit = sum(_w(p, weighted) for p in pairs if p.truth is intent and p.predicted is intent)
        support = sum(_w(p, weighted) for p in pairs if p.truth is intent)
        predicted = sum(_w(p, weighted) for p in pairs if p.predicted is intent)
        precision = hit / predicted if predicted else 0.0
        recall = hit / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        scores[intent] = ClassScore(precision, recall, f1, support, predicted)
    return scores


def macro_f1(pairs: Sequence[Pair], *, weighted: bool = False) -> float:
    """Mean F1 over the classes the reference contains."""
    scores = per_class(pairs, weighted=weighted)
    present = [score.f1 for score in scores.values() if score.support > 0]
    return sum(present) / len(present) if present else 0.0


def confusion(pairs: Sequence[Pair]) -> dict[Intent, Counter[Intent]]:
    """Rows are the reference, columns the prediction. Unweighted."""
    matrix: dict[Intent, Counter[Intent]] = {}
    for pair in pairs:
        matrix.setdefault(pair.truth, Counter())[pair.predicted] += 1
    return matrix


def majority_baseline(pairs: Sequence[Pair], *, weighted: bool = False) -> list[Pair]:
    """The same items, answered by always saying the commonest class.

    A classifier that cannot beat this has learned the class balance and
    nothing else. With one sequence making up two-thirds of all sessions, the
    weighted version of this baseline is a high bar, and it should be.
    """
    if not pairs:
        return []
    counts: dict[Intent, float] = {}
    for pair in pairs:
        counts[pair.truth] = counts.get(pair.truth, 0.0) + _w(pair, weighted)
    # Ties broken by name, so the baseline does not depend on input order.
    commonest = min(counts, key=lambda intent: (-counts[intent], intent.value))
    return [Pair(p.truth, commonest, p.weight) for p in pairs]


def cohen_kappa(first: Sequence[Intent], second: Sequence[Intent]) -> float:
    """Agreement between two labellers beyond what chance would give."""
    if len(first) != len(second):
        raise ValueError("both labellers must label the same items")
    n = len(first)
    if n == 0:
        return 0.0
    observed = sum(a is b for a, b in zip(first, second, strict=True)) / n
    a_counts, b_counts = Counter(first), Counter(second)
    expected = sum(a_counts[k] * b_counts[k] for k in a_counts.keys() | b_counts.keys()) / n / n
    if expected == 1:
        return 1.0
    return (observed - expected) / (1 - expected)


def mcnemar(first_right: Sequence[bool], second_right: Sequence[bool]) -> tuple[int, int, float]:
    """Exact two-sided McNemar test on paired right/wrong answers.

    Only the items the two classifiers disagree on carry information: `b` the
    first got right and the second wrong, `c` the reverse. Returns `(b, c, p)`.
    Exact rather than the chi-squared approximation, because with 140 items the
    discordant count can be small enough for the approximation to mislead.
    """
    if len(first_right) != len(second_right):
        raise ValueError("both classifiers must answer the same items")
    b = sum(x and not y for x, y in zip(first_right, second_right, strict=True))
    c = sum(y and not x for x, y in zip(first_right, second_right, strict=True))
    n = b + c
    if n == 0:
        return b, c, 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2**n
    return b, c, min(1.0, 2 * tail)


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile, `q` between 0 and 100."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def _w(pair: Pair, weighted: bool) -> float:
    return pair.weight if weighted else 1.0
