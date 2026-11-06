"""Run a classifier over the evaluation sample and keep what it said.

Predictions are written to `eval/predictions/<classifier>.jsonl`, one line per
item, and committed. Two reasons. A paid model run once is a result anyone can
re-score without a key or a bill; and a model that is later retired or changed
behind the same name cannot quietly rewrite a comparison that was already
published.

The classifier sees the anonymised facts in `eval/sample.jsonl`, never the
database. That is what makes a prediction reproducible by somebody who does not
have the homelab, and the anonymiser's own test is what makes it fair: it
checks, on every export, that anonymising changes nothing the rules conclude.

A run can be interrupted and resumed. Items already predicted by the same
classifier are skipped, so a rate-limited free tier can be worked through over
several sittings without paying twice for the same answer.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Behaviour, Intent, Label, Operator
from honeypot_ai.label.sample import SampleItem

DEFAULT_DIR = Path("eval/predictions")

Classify = Callable[[SessionFacts], Label]
#: How long a prompt is, for the cost estimate. Zero for anything with no prompt.
PromptSize = Callable[[SessionFacts], int]

#: What the LLM classifier writes in `notes` when it gave up on an item.
_FAILURE_PREFIX = "unclassified:"


@dataclass(frozen=True)
class Prediction:
    sample_id: str
    classifier: str
    intent: Intent
    behaviours: frozenset[Behaviour]
    operator: Operator
    confidence: float | None
    notes: str | None
    #: Wall-clock seconds for this item, retries included.
    latency_s: float
    #: Characters sent to the model, system prompt included.
    prompt_chars: int
    predicted_at: datetime
    taxonomy_version: int = TAXONOMY_VERSION

    @property
    def failed(self) -> bool:
        """The classifier produced no answer. Scored as wrong, not left out:
        dropping failures would flatter whichever model fails most."""
        return (self.notes or "").startswith(_FAILURE_PREFIX)


def file_for(classifier: str, directory: Path = DEFAULT_DIR) -> Path:
    """`gemini:gemini-3.5-flash-lite` → `gemini_gemini-3.5-flash-lite.jsonl`."""
    return directory / (re.sub(r"[^A-Za-z0-9._-]", "_", classifier) + ".jsonl")


def predict(
    items: Sequence[SampleItem],
    classify: Classify,
    classifier: str,
    path: Path,
    *,
    prompt_size: PromptSize = lambda _facts: 0,
    limit: int | None = None,
    clock: Callable[[], float] = time.perf_counter,
    on_item: Callable[[Prediction], None] = lambda _p: None,
) -> int:
    """Predict every item not yet predicted, saving each as it is made."""
    done = {p.sample_id for p in read_predictions(path) if p.classifier == classifier}
    todo = [item for item in items if item.sample_id not in done]
    if limit is not None:
        todo = todo[:limit]

    for item in todo:
        started = clock()
        label = classify(item.facts)
        elapsed = clock() - started
        prediction = Prediction(
            sample_id=item.sample_id,
            classifier=classifier,
            intent=label.intent,
            behaviours=label.behaviours,
            operator=label.operator,
            confidence=label.confidence,
            notes=label.notes,
            latency_s=round(elapsed, 3),
            prompt_chars=prompt_size(item.facts),
            predicted_at=datetime.now(UTC),
        )
        append_prediction(prediction, path)
        on_item(prediction)
    return len(todo)


def append_prediction(prediction: Prediction, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "sample_id": prediction.sample_id,
        "classifier": prediction.classifier,
        "intent": prediction.intent.value,
        "behaviours": sorted(b.value for b in prediction.behaviours),
        "operator": prediction.operator.value,
        "confidence": prediction.confidence,
        "notes": prediction.notes,
        "latency_s": prediction.latency_s,
        "prompt_chars": prediction.prompt_chars,
        "predicted_at": prediction.predicted_at.isoformat(),
        "taxonomy_version": prediction.taxonomy_version,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_predictions(path: Path) -> list[Prediction]:
    if not path.exists():
        return []
    out = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            r = json.loads(line)
            out.append(
                Prediction(
                    sample_id=r["sample_id"],
                    classifier=r["classifier"],
                    intent=Intent(r["intent"]),
                    behaviours=frozenset(Behaviour(b) for b in r["behaviours"]),
                    operator=Operator(r["operator"]),
                    confidence=r["confidence"],
                    notes=r["notes"],
                    latency_s=r["latency_s"],
                    prompt_chars=r["prompt_chars"],
                    predicted_at=datetime.fromisoformat(r["predicted_at"]),
                    taxonomy_version=r["taxonomy_version"],
                )
            )
    return out


def latest_predictions(predictions: Iterable[Prediction]) -> dict[str, Prediction]:
    """One answer per item and current taxonomy: the last line written wins."""
    current: dict[str, Prediction] = {}
    for prediction in predictions:
        if prediction.taxonomy_version == TAXONOMY_VERSION:
            current[prediction.sample_id] = prediction
    return current
