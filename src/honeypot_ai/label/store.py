"""The two files that make up the evaluation set.

`eval/sample.jsonl` is what to label: anonymised sessions, frozen once drawn.
`eval/labels.jsonl` is what a person said about them.

They are separate on purpose. The sample is regenerated rarely and never
while anyone is labelling it — redrawing it would orphan every label already
written — so the tool refuses to overwrite one without `--force`. The labels
are append-only: changing your mind about a session adds a line rather than
editing one, and the latest line per labeller wins. The history of second
thoughts is kept, because a session two careful readings disagreed about is
worth knowing about in its own right.

Both are JSON Lines, so a diff of either in review shows exactly which items
changed and nothing else.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Behaviour, Intent, Operator
from honeypot_ai.label.sample import DrawnBy, SampleItem

DEFAULT_SAMPLE = Path("eval/sample.jsonl")
DEFAULT_LABELS = Path("eval/labels.jsonl")
DEFAULT_META = Path("eval/sample-meta.json")


@dataclass(frozen=True)
class HumanLabel:
    """One person's answer about one item."""

    sample_id: str
    intent: Intent
    behaviours: frozenset[Behaviour]
    operator: Operator
    labeller: str
    labelled_at: datetime
    taxonomy_version: int = TAXONOMY_VERSION
    notes: str | None = None


def _facts_to_json(facts: SessionFacts) -> dict[str, Any]:
    return {
        "session_id": facts.session_id,
        "commands": list(facts.commands),
        "authenticated": facts.authenticated,
        "download_urls": list(facts.download_urls),
        "captured_hashes": list(facts.captured_hashes),
        "command_gaps": [round(gap, 3) for gap in facts.command_gaps],
    }


def _facts_from_json(data: dict[str, Any]) -> SessionFacts:
    return SessionFacts(
        session_id=data["session_id"],
        commands=tuple(data["commands"]),
        authenticated=data["authenticated"],
        download_urls=tuple(data["download_urls"]),
        captured_hashes=tuple(data["captured_hashes"]),
        command_gaps=tuple(data["command_gaps"]),
    )


def write_sample(items: Iterable[SampleItem], path: Path = DEFAULT_SAMPLE) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            record = {
                "sample_id": item.sample_id,
                "session_id": item.session_id,
                "stratum": item.stratum.value,
                "weight": item.weight,
                "drawn_by": item.drawn_by.value,
                "facts": _facts_to_json(item.facts),
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1
    return count


def read_sample(path: Path = DEFAULT_SAMPLE) -> list[SampleItem]:
    items = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            items.append(
                SampleItem(
                    sample_id=record["sample_id"],
                    session_id=record["session_id"],
                    stratum=Intent(record["stratum"]),
                    weight=record["weight"],
                    drawn_by=DrawnBy(record["drawn_by"]),
                    facts=_facts_from_json(record["facts"]),
                )
            )
    return items


def append_label(label: HumanLabel, path: Path = DEFAULT_LABELS) -> None:
    """Write one label immediately, so a crash or a Ctrl-C loses nothing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "sample_id": label.sample_id,
        "intent": label.intent.value,
        "behaviours": sorted(b.value for b in label.behaviours),
        "operator": label.operator.value,
        "labeller": label.labeller,
        "labelled_at": label.labelled_at.isoformat(),
        "taxonomy_version": label.taxonomy_version,
        "notes": label.notes,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_labels(path: Path = DEFAULT_LABELS) -> list[HumanLabel]:
    """Every line, oldest first. See `latest` for the current answers."""
    if not path.exists():
        return []
    labels = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            labels.append(
                HumanLabel(
                    sample_id=record["sample_id"],
                    intent=Intent(record["intent"]),
                    behaviours=frozenset(Behaviour(b) for b in record["behaviours"]),
                    operator=Operator(record["operator"]),
                    labeller=record["labeller"],
                    labelled_at=datetime.fromisoformat(record["labelled_at"]),
                    taxonomy_version=record["taxonomy_version"],
                    notes=record.get("notes"),
                )
            )
    return labels


def latest(labels: Iterable[HumanLabel], labeller: str | None = None) -> dict[str, HumanLabel]:
    """The current answer per item: the last line written wins."""
    current: dict[str, HumanLabel] = {}
    for label in labels:
        if labeller is None or label.labeller == labeller:
            current[label.sample_id] = label
    return current


def now() -> datetime:
    return datetime.now(UTC)
