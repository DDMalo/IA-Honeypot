"""The labelling loop: show a session, ask what it was, write the answer.

**Blind, by construction.** The person labelling sees nothing a classifier
could not see: the commands, whether the login succeeded, the download
attempts, the timing. Not the rule engine's label, not any model's, not the
country or the reputation of the address, and not how many other sessions
shared this sequence. Every one of those would anchor the answer, and an
evaluation built on labels formed by looking at the rules' output measures
how persuadable the labeller was rather than how right the rules were.

The sample file does record each item's stratum — the rules' label — because
the evaluation needs it to reweight the results. This module never prints it.

Input and output are passed in rather than taken from the terminal, which is
what lets the whole loop be tested by scripting the answers.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import (
    INTENT_DEFINITIONS,
    INTENT_PRECEDENCE,
    Behaviour,
    Intent,
    Operator,
)
from honeypot_ai.label.sample import SampleItem
from honeypot_ai.label.store import DEFAULT_LABELS, HumanLabel, append_label, now

#: Offered in precedence order, with `other` last, so the menu itself is a
#: reminder of the rule that decides between them.
INTENT_MENU: tuple[Intent, ...] = (*INTENT_PRECEDENCE, Intent.OTHER)
BEHAVIOUR_MENU: tuple[Behaviour, ...] = tuple(Behaviour)

#: Sessions this long are shown head and tail. The 13 October dropper ran 575
#: commands, almost all of them the same shape, and nobody reads 575 lines.
HEAD_LINES = 40
TAIL_LINES = 10


class Quit(Exception):
    """The labeller asked to stop. Everything so far is already saved."""


class Skip(Exception):
    """Not this one, not now. Asked again next time."""


Ask = Callable[[str], str]
Say = Callable[[str], None]


def collapse(commands: Sequence[str]) -> list[tuple[str, int]]:
    """Consecutive repeats as one line with a count.

    A presentation aid, not a summary: nothing is dropped, and the count is
    what a reader would otherwise have had to work out by scrolling.
    """
    runs: list[tuple[str, int]] = []
    for command in commands:
        if runs and runs[-1][0] == command:
            runs[-1] = (command, runs[-1][1] + 1)
        else:
            runs.append((command, 1))
    return runs


def render(facts: SessionFacts) -> str:
    """The session as a person reads it. No label of any kind is shown."""
    lines: list[str] = []
    login = "succeeded" if facts.authenticated else "did not succeed"
    lines.append(f"login {login} · {len(facts.commands)} command(s)")

    if facts.command_gaps:
        median = statistics.median(facts.command_gaps)
        total = sum(facts.command_gaps)
        lines.append(f"median gap {median:.2f}s · first to last {total:.1f}s")

    runs = collapse(facts.commands)
    if not runs:
        lines.append("  (no commands)")

    shown = runs if len(runs) <= HEAD_LINES + TAIL_LINES else None
    if shown is None:
        head, tail = runs[:HEAD_LINES], runs[-TAIL_LINES:]
        hidden = len(runs) - HEAD_LINES - TAIL_LINES
        blocks = [*head, (f"… {hidden} more line(s) …", 0), *tail]
    else:
        blocks = shown

    for index, (command, count) in enumerate(blocks, start=1):
        if count == 0:
            lines.append(f"       {command}")
            continue
        suffix = f"   ×{count}" if count > 1 else ""
        # Multi-line commands — a script pasted in one go — keep their shape.
        body = command.replace("\n", "\n        ")
        lines.append(f"  {index:>3}  {body}{suffix}")

    if facts.download_urls:
        lines.append("download attempts:")
        lines.extend(f"       {url}" for url in facts.download_urls)
    if facts.captured_hashes:
        lines.append(f"{len(facts.captured_hashes)} file(s) captured")

    return "\n".join(lines)


def help_text() -> str:
    lines = ["Intent is the furthest point reached, in this order:", ""]
    for number, intent in enumerate(INTENT_MENU, start=1):
        lines.append(f"  {number}  {intent.value:<19} {INTENT_DEFINITIONS[intent]}")
    lines += ["", "Behaviours (any number, by number or name):", ""]
    for number, behaviour in enumerate(BEHAVIOUR_MENU, start=1):
        lines.append(f"  {number:>2}  {behaviour.value}")
    lines += ["", "s skip · q quit · ? this help"]
    return "\n".join(lines)


def _control(answer: str) -> None:
    if answer == "q":
        raise Quit
    if answer == "s":
        raise Skip


def parse_intent(answer: str) -> Intent | None:
    answer = answer.strip().lower()
    if answer.isdigit() and 1 <= int(answer) <= len(INTENT_MENU):
        return INTENT_MENU[int(answer) - 1]
    matches = (
        [intent for intent in INTENT_MENU if intent.value.startswith(answer)] if answer else []
    )
    return matches[0] if len(matches) == 1 else None


def parse_behaviours(answer: str) -> frozenset[Behaviour] | None:
    """Numbers or names, separated by commas or spaces. Empty is a valid "none"."""
    picked: set[Behaviour] = set()
    for token in answer.replace(",", " ").split():
        token = token.lower()
        if token.isdigit() and 1 <= int(token) <= len(BEHAVIOUR_MENU):
            picked.add(BEHAVIOUR_MENU[int(token) - 1])
            continue
        try:
            picked.add(Behaviour(token))
        except ValueError:
            return None
    return frozenset(picked)


def parse_operator(answer: str) -> Operator | None:
    return {
        "a": Operator.AUTOMATED,
        "i": Operator.INTERACTIVE,
        "u": Operator.UNKNOWN,
        "": Operator.UNKNOWN,
    }.get(answer.strip().lower())


def _ask_until[T](ask: Ask, say: Say, prompt: str, parse: Callable[[str], T | None]) -> T:
    while True:
        answer = ask(prompt).strip()
        if answer == "?":
            say(help_text())
            continue
        _control(answer.lower())
        value = parse(answer)
        if value is not None:
            return value
        say("  not understood — a number, a name, or ? for the list")


def label_one(item: SampleItem, labeller: str, ask: Ask, say: Say) -> HumanLabel:
    say(render(item.facts))
    intent = _ask_until(ask, say, "intent [1-8, ?]: ", parse_intent)
    behaviours = _ask_until(ask, say, "behaviours [numbers, blank for none]: ", parse_behaviours)
    operator = _ask_until(
        ask, say, "operator [a]utomated [i]nteractive [u]nknown: ", parse_operator
    )
    notes = ask("notes (optional): ").strip() or None
    return HumanLabel(
        sample_id=item.sample_id,
        intent=intent,
        behaviours=behaviours,
        operator=operator,
        labeller=labeller,
        labelled_at=now(),
        notes=notes,
    )


@dataclass
class ReviewStats:
    labelled: int = 0
    skipped: int = 0
    remaining: int = 0

    def __str__(self) -> str:
        return (
            f"{self.labelled} labelled this sitting, {self.skipped} skipped, "
            f"{self.remaining} still to do"
        )


def review(
    items: Sequence[SampleItem],
    done: set[str],
    labeller: str,
    ask: Ask,
    say: Say,
    labels_path: Path = DEFAULT_LABELS,
) -> ReviewStats:
    """Label every item not yet done, saving each answer as it is given."""
    todo = [item for item in items if item.sample_id not in done]
    stats = ReviewStats(remaining=len(todo))

    for position, item in enumerate(todo, start=1):
        say(f"\n── {position}/{len(todo)} · {item.sample_id} " + "─" * 40)
        try:
            label = label_one(item, labeller, ask, say)
        except Skip:
            stats.skipped += 1
            continue
        except Quit:
            break
        append_label(label, labels_path)
        stats.labelled += 1
        stats.remaining -= 1

    return stats
