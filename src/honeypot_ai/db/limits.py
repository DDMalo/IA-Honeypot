"""The one limit that keeps breaking this pipeline.

PostgreSQL's wire protocol allows at most 65,535 bind parameters in a single
statement. Nothing in SQLAlchemy warns about approaching it: a query is built,
it works on every dataset anyone tested it against, and then one day a busy
backlog pushes it over and the statement fails outright — taking the whole run
with it, with the error buried under forty thousand lines of parameter dump.

It has happened twice here, in two different modules, for the same reason both
times: a list whose length is a property of the data rather than of the code.
A multi-row INSERT spends one parameter per column per row. An `IN (...)` over
a Python list spends one per element. Neither is bounded by batching sessions,
because a batch of sessions holds an arbitrary number of commands and a run
holds an arbitrary number of sessions.

An `IN` over a *subquery* spends none, and is the better fix where the values
are already in the database. This module is for the cases where they are not.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

#: PostgreSQL's protocol-level ceiling on bind parameters per statement.
MAX_BIND_PARAMETERS = 65_535


def rows_per_statement(columns: int) -> int:
    """How many rows of this width fit under the limit.

    At least one, always: a row wider than the whole budget would otherwise
    divide to zero and loop forever rather than fail.
    """
    return max(1, MAX_BIND_PARAMETERS // max(1, columns))


def chunked[T](items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    """Yield slices of at most `size`, and nothing at all for an empty input."""
    for start in range(0, len(items), max(1, size)):
        yield items[start : start + size]


def in_chunks[T](values: Sequence[T], spare: int = 8) -> Iterator[Sequence[T]]:
    """Split values destined for an `IN (...)` so each statement stays legal.

    `spare` leaves room for the handful of other parameters the same statement
    carries — a classifier name, a cutoff date — which would otherwise push a
    chunk sized exactly to the limit one parameter over it.
    """
    yield from chunked(values, MAX_BIND_PARAMETERS - spare)
