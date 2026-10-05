"""Deleting data once it has served its purpose.

Captured sessions contain IP addresses, which are personal data: keeping them
indefinitely needs a justification, and "it might be useful one day" is not
one. Retention is therefore a feature of the pipeline rather than an
afterthought, and the schema was built so that enforcing it is a `DELETE`
rather than a script — foreign keys cascade, so removing a session removes
everything attached to it.
"""

from honeypot_ai.retention.policy import (
    DEFAULT_SESSION_DAYS,
    RetentionStats,
    apply_retention,
    prune_orphaned_intel,
    prune_sessions,
)

__all__ = [
    "DEFAULT_SESSION_DAYS",
    "RetentionStats",
    "apply_retention",
    "prune_orphaned_intel",
    "prune_sessions",
]
