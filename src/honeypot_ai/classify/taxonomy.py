"""The labels this project predicts, and the rules for applying them.

Everything downstream depends on this module: the rule engine, the LLM
classifier, the labelling tool and the evaluation all import their vocabulary
from here, so a category cannot drift between them.

The taxonomy was derived from 7,735 real sessions captured by this honeypot,
not from a list of categories that sounded plausible. That ordering matters —
categories invented first and fitted to the data afterwards tend to describe
the analyst rather than the attacks.

## Two axes, not one

A session gets exactly one `Intent` and any number of `Behaviour`s.

`Intent` answers "how far did this actor get, and what were they after?" It is
single-valued because evaluation needs a single correct answer per session;
multi-label accuracy is a much harder thing to interpret, and nothing here
needs it.

`Behaviour` answers "what did they actually do?" It is multi-valued because a
session does several things, and because these are the unit that maps to
MITRE ATT&CK techniques in v0.6.0. Keeping them separate means the ATT&CK
mapping can grow without renegotiating the labels the classifier predicts.

## The precedence rule

Most sessions do more than one thing, so a label needs a tie-break that two
different people would apply the same way. The rule is: **the intent is the
furthest point reached**, along the order in `INTENT_PRECEDENCE`. A session
that fingerprints the host and then writes an SSH key is `persistence`, not
`fingerprinting`, because the fingerprinting was in service of the rest.

That is a decision, not a fact. The alternative — labelling by what the
session spent most of its commands on — would classify that same session as
fingerprinting, which is useless for triage. Recorded here so the choice is
visible rather than implicit in someone's labelling habits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Intent(StrEnum):
    """What the actor was ultimately doing. Exactly one per session."""

    PROTOCOL_PROBE = "protocol_probe"
    """Spoke a different protocol at the port entirely.

    Internet-wide census scanners send HTTP or SIP at whatever port answers,
    so the honeypot records request headers — `User-Agent: ... zgrab/0.x`,
    `CSeq: 42 OPTIONS` — where commands would be. The actor never engaged with
    the emulated shell and may not know what it reached.

    Its own category rather than `other` because conflating "ran uname on my
    host" with "spoke HTTP at my SSH port" would quietly inflate every attack
    statistic this project produces. It sits at the bottom of the precedence
    order: this is the least engagement a session can have.
    """

    CREDENTIAL_ACCESS = "credential_access"
    """Tried to log in and nothing more. No command was ever issued.

    Note this is *not* the same as "failed to log in": this honeypot accepts
    plausible credentials, so most of these authenticated successfully and
    then disconnected without doing anything. They were collecting working
    credentials, not using them.
    """

    FINGERPRINTING = "fingerprinting"
    """Established what the host is, then left.

    `uname`, `whoami`, `/proc/version`. No attempt to act on the machine. The
    overwhelming majority of sessions this honeypot sees.
    """

    SHELL_PROBING = "shell_probing"
    """Tried to obtain or confirm a usable shell.

    Sequences like `enable`, `system`, `shell`, `sh`, `linuxshell` are attempts
    to break out of the restricted menu shells that embedded devices ship with.
    `busybox` probes belong here too. The actor does not yet know whether it
    has a real shell; everything else is contingent on finding out.
    """

    RESOURCE_PROFILING = "resource_profiling"
    """Measured what the machine is worth.

    CPU model, core count, GPU presence, uptime, who else is logged in. The
    distinction from `FINGERPRINTING` is identity versus value: one asks what
    the host *is*, this asks what it is *good for*. A GPU probe on a random
    SSH host is mining reconnaissance.
    """

    STAGING = "staging"
    """Prepared the ground for a payload.

    Hunting for a directory that is both writable and executable, `chmod 777`,
    writing a throwaway script and running it to confirm execution works,
    fetching a file. The payload need not have arrived: on this sensor
    outbound traffic is blocked, so the attempt is what is recorded.
    """

    PERSISTENCE = "persistence"
    """Installed a way back in.

    Appending to `authorized_keys`, cron entries, new accounts, clearing
    immutable flags on `~/.ssh` first. The furthest an actor gets here, and
    the only intent that outlives the session.
    """

    OTHER = "other"
    """Does not fit any of the above.

    Deliberately not a dumping ground: every `OTHER` is a prompt to ask whether
    the taxonomy is missing a category. If this class grows past a few percent
    of the labelled set, the taxonomy is wrong and should change.
    """


#: Lowest to highest. A session's intent is the furthest category it reached.
#: `OTHER` is absent on purpose — it is a fallback, never a rank.
INTENT_PRECEDENCE: tuple[Intent, ...] = (
    Intent.PROTOCOL_PROBE,
    Intent.CREDENTIAL_ACCESS,
    Intent.FINGERPRINTING,
    Intent.SHELL_PROBING,
    Intent.RESOURCE_PROFILING,
    Intent.STAGING,
    Intent.PERSISTENCE,
)


class Behaviour(StrEnum):
    """Something observable the session did. Zero or more per session.

    These are the unit that maps to MITRE ATT&CK in v0.6.0, which is why they
    are narrower than intents and phrased as actions rather than goals.
    """

    # Discovery
    HOST_ENUMERATION = "host_enumeration"
    USER_ENUMERATION = "user_enumeration"
    ARCHITECTURE_DETECTION = "architecture_detection"
    CPU_PROFILING = "cpu_profiling"
    GPU_DETECTION = "gpu_detection"
    UPTIME_CHECK = "uptime_check"
    LOGIN_HISTORY_CHECK = "login_history_check"
    PROCESS_ENUMERATION = "process_enumeration"
    FILESYSTEM_DISCOVERY = "filesystem_discovery"
    NETWORK_DISCOVERY = "network_discovery"

    # Not the shell at all
    HTTP_REQUEST = "http_request"
    SIP_REQUEST = "sip_request"

    # Shell acquisition
    SHELL_ESCAPE = "shell_escape"
    SANDBOX_CHECK = "sandbox_check"
    """Testing whether the shell is real.

    `mount` shows an overlay filesystem, `env` leaks container variables,
    `/proc/self` is thin inside a jail, and an empty `history` means nobody
    has ever used this account. All four ask the same question: am I in a
    honeypot? Which makes it the most self-aware thing in the corpus."""

    OBFUSCATED_COMMAND = "obfuscated_command"
    """A command that only becomes meaningful after decoding. Recorded in its
    own right: obfuscation is a choice the actor made, and worth counting."""

    BUSYBOX_PROBE = "busybox_probe"
    MARKER_ECHO = "marker_echo"
    """Echoing a fixed string to confirm the shell executes and to identify
    itself to its own operator. Botnet families leave recognisable markers."""

    # Staging
    WRITABLE_DIR_HUNT = "writable_dir_hunt"
    PERMISSION_CHANGE = "permission_change"
    EXECUTION_TEST = "execution_test"
    PAYLOAD_DOWNLOAD = "payload_download"
    PAYLOAD_EXECUTION = "payload_execution"

    # Persistence
    SSH_DIR_RESET = "ssh_dir_reset"
    IMMUTABLE_FLAG_CLEAR = "immutable_flag_clear"
    AUTHORIZED_KEYS_WRITE = "authorized_keys_write"
    CRON_INSTALL = "cron_install"
    ACCOUNT_CREATION = "account_creation"

    # Keeping the box to themselves
    COMPETITOR_KILL = "competitor_kill"
    """Killing or deleting malware already on the host. Common enough to be
    worth its own label, but almost never the point of a session, which is why
    it is a behaviour rather than an intent."""

    HISTORY_CLEARING = "history_clearing"

    # Reaching outwards
    LATERAL_SCAN = "lateral_scan"


class Operator(StrEnum):
    """Whether a human appeared to be at the keyboard.

    Independent of intent, and worth recording separately: the proportion of
    interactive sessions is a finding in itself, and an interactive session is
    worth reading by hand whatever it was doing.
    """

    AUTOMATED = "automated"
    INTERACTIVE = "interactive"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Label:
    """One session's label, from a human or a classifier.

    `notes` exists for the labeller's reasoning. It is not an afterthought:
    the disagreements recorded there are what tell you whether the taxonomy
    itself is the problem.
    """

    session_id: str
    intent: Intent
    behaviours: frozenset[Behaviour] = field(default_factory=frozenset)
    operator: Operator = Operator.UNKNOWN
    confidence: float | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be between 0 and 1, got {self.confidence}")


def resolve_intent(candidates: set[Intent] | frozenset[Intent]) -> Intent:
    """Collapse several applicable intents into the one the session gets.

    Applies the precedence rule: the furthest point reached wins. An empty set
    means nothing was recognised, which is `OTHER` and not an error — an
    unrecognised session is a finding, not a bug.
    """
    ranked = [intent for intent in INTENT_PRECEDENCE if intent in candidates]
    if not ranked:
        return Intent.OTHER
    return ranked[-1]


def intent_rank(intent: Intent) -> int:
    """Position in the precedence order; -1 for `OTHER`, which has no rank."""
    try:
        return INTENT_PRECEDENCE.index(intent)
    except ValueError:
        return -1
