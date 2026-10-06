"""A rule engine that labels a session from its commands.

This exists to be beaten. Its real job is to be the baseline the language
model in v0.4.0 has to improve on — because "the model got 0.89" means nothing
without a number next to it, and because a rule engine is the honest
comparison: it is free, instant, deterministic, and on data this repetitive it
is going to be hard to beat.

Every pattern here was written against commands this honeypot actually
received. None of them are guesses about what attackers might type.

## How a label is produced

Each rule matches a `Behaviour`. Behaviours that imply an intent contribute a
candidate, and `resolve_intent` keeps the furthest one along the kill chain.
Nothing votes or scores: the taxonomy's precedence rule decides, so the rule
engine and a human labeller following `docs/taxonomy.md` reach the same
answer for the same reason.

## What the confidence means

It is **coverage**, not certainty: the share of a session's commands that
matched at least one rule. A label drawn from two recognised commands out of
twenty deserves suspicion, and this is the number that says so. It is not a
probability and must not be read as one — which is exactly the sort of thing
that gets forgotten, so it is written down here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Label, Operator, resolve_intent


@dataclass(frozen=True)
class Rule:
    """One pattern, the behaviour it evidences, and the intent that implies.

    `intent` is `None` for behaviours that say nothing about how far an actor
    got. Killing competing malware is a good example: it is worth recording,
    but it happens at every stage and on its own places nobody anywhere.
    """

    behaviour: Behaviour
    pattern: re.Pattern[str]
    intent: Intent | None = None
    why: str = ""


def _rule(behaviour: Behaviour, pattern: str, intent: Intent | None = None, why: str = "") -> Rule:
    return Rule(behaviour, re.compile(pattern, re.IGNORECASE), intent, why)


#: Ordered for readability only; every rule is tested against every command.
RULES: tuple[Rule, ...] = (
    # ---- Discovery -------------------------------------------------------
    _rule(
        Behaviour.HOST_ENUMERATION,
        r"\buname\b|/proc/version|/etc/os-release|\bhostname(ctl)?\b|\bssh\s+-V\b",
        Intent.FINGERPRINTING,
        "asks what the host is, or what software it runs",
    ),
    _rule(
        Behaviour.USER_ENUMERATION,
        r"\bwhoami\b|/etc/passwd|/etc/shadow|\becho\s+\$user\b|\bid\s*$",
        Intent.FINGERPRINTING,
        "asks who it is running as",
    ),
    _rule(
        Behaviour.ARCHITECTURE_DETECTION,
        r"uname\s+-[a-z]*m|\barch=|\bx86_64\b|\baarch64\b|\barmv7l\b",
        Intent.FINGERPRINTING,
        "picks the right binary to deliver later",
    ),
    _rule(
        Behaviour.CPU_PROFILING,
        r"\blscpu\b|\bnproc\b|/proc/cpuinfo|model\s+name",
        Intent.RESOURCE_PROFILING,
        "measures compute worth stealing",
    ),
    _rule(
        Behaviour.GPU_DETECTION,
        r"\blspci\b|\bnvidia\b|\bvga\b|nvidia-smi",
        Intent.RESOURCE_PROFILING,
        "nothing legitimate asks an anonymous SSH host about its graphics card",
    ),
    _rule(
        Behaviour.UPTIME_CHECK,
        r"/proc/uptime|\buptime\b",
        Intent.RESOURCE_PROFILING,
        "a long uptime means an unattended machine",
    ),
    _rule(
        Behaviour.LOGIN_HISTORY_CHECK,
        r"^\s*last\b|\blast\s+-|\bwho\b|\bw\s*$|/var/log/wtmp",
        Intent.RESOURCE_PROFILING,
        "checks whether anyone else is watching",
    ),
    _rule(
        Behaviour.FILESYSTEM_DISCOVERY,
        r"^\s*(pwd|ls(\s+-\S+)*(\s+/\S*)?|df|du|find\s+/)\s*$|\bls\s+-la\b|\bfind\s+/\s",
        Intent.FINGERPRINTING,
        "looks around the filesystem",
    ),
    _rule(
        Behaviour.NETWORK_DISCOVERY,
        r"\bnetstat\b|\bss\s+-|\bifconfig\b|\bip\s+a(ddr)?\b|\barp\s+-|/proc/net/",
        Intent.FINGERPRINTING,
        "looks at what the host is connected to",
    ),
    _rule(
        Behaviour.PROCESS_ENUMERATION,
        r"\bps\s+-|\bps\s+aux|/proc/\*|proc_dir|\btop\b",
        None,
        "looks at what is running; happens at every stage",
    ),
    # ---- Not the shell at all --------------------------------------------
    _rule(
        Behaviour.HTTP_REQUEST,
        r"^\s*(get|post|head)\s+\S+\s+http/\d|^\s*(user-agent|accept|accept-encoding|host"
        r"|connection|content-length):",
        Intent.PROTOCOL_PROBE,
        "an HTTP request sent at a port that does not speak HTTP",
    ),
    _rule(
        Behaviour.SIP_REQUEST,
        r"^\s*(call-id|cseq|max-forwards|via|from|to):\s|sip:",
        Intent.PROTOCOL_PROBE,
        "a SIP probe; census scanners try every protocol on every port",
    ),
    # ---- Getting a shell -------------------------------------------------
    _rule(
        Behaviour.SHELL_ESCAPE,
        r"^\s*(enable|system|shell|linuxshell|sh|ping;\s*sh)\s*$",
        Intent.SHELL_PROBING,
        "escape words for the restricted menus on embedded devices",
    ),
    _rule(
        Behaviour.BUSYBOX_PROBE,
        r"\bbusybox\b",
        Intent.SHELL_PROBING,
        "the shell that ships on routers, cameras and recorders",
    ),
    _rule(
        Behaviour.MARKER_ECHO,
        r"echo\s+(-e\s+)?[\"']?(\\x[0-9a-f]{2}){3,}|echo\s+xsec\b",
        Intent.SHELL_PROBING,
        "confirms the shell runs, and announces the family to its operator",
    ),
    # ---- Staging ---------------------------------------------------------
    _rule(
        Behaviour.WRITABLE_DIR_HUNT,
        r">\s*/\S*/?\.\w+\s*&&\s*chmod",
        Intent.STAGING,
        "hunting for somewhere both writable and executable",
    ),
    _rule(
        Behaviour.PERMISSION_CHANGE,
        r"\bchmod\b",
        None,
        "on its own says nothing; the surrounding rule does",
    ),
    _rule(
        Behaviour.EXECUTION_TEST,
        r"chmod\s+\+x\s+\S+\s*&&\s*\./|printf\s+[\"']#!/bin/",
        Intent.STAGING,
        "writes a throwaway script and runs it to prove execution works",
    ),
    _rule(
        Behaviour.PAYLOAD_DOWNLOAD,
        r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\bnc\s+\S+\s+\d+\s*>",
        Intent.STAGING,
        "fetching the payload; blocked on this sensor, but the attempt counts",
    ),
    # ---- Persistence -----------------------------------------------------
    _rule(
        Behaviour.IMMUTABLE_FLAG_CLEAR,
        r"\bchattr\s+-\w*i|\blockr\s+-\w*i",
        Intent.PERSISTENCE,
        "unlocks a directory a previous occupant protected",
    ),
    _rule(
        Behaviour.SSH_DIR_RESET,
        r"rm\s+-rf\s+[^\n]*\.ssh|mkdir\s+[^\n]*\.ssh",
        Intent.PERSISTENCE,
        "clears out whatever keys were there first",
    ),
    _rule(
        Behaviour.AUTHORIZED_KEYS_WRITE,
        r"authorized_keys",
        Intent.PERSISTENCE,
        "the way back in that outlives the session",
    ),
    _rule(
        Behaviour.CRON_INSTALL,
        r"\bcrontab\b|/etc/cron|/var/spool/cron",
        Intent.PERSISTENCE,
        "scheduled re-entry",
    ),
    _rule(
        Behaviour.ACCOUNT_CREATION,
        r"\buseradd\b|\badduser\b|>>\s*/etc/passwd",
        Intent.PERSISTENCE,
        "an account of their own",
    ),
    # ---- Holding the box -------------------------------------------------
    _rule(
        Behaviour.COMPETITOR_KILL,
        r"kill\s+-9|\bpkill\b|\(deleted\)",
        None,
        "malware removing other malware; happens at every stage",
    ),
    _rule(
        Behaviour.HISTORY_CLEARING,
        r"history\s+-c|unset\s+histfile|rm\s+[^\n]*bash_history|/dev/null\s*>\s*[^\n]*history",
        None,
        "covering tracks says nothing about the goal",
    ),
    # ---- Reaching outwards -----------------------------------------------
    _rule(
        Behaviour.LATERAL_SCAN,
        r"\bmasscan\b|\bzmap\b|\bnmap\b|\bssh\s+\w+@",
        None,
        "moving on to somebody else",
    ),
)


#: Single-byte XOR keys worth trying. Deliberately small: every extra key is
#: another chance to turn noise into a false match, and 0x09 is the one this
#: honeypot has actually seen.
XOR_KEYS: tuple[int, ...] = (0x09,)


def deobfuscate(command: str) -> str | None:
    """Return a decoded form of `command` if one is both printable and known.

    Some sessions arrive as `lghkel`, `zpz}ld`, `zalee`, `za`. Decoded with a
    single-byte XOR of 0x09 those are `enable`, `system`, `shell`, `sh` — the
    same restricted-shell escape sequence as every other Mirai-family session,
    sent through a client that obfuscates it.

    The decode is deliberately conservative. A candidate is accepted only when
    it is printable **and** matches a rule that already exists, so this can add
    a match that was missed but can never invent a category or override a
    plain-text one. That asymmetry is the point: a decoder that is allowed to
    reinterpret anything will eventually reinterpret something real.
    """
    for key in XOR_KEYS:
        candidate = "".join(chr(ord(character) ^ key) for character in command)
        if not candidate.isprintable():
            continue
        if any(rule.pattern.search(candidate) for rule in RULES):
            return candidate
    return None


#: Below this gap, nobody typed it. Generous on purpose: the claim being made
#: is only "certainly a script", never "certainly a person".
AUTOMATED_GAP_SECONDS = 1.0


def match_behaviours(facts: SessionFacts) -> tuple[frozenset[Behaviour], int]:
    """Every behaviour the rules recognise, and how many commands matched one.

    The count is returned alongside because coverage is the only honest
    confidence a rule engine can offer.
    """
    found: set[Behaviour] = set()
    matched_commands = 0

    for raw in facts.commands:
        hit = False
        for rule in RULES:
            if rule.pattern.search(raw):
                found.add(rule.behaviour)
                hit = True

        if not hit:
            decoded = deobfuscate(raw)
            if decoded is not None:
                found.add(Behaviour.OBFUSCATED_COMMAND)
                for rule in RULES:
                    if rule.pattern.search(decoded):
                        found.add(rule.behaviour)
                        hit = True

        if hit:
            matched_commands += 1

    # Transfers are evidence in their own right: Cowrie records a download
    # Cowrie itself performed, which no command text need mention.
    if facts.download_urls:
        found.add(Behaviour.PAYLOAD_DOWNLOAD)
    if facts.captured_hashes:
        found.add(Behaviour.PAYLOAD_EXECUTION)

    return frozenset(found), matched_commands


def infer_operator(facts: SessionFacts) -> Operator:
    """Whether this was certainly a script.

    Asymmetric on purpose. Commands arriving milliseconds apart were not
    typed, so that is a safe `AUTOMATED`. The converse does not hold — a script
    with `sleep` in it looks exactly like a slow human — so a slow session is
    `UNKNOWN`, never `INTERACTIVE`. Deciding that a human was present is a
    judgement, and this module does not make judgements.
    """
    if len(facts.commands) < 2 or not facts.command_gaps:
        return Operator.UNKNOWN
    if max(facts.command_gaps) < AUTOMATED_GAP_SECONDS:
        return Operator.AUTOMATED
    return Operator.UNKNOWN


def classify(facts: SessionFacts) -> Label:
    """Label one session."""
    if not facts.commands and not facts.download_urls:
        # Logged in and left. Full confidence: there is nothing to misread.
        return Label(
            session_id=facts.session_id,
            intent=Intent.CREDENTIAL_ACCESS,
            operator=Operator.UNKNOWN,
            confidence=1.0,
            notes="no commands issued",
        )

    behaviours, matched_commands = match_behaviours(facts)
    candidates = {rule.intent for rule in RULES if rule.intent and rule.behaviour in behaviours}
    if Behaviour.PAYLOAD_EXECUTION in behaviours:
        candidates.add(Intent.STAGING)

    coverage = matched_commands / len(facts.commands) if facts.commands else 1.0
    intent = resolve_intent(candidates)

    return Label(
        session_id=facts.session_id,
        intent=intent,
        behaviours=behaviours,
        operator=infer_operator(facts),
        confidence=round(coverage, 3),
        notes=None if behaviours else "no rule matched any command",
    )


def classify_all(sessions: Iterable[SessionFacts]) -> list[Label]:
    """Label many sessions. Order is preserved."""
    return [classify(facts) for facts in sessions]
