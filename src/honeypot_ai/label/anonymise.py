"""Make a session safe to commit, without changing what it says.

The evaluation set lives in `eval/` and is committed, because an evaluation
nobody else can rerun is a claim rather than a result. Committing it means
publishing attacker sessions, and two things in them must not be published.

**Public addresses.** An address is personal data — often a compromised router
in somebody's home rather than an attacker — and the project's rule is that
none leaves the homelab. Every public IPv4 and IPv6 address is replaced with
one from the documentation ranges (RFC 5737, RFC 3849), *consistently*: the
same address becomes the same placeholder everywhere in the export, so two
sessions fetching from one server still visibly fetch from one server.
Private, loopback and unspecified addresses are left alone. `ping 127.0.0.1`
identifies nobody, and rewriting it would change what the session means.

**Payloads typed in as text.** A dropper that writes a binary through `echo -ne
"\\x7F\\x45\\x4C\\x46..."` puts the malware itself into the command log. The
sample-handling rule says only hashes leave the sensor, so long runs of hex
escapes and long base64 blobs are cut to their first few units and replaced
with their length and a short hash. Four bytes is enough to keep `\\x7F ELF`
recognisable, and enough for every rule that matches hex markers to keep
matching — which is tested, because anonymisation that changes a classifier's
answer would quietly change the evaluation.

What is deliberately kept: hostnames in URLs, which are attacker
infrastructure and the ordinary currency of threat intelligence; file hashes,
which the project already publishes; and passwords an attacker sets, which
belong to nobody.

The mapping from real address to placeholder exists only in memory for the
length of one export and is never written anywhere. A file of it next to the
dataset would undo the whole exercise.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field, replace

from honeypot_ai.classify.facts import SessionFacts

#: Hex escapes kept from the start of a long run. Enough for the ELF magic
#: number and for the rule engine's two-byte marker threshold; far too little
#: to reconstruct anything from.
KEEP_HEX_BYTES = 4

#: A run of hex escapes at least this long is treated as a payload.
MIN_HEX_RUN = 8

#: Base64 runs at least this long are treated as a payload. Long enough that a
#: SHA-256 written in a command (64 characters) is left intact.
MIN_BASE64_RUN = 80
KEEP_BASE64_CHARS = 16

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Permissive on purpose: candidates are validated by `ipaddress`, so a stray
# run of colons in a shell command is checked and left alone rather than
# mangled.
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_HEX_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
_BASE64_RUN = re.compile(rf"[A-Za-z0-9+/]{{{MIN_BASE64_RUN},}}={{0,2}}")

_V4_RANGES = ("198.51.100", "203.0.113", "192.0.2")


def _short_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


@dataclass
class Anonymiser:
    """One export's worth of consistent replacements.

    Create one per export and pass every session through it in a fixed order,
    and the placeholders come out the same every time the export is rebuilt.
    """

    _v4: dict[str, str] = field(default_factory=dict)
    _v6: dict[str, str] = field(default_factory=dict)

    @property
    def addresses_replaced(self) -> int:
        return len(self._v4) + len(self._v6)

    def _placeholder_v4(self, address: str) -> str:
        if address not in self._v4:
            n = len(self._v4)
            block, host = divmod(n, 254)
            if block >= len(_V4_RANGES):
                raise ValueError("more distinct public IPv4 addresses than documentation space")
            self._v4[address] = f"{_V4_RANGES[block]}.{host + 1}"
        return self._v4[address]

    def _placeholder_v6(self, address: str) -> str:
        if address not in self._v6:
            self._v6[address] = f"2001:db8::{len(self._v6) + 1:x}"
        return self._v6[address]

    def _replace_v4(self, match: re.Match[str]) -> str:
        text = match.group(0)
        try:
            address = ipaddress.IPv4Address(text)
        except ValueError:
            return text  # 999.1.1.1 is not an address, whatever it looks like
        return self._placeholder_v4(str(address)) if address.is_global else text

    def _replace_v6(self, match: re.Match[str]) -> str:
        text = match.group(0)
        try:
            address = ipaddress.IPv6Address(text)
        except ValueError:
            return text
        return self._placeholder_v6(str(address)) if address.is_global else text

    def text(self, value: str) -> str:
        """Anonymise one string."""
        value = _HEX_RUN.sub(_truncate_hex, value)
        value = _BASE64_RUN.sub(_truncate_base64, value)
        value = _IPV4.sub(self._replace_v4, value)
        return _IPV6.sub(self._replace_v6, value)

    def facts(self, facts: SessionFacts) -> SessionFacts:
        """The same session, safe to commit."""
        return replace(
            facts,
            commands=tuple(self.text(command) for command in facts.commands),
            download_urls=tuple(self.text(url) for url in facts.download_urls),
        )


def _truncate_hex(match: re.Match[str]) -> str:
    run = match.group(0)
    count = len(run) // 4  # every escape is four characters: \xNN
    if count < MIN_HEX_RUN:
        return run
    data = bytes(int(run[i + 2 : i + 4], 16) for i in range(0, len(run), 4))
    kept = run[: KEEP_HEX_BYTES * 4]
    return f"{kept}<+{count - KEEP_HEX_BYTES} bytes sha256:{_short_hash(data)}>"


def _truncate_base64(match: re.Match[str]) -> str:
    run = match.group(0)
    kept = run[:KEEP_BASE64_CHARS]
    rest = len(run) - KEEP_BASE64_CHARS
    return f"{kept}<+{rest} chars sha256:{_short_hash(run.encode())}>"
