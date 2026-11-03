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

**Private keys.** One session in the first real sample wrote an OpenSSH
private key to disk and used it to fetch its payload over `scp` — and wrote it
one line per command, so each line was shorter than any single-string
threshold would catch. A working credential to somebody's server, quite
possibly another victim's, is not something to publish whoever it belongs to.
Key blocks are therefore tracked *across* commands: from a `BEGIN ... PRIVATE
KEY` marker to its `END`, everything is replaced, and the markers themselves
are rewritten so the repository's own private-key hook does not have to be
the thing that catches it.

Nothing of an encoded run is kept, not even a prefix. Keeping sixteen
characters of every line of a ten-line key keeps roughly a quarter of it, in
scattered positions, and partial-key-exposure attacks on RSA work from
fractions not much larger than that.

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

#: Base64 runs at least this long, and written in a mixture of upper case,
#: lower case and digits, are treated as encoded content. The mixture is what
#: separates encoded data from a long path or a hex digest: a SHA-256 has no
#: upper case, a path has almost no digits, and a random 40-character base64
#: string lacks one of the three classes about once in a thousand.
#:
#: It was 80 until the first real sample, where a private key pasted one
#: line per command arrived in pieces of 44 to 71 characters.
MIN_BASE64_RUN = 40

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Permissive on purpose: candidates are validated by `ipaddress`, so a stray
# run of colons in a shell command is checked and left alone rather than
# mangled.
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_HEX_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
_BASE64_RUN = re.compile(rf"[A-Za-z0-9+/]{{{MIN_BASE64_RUN},}}={{0,2}}")
_PEM_BEGIN = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S
)

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
        commands = redact_private_keys(facts.commands)
        return replace(
            facts,
            commands=tuple(self.text(command) for command in commands),
            download_urls=tuple(self.text(url) for url in facts.download_urls),
        )


def _key_placeholder(kind: str, body: str) -> str:
    digest = _short_hash(body.encode())
    return f"<private key: {kind.strip() or 'PRIVATE KEY'}, {len(body)} chars sha256:{digest}>"


def redact_private_keys(commands: tuple[str, ...]) -> tuple[str, ...]:
    """Replace private-key blocks, including ones split across commands.

    A block that opens and closes inside one command is replaced whole. A
    block that opens and does not close is followed into the next commands,
    and every one of them is replaced until the line that closes it. A block
    that never closes is redacted to the end of the session, which loses some
    commands rather than publishing a key.
    """
    out: list[str] = []
    kind: str | None = None
    body: list[str] = []

    for command in commands:
        if kind is not None:
            end = _PEM_END.search(command)
            if end is None:
                body.append(command)
                out.append("<private key continues>")
                continue
            body.append(command[: end.start()])
            out.append(_key_placeholder(kind, "".join(body)) + command[end.end() :])
            kind, body = None, []
            continue

        command = _PEM_BLOCK.sub(lambda m: _key_placeholder(m.group(1), m.group(0)), command)
        begin = _PEM_BEGIN.search(command)
        if begin is None:
            # A closing marker with nothing open: the real session wrote the
            # key twice, and the second copy's END arrived on its own.
            out.append(_PEM_END.sub("<private key ends>", command))
            continue

        kind = begin.group(1)
        body = [command[begin.end() :]]
        out.append(command[: begin.start()] + "<private key begins>")

    return tuple(out)


def _truncate_hex(match: re.Match[str]) -> str:
    run = match.group(0)
    count = len(run) // 4  # every escape is four characters: \xNN
    if count < MIN_HEX_RUN:
        return run
    data = bytes(int(run[i + 2 : i + 4], 16) for i in range(0, len(run), 4))
    kept = run[: KEEP_HEX_BYTES * 4]
    return f"{kept}<+{count - KEEP_HEX_BYTES} bytes sha256:{_short_hash(data)}>"


def _looks_encoded(run: str) -> bool:
    return (
        any(c.isupper() for c in run)
        and any(c.islower() for c in run)
        and any(c.isdigit() for c in run)
    )


def _truncate_base64(match: re.Match[str]) -> str:
    run = match.group(0)
    if not _looks_encoded(run):
        return run
    return f"<base64: {len(run)} chars sha256:{_short_hash(run.encode())}>"
