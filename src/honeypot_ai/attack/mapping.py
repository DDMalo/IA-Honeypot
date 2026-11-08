"""From what a session did to the ATT&CK techniques that describes.

The mapping is a table, written by hand and checked by test against the pinned
catalogue, rather than something a model is asked for. Two reasons. A model
asked for technique IDs will produce plausible ones, and ATT&CK changes under
its users — release 20 alone renamed a tactic and revoked dozens of
techniques — so a confident answer is not evidence of a correct one. And the
same behaviour must always produce the same techniques, or a weekly count of
"T1105 this week" means nothing.

Techniques are derived from **behaviours**, the observable half of a label,
never from intent. Intent is a judgement about how far an actor got; a
technique is a claim that something specific happened. Only the second belongs
in an ATT&CK report.

Each row says why, because the reasons are where the arguments are. Where no
technique fits honestly, the row is empty and says so: an empty mapping is a
finding about ATT&CK's coverage of this traffic, and a forced one is noise.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from honeypot_ai.attack.catalogue import Catalogue, Technique, load
from honeypot_ai.classify.taxonomy import Behaviour


@dataclass(frozen=True)
class Mapping:
    techniques: tuple[str, ...]
    why: str


B = Behaviour

#: Every behaviour appears exactly once; a test enforces it, so a behaviour
#: added to the taxonomy without a decision here fails the build.
MAPPING: dict[Behaviour, Mapping] = {
    # Discovery
    B.HOST_ENUMERATION: Mapping(("T1082",), "uname, os-release, hostname: what the host is"),
    B.USER_ENUMERATION: Mapping(
        ("T1033", "T1087.001"), "whoami and id ask who it runs as; /etc/passwd lists accounts"
    ),
    B.ARCHITECTURE_DETECTION: Mapping(("T1082",), "the CPU architecture, to pick a binary"),
    B.CPU_PROFILING: Mapping(("T1082",), "processor model and count"),
    B.GPU_DETECTION: Mapping(
        ("T1082",),
        "hardware discovery. Not T1496 (Resource Hijacking): looking for a GPU is not using it",
    ),
    B.UPTIME_CHECK: Mapping(("T1082",), "uptime is system information"),
    B.LOGIN_HISTORY_CHECK: Mapping(("T1033",), "who, w and last show who else is logged in"),
    B.PROCESS_ENUMERATION: Mapping(("T1057",), "ps, top, walking /proc"),
    B.FILESYSTEM_DISCOVERY: Mapping(("T1083",), "ls, df, find over the filesystem"),
    B.NETWORK_DISCOVERY: Mapping(
        ("T1016", "T1049"),
        "interfaces and routes (ifconfig, ip), and live connections (netstat, ss)",
    ),
    # Not the shell at all
    B.HTTP_REQUEST: Mapping(
        ("T1595",), "an HTTP request at an SSH or Telnet port is a scanner probing services"
    ),
    B.SIP_REQUEST: Mapping(("T1595",), "the same, in SIP"),
    # Shell acquisition
    B.SHELL_ESCAPE: Mapping(("T1059.004",), "breaking out of a device menu into a Unix shell"),
    B.SANDBOX_CHECK: Mapping(
        ("T1497.001",), "mount, env, /proc/self, an arithmetic test: is this a real machine?"
    ),
    B.OBFUSCATED_COMMAND: Mapping(("T1027",), "commands sent XOR-encoded"),
    B.BUSYBOX_PROBE: Mapping(
        ("T1082",), "a nonsense applet name to learn whether BusyBox is there"
    ),
    B.MARKER_ECHO: Mapping(
        ("T1059.004",), "echoing a marker to confirm the shell executes what it is sent"
    ),
    # Staging
    B.WRITABLE_DIR_HUNT: Mapping(("T1083",), "probing directories for one writable and executable"),
    B.PERMISSION_CHANGE: Mapping(("T1222.002",), "chmod; filed under defense-impairment in 20.1"),
    B.EXECUTION_TEST: Mapping(("T1059.004",), "writing and running a throwaway script"),
    B.PAYLOAD_DOWNLOAD: Mapping(("T1105",), "wget, curl, tftp, scp: bringing a tool in"),
    B.PAYLOAD_WRITE: Mapping(
        ("T1105",),
        "the same tool transfer through the session itself, with echo -ne or a base64 heredoc",
    ),
    B.PAYLOAD_EXECUTION: Mapping(("T1059.004",), "running what was fetched or written"),
    B.BASE64_DECODE: Mapping(("T1140",), "decoding base64 or uuencoded data on the host"),
    # Persistence
    B.SSH_DIR_RESET: Mapping(("T1098.004",), "clearing .ssh to plant a key"),
    B.IMMUTABLE_FLAG_CLEAR: Mapping(
        ("T1222.002",), "chattr -i changes file attributes, here to unlock .ssh"
    ),
    B.AUTHORIZED_KEYS_WRITE: Mapping(("T1098.004",), "a key in authorized_keys"),
    B.CRON_INSTALL: Mapping(("T1053.003",), "a crontab entry"),
    B.ACCOUNT_CREATION: Mapping(("T1136.001",), "a new local account"),
    B.PASSWORD_CHANGE: Mapping(("T1098",), "an existing account's password changed"),
    # Keeping the box
    B.COMPETITOR_KILL: Mapping(
        (),
        "killing other malware has no technique: the closest, T1489 (Service Stop) and T1685 "
        "(Disable or Modify Tools), describe attacking the owner's defences, not rival malware",
    ),
    B.HISTORY_CLEARING: Mapping(("T1070.003",), "clearing shell history"),
    # Reaching outwards
    B.LATERAL_SCAN: Mapping(("T1046",), "masscan, zmap, nmap aimed at other hosts"),
}


def techniques_for(
    behaviours: Iterable[Behaviour], catalogue: Catalogue | None = None
) -> tuple[Technique, ...]:
    """The current techniques evidenced by these behaviours, by ID, without repeats.

    Every ID is checked against the pinned catalogue on the way out, so a
    mapping that has gone stale raises rather than reporting a technique that
    no longer exists.
    """
    catalogue = catalogue or load()
    ids = {technique for b in behaviours for technique in MAPPING[b].techniques}
    return tuple(catalogue.require(technique_id) for technique_id in sorted(ids))
