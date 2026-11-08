# MITRE ATT&CK mapping

Every session the honeypot labels carries a set of **behaviours**: what the attacker observably did, such as `payload_download` or `authorized_keys_write` (see [the taxonomy](taxonomy.md)). This document is about the step after that, which turns behaviours into [MITRE ATT&CK](https://attack.mitre.org) techniques, so that a week of traffic can be described in the vocabulary the rest of the field uses.

Three decisions carry the weight. The catalogue is a pinned, verified copy of one ATT&CK release, not something remembered. The mapping is a table written by hand, not a model's answer. And techniques come from behaviours, never from intent.

## A pinned copy of one release

The project uses **Enterprise ATT&CK 20.1** (5 November 2026), committed as `src/honeypot_ai/attack/releases/enterprise-attack-20.1.json`. It holds every technique's ID, name, tactics and status, 867 techniques and 15 tactics, derived from MITRE's official STIX bundle in [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data). The file records the SHA-256 of the bundle it came from, so it can be rebuilt byte for byte and checked:

```bash
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/mitre-attack/attack-stix-data
git -C attack-stix-data checkout HEAD -- enterprise-attack/enterprise-attack-20.1.json
python -m honeypot_ai.attack build attack-stix-data/enterprise-attack/enterprise-attack-20.1.json
git diff --exit-code src/honeypot_ai/attack/releases/
```

Nothing at runtime downloads anything. `catalogue.load().require(id)` accepts a technique only if it exists in the pinned release and is current. A revoked technique is refused and the error names its replacement.

This was worth doing before writing a single row of the mapping, because ATT&CK changes under its users. Release 20 alone renamed the Defense Evasion tactic to **Stealth**, split off a new **Defense Impairment** tactic, and revoked T1562 (Impair Defenses) in favour of T1685. A mapping typed from memory would have used the old names and the revoked ID, and it would have looked perfectly plausible.

## A table, not a model

The mapping lives in `src/honeypot_ai/attack/mapping.py`. A model asked for technique IDs produces plausible ones, and plausible is exactly the failure the pinned catalogue exists to catch. A weekly count of "T1105 this week" also means something only if the same behaviour always produces the same techniques.

Every row says why, because the reasons are where the arguments are. The tests enforce three things:

- every behaviour in the taxonomy has a row, so adding a behaviour without deciding its techniques fails the build;
- every technique in the table exists and is current in the pinned release;
- `techniques_for()` checks again at runtime, so a stale mapping raises an error instead of reporting a revoked technique.

## Techniques come from behaviours, not from intent

Intent is a judgement about how far an actor got, such as `staging` or `persistence`. A technique is a claim that something specific happened. Only claims belong in an ATT&CK report, so intent never produces a technique. A `staging` session that only hunted for a writable directory evidences T1083 (File and Directory Discovery), not T1105 (Ingress Tool Transfer), because nothing was transferred.

## The mapping

| Behaviour | Techniques | Why |
|---|---|---|
| `host_enumeration` | [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | uname, os-release, hostname: what the host is |
| `user_enumeration` | [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account | whoami and id ask who it runs as; /etc/passwd lists accounts |
| `architecture_detection` | [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | the CPU architecture, to pick a binary |
| `cpu_profiling` | [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | processor model and count |
| `gpu_detection` | [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | hardware discovery. Not T1496 (Resource Hijacking): looking for a GPU is not using it |
| `uptime_check` | [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | uptime is system information |
| `login_history_check` | [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery | who, w and last show who else is logged in |
| `process_enumeration` | [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery | ps, top, walking /proc |
| `filesystem_discovery` | [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery | ls, df, find over the filesystem |
| `network_discovery` | [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery | interfaces and routes (ifconfig, ip), and live connections (netstat, ss) |
| `http_request` | [T1595](https://attack.mitre.org/techniques/T1595) Active Scanning | an HTTP request at an SSH or Telnet port is a scanner probing services |
| `sip_request` | [T1595](https://attack.mitre.org/techniques/T1595) Active Scanning | the same, in SIP |
| `shell_escape` | [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell | breaking out of a device menu into a Unix shell |
| `sandbox_check` | [T1497.001](https://attack.mitre.org/techniques/T1497/001) System Checks | mount, env, /proc/self, an arithmetic test: is this a real machine? |
| `obfuscated_command` | [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information | commands sent XOR-encoded |
| `busybox_probe` | [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | a nonsense applet name to learn whether BusyBox is there |
| `marker_echo` | [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell | echoing a marker to confirm the shell executes what it is sent |
| `writable_dir_hunt` | [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery | probing directories for one writable and executable |
| `permission_change` | [T1222.002](https://attack.mitre.org/techniques/T1222/002) Linux and Mac Permissions | chmod; filed under defense-impairment in 20.1 |
| `execution_test` | [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell | writing and running a throwaway script |
| `payload_download` | [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer | wget, curl, tftp, scp: bringing a tool in |
| `payload_write` | [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer | the same tool transfer through the session itself, with echo -ne or a base64 heredoc |
| `payload_execution` | [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell | running what was fetched or written |
| `base64_decode` | [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information | decoding base64 or uuencoded data on the host |
| `ssh_dir_reset` | [T1098.004](https://attack.mitre.org/techniques/T1098/004) SSH Authorized Keys | clearing .ssh to plant a key |
| `immutable_flag_clear` | [T1222.002](https://attack.mitre.org/techniques/T1222/002) Linux and Mac Permissions | chattr -i changes file attributes, here to unlock .ssh |
| `authorized_keys_write` | [T1098.004](https://attack.mitre.org/techniques/T1098/004) SSH Authorized Keys | a key in authorized_keys |
| `cron_install` | [T1053.003](https://attack.mitre.org/techniques/T1053/003) Cron | a crontab entry |
| `account_creation` | [T1136.001](https://attack.mitre.org/techniques/T1136/001) Local Account | a new local account |
| `password_change` | [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation | an existing account's password changed |
| `competitor_kill` | — | killing other malware has no technique: the closest, T1489 (Service Stop) and T1685 (Disable or Modify Tools), describe attacking the owner's defences, not rival malware |
| `history_clearing` | [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History | clearing shell history |
| `lateral_scan` | [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery | masscan, zmap, nmap aimed at other hosts |

### The one empty row

`competitor_kill` maps to nothing, on purpose. The closest candidates are T1489 (Service Stop) and T1685 (Disable or Modify Tools), and both describe attacking the owner's defences. Malware killing rival malware is neither. An empty row is a finding about how well ATT&CK covers this traffic. A forced row would only be noise.

### Choices worth a second look

- `gpu_detection` is T1082, discovery, and not T1496 (Resource Hijacking). Looking for a GPU is not the same as using one.
- `permission_change` (`chmod`) is T1222.002, which release 20.1 files under **Defense Impairment**. Making a payload executable fits that tactic less well than its name suggests, but the technique is correct and the tactic is MITRE's call.
- `payload_write` is T1105, the same technique as a download. Writing a binary into the shell 32 bytes at a time with `echo -ne` is still bringing a tool in, just through the session instead of over a second connection.
- Some techniques belong to several tactics. T1053.003 (Cron), for example, is Execution, Persistence and Privilege Escalation. The weekly report lists such a technique once, with all its tactics, and places it by the first one in matrix order. It does not repeat the technique in every tactic's table.

## Moving to a new release

1. Rebuild the catalogue from the new bundle with the commands above, changing the file name.
2. Change `PINNED_VERSION` in `catalogue.py`.
3. Run the tests. Any row that names a technique the new release revoked or deprecated fails, and the error names the replacement.
4. Decide each failure by hand and say why in the row.

## Attribution

ATT&CK is © The MITRE Corporation and is used under MITRE's licence. The full notice travels inside the committed catalogue and closes every weekly report. Only identifiers, names, tactics and status are kept; no descriptions are reproduced.
