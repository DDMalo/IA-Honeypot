# Privacy and data retention

A honeypot collects data about people without asking them. Most of them are bots, but the records are the same either way: an IP address, the credentials tried, the commands typed. Under the GDPR an IP address is personal data, so this project treats the question of what it keeps, for how long, and who can see it, as part of the design rather than as paperwork added afterwards.

This document describes what the project does. It is not legal advice; anyone running something similar should check their own situation.

## What is collected

| Data | Why |
|---|---|
| Source IP address and port | Identifies an actor across sessions; resolves to a country and a network |
| Credentials tried | The central research question: which credentials are sprayed in the wild |
| Commands typed | What an attacker does once inside, which is what the classification works on |
| URLs requested, file hashes | Where malware is staged, and which samples are circulating |
| Client version, timestamps, duration | Fingerprints tooling and campaigns |

Nothing is collected about anyone who does not connect to the honeypot, and the honeypot is never advertised, linked or promoted. Every connection it receives is unsolicited.

## Lawful basis and purpose

The data is processed for **security research**: understanding how automated attacks against exposed SSH and Telnet services actually behave. That is a legitimate interest, and the measures below exist to keep the processing proportionate to it.

The purpose bounds the use. The data is not used to identify individuals, is not combined with other sources to do so, is not published in a form that identifies them, and is not used to retaliate against anyone.

### External lookups

Two of the enrichment steps involve someone else's data, and they are deliberately different.

**Geolocation and network** come from MaxMind's GeoLite2 databases, which are **files on disk, queried offline**. No address ever leaves the homelab for this. That was a reason to choose database files over a web API, not merely a side effect.

**Reputation** is the one exception to "nothing is sent out". Checking an address against AbuseIPDB means sending that address to AbuseIPDB — there is no way around it, and claiming otherwise would be dishonest. Three things keep it proportionate: only the address is sent, never credentials, commands or any other session content; each address is sent once a fortnight rather than once a session, because the result is cached; and the addresses in question are those of machines that attacked an unadvertised host, which is the behaviour AbuseIPDB exists to record. Removing the API key disables the step entirely and the rest of the pipeline continues working.

**File hashes** sent to VirusTotal are not personal data: a SHA-256 says nothing about who delivered the file. Samples themselves are never uploaded — not for privacy reasons but for two others worth stating. Uploading publishes the file to everyone with a paid VirusTotal account, which may not be the submitter's to give away; and for a sample aimed at a specific target it tells the attacker their payload has been found. The code calls only the lookup endpoint, never the upload one.

## Retention

Each copy of the data is kept only as long as it is needed where it sits.

Reports on file hashes are removed with the transfers that referenced them. That is housekeeping rather than privacy — a hash identifies a file, not a person — but leaving them would mean a table that only ever grows.

| Where | What | Kept for | Why that long |
|---|---|---|---|
| Sensor | Rotated logs | 30 days | Already copied to the homelab; the sensor is a buffer, not an archive, and it is the machine most exposed to compromise |
| Sensor | Malware samples | 30 days | The hash is kept forever and is enough for analysis; the file is not |
| Sensor | Session recordings | 30 days | Same reasoning as the logs |
| Homelab | Raw synced logs | 90 days | A margin for re-ingesting after a bug, without becoming an archive |
| Database | Sessions and their contents | 365 days | A full year makes seasonal patterns visible; beyond that the research value falls away faster than the privacy cost does |
| Database | Address intelligence | Until no session refers to it | Keeping the list of who attacked after deleting the attacks would defeat the point |

Enforcement is automated on both machines, because a retention policy nobody runs is not a policy:

```bash
python -m honeypot_ai.retention --dry-run   # rehearse
python -m honeypot_ai.retention             # enforce
```

The schema was built so that this is a `DELETE`: foreign keys cascade, so removing a session removes its credentials, commands and transfers with it.

### A refinement not implemented

Instead of deleting old sessions, their addresses could be truncated to a /24 and the rest kept. That would preserve long-term trends while removing the identifying part. It is not done because deleting is simpler to reason about and simpler to verify, and for a first version that matters more than the extra history. The trade-off is recorded here so it reads as a decision rather than an oversight.

## What is published

Everything in this repository is public, so the line is drawn strictly.

**Never committed:** raw logs, database contents, individual IP addresses, captured samples, and the `.env` files that hold credentials. `.gitignore` enforces this, and a `gitleaks` pre-commit hook catches secrets.

**Published:** aggregates, and the sample fixtures used by the tests, which use the addresses reserved for documentation by RFC 5737 (`203.0.113.0/24`, `198.51.100.0/24`). No real attacker address appears anywhere in the repository.

Weekly reports and dashboards follow the same rule: counts, countries, networks and credential frequencies — never a list of addresses.

## Access

The database lives on a private machine at home, bound to loopback, reachable only over an authenticated tunnel. It is not exposed to the internet and has one user.

## Related measures

Captured samples are never executed and never redistributed; only hashes leave the sensor. Attacker-authored text is treated as untrusted when it reaches a language model (see `docs/architecture.md`), which is as much a privacy measure as a security one: it is what stops attacker input steering what gets written about them.
