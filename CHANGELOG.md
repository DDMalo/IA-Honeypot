# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-01

Second milestone: captured attacks now reach the homelab and land in a database. The sensor's first day produced 36,000 events and 4,285 sessions.

### Added

- **Log shipping.** The homelab pulls Cowrie's logs over the tunnel with rsync on a 15-minute timer. The direction is deliberate: the sensor holds no credential that reaches into the home network, and the machine that needs the data is the one that asks for it.
- **Parser.** `cowrie.json` is read as a stream and folded into sessions. Truncated lines, unfamiliar event types, sessions left open by a dropped connection and out-of-order events are all tolerated and counted rather than silently dropped — the log is written while the machine is under attack, so none of those may stop the rest of the file being ingested.
- **Data models.** Immutable Pydantic models for events and sessions. Unknown fields on an event are preserved, so a Cowrie upgrade cannot break ingestion.
- **Database.** PostgreSQL schema with sessions and child tables for credentials, commands and file transfers, managed with Alembic migrations. Source addresses are stored as `inet` so queries can ask about whole subnets.
- **Ingestion worker.** Loads parsed sessions in batched transactions and runs on a timer. Re-running it over the same log is safe and cheap: Cowrie's session id is the primary key, and a session is rewritten only when it has actually grown. No cursor is kept, which removes the class of bugs that appears when the log rotates or the process dies mid-run.
- **Fixtures.** Anonymised sample logs using the RFC 5737 documentation ranges, so the parser is tested in CI without committing a single real attacker address.

### Changed

- Replaced `iptables-persistent` with `ufw` plus a systemd unit for the container rules. On Ubuntu 26.04 the two packages conflict: installing the former silently removes the latter, leaving its rules loaded with no tool to manage them.
- Database credentials are passed to the PostgreSQL container through `env_file` rather than variable interpolation, so `docker compose ps` and `logs` work without repeating `--env-file`.

### Security

- Nothing under `/srv/honeypot/raw`, and nothing in the database, is ever committed: both contain attacker IP addresses.
- The homelab's key on the sensor is restricted to a single source address, and the documentation describes narrowing it further with a forced command.

## [0.1.0] - 2026-10-01

First milestone: the collection infrastructure is live and capturing real attacks.

### Added

- **Sensor.** Cowrie SSH/Telnet honeypot on a dedicated public VPS, deployed with Docker Compose. Port 22 and 23 are exposed to the internet; administrative SSH is relocated to a non-standard port, so every connection to 22 is unsolicited by construction.
- **Containment.** Default-deny egress on the sensor host, plus `DOCKER-USER` rules confining the honeypot network, applied at boot by a dedicated systemd unit. The honeypot cannot open outbound connections to third parties.
- **Homelab.** Repurposed laptop running Ubuntu Server and Docker, hardened and administered over key-only SSH.
- **Tunnel.** WireGuard mesh (Tailscale) between sensor and homelab, with no inbound ports opened on the home network. The homelab initiates every connection; the sensor holds no credential that reaches inward.
- **Documentation.** Architecture and threat model, sensor setup, homelab setup, tunnel setup, and sensor firewall notes.
- **Repository tooling.** Python 3.12 package layout, pre-commit hooks (ruff, mypy, gitleaks, file checks), CI running lint/type/test on every pull request, CodeQL analysis, Dependabot, issue and pull request templates, contributing guide and security policy.

### Security

- Captured malware samples are never executed and never committed; only SHA-256 hashes leave the sensor.
- SSH forwarding and tunnelling are disabled in Cowrie, so the honeypot cannot be used as a relay.
- Branch protection requires a passing CI run before anything reaches `develop` or `main`.

### Notes

- Replaced `iptables-persistent` with `ufw` plus a systemd unit: on Ubuntu 26.04 the two packages conflict, and installing the former silently removes the latter, leaving its rules loaded with no tool to manage them.

[Unreleased]: https://github.com/DDMalo/IA-Honeypot/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/DDMalo/IA-Honeypot/releases/tag/v0.2.0
[0.1.0]: https://github.com/DDMalo/IA-Honeypot/releases/tag/v0.1.0
