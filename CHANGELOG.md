# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/DDMalo/IA-Honeypot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DDMalo/IA-Honeypot/releases/tag/v0.1.0
