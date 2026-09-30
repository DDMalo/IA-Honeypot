# IA-Honeypot
[![CI](https://github.com/DDMalo/IA-Honeypot/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/DDMalo/IA-Honeypot/actions/workflows/ci.yml)
> SSH/Telnet honeypot with AI-powered attack classification and MITRE ATT&CK mapping.

**Status:** 🚧 Early development (v0.1.0 in progress). See the [project board](../../projects) and [milestones](../../milestones) for the roadmap.

## What is this?

IA-Honeypot collects real-world attacks with a [Cowrie](https://github.com/cowrie/cowrie) honeypot, enriches them with geolocation and IP reputation data, and uses both rule-based and LLM-based classifiers to understand what attackers are trying to do. Each session is mapped to [MITRE ATT&CK](https://attack.mitre.org/) techniques and summarized in automated weekly reports.

A key goal of the project is to **measure** which classification approach works best (rules, a cloud LLM or a local model) using a hand-labeled dataset, instead of relying on a single model blindly.

## Architecture

```
Internet ──► [VPS: Cowrie sensor] ──(secure tunnel)──► [Homelab]
                                                        ├─ Ingestion (Python)
                                                        ├─ PostgreSQL
                                                        ├─ Enrichment (GeoIP, ASN, reputation)
                                                        ├─ Classification (rules + LLM)
                                                        ├─ MITRE ATT&CK mapping
                                                        └─ Grafana dashboards & weekly reports
```

## Roadmap

| Version | Goal |
|---|---|
| v0.1.0 | Base infrastructure and repository tooling |
| v0.2.0 | Log ingestion and storage |
| v0.3.0 | Enrichment and first dashboard |
| v0.4.0 | Rule-based and LLM classification |
| v0.5.0 | Evaluation on a labeled dataset |
| v0.6.0 | MITRE ATT&CK mapping and weekly reports |
| v1.0.0 | Stable release and documentation site |

## Security considerations

Running a honeypot involves real risks. This project isolates the sensor on a dedicated VPS, blocks outbound traffic so it cannot be used against third parties, never stores malware samples in the repository, and treats all attacker input as untrusted when it is sent to an LLM (prompt injection). Details will be documented in `docs/`.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows (Git Bash): source .venv/Scripts/activate
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE)

## Documentation

- [Homelab setup](docs/homelab-setup.md)
- [Sensor setup](docs/sensor-setup.md)
