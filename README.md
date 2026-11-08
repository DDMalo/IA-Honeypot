# IA-Honeypot

[![CI](https://github.com/DDMalo/IA-Honeypot/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/DDMalo/IA-Honeypot/actions/workflows/ci.yml)
> SSH/Telnet honeypot with AI-powered attack classification.

**Status:** v0.5.0 — running against live traffic since 30 September 2026. **228,944 real sessions** captured by 7 November, enriched, classified, and the classifiers measured against hand-labelled data. See the [milestones](../../milestones) for what is next.

## What is this?

A [Cowrie](https://github.com/cowrie/cowrie) honeypot on a public VPS collects real attacks. A homelab pulls the logs over a private tunnel, stores them in PostgreSQL, enriches each source address with geolocation, network and reputation data, and labels every session with what the attacker was trying to do.

Sessions are labelled twice over: by a deterministic rule engine, and by a language model. Both answers are kept, because **the disagreement is the interesting part** — and it has already earned its place, when a model spotted a complete dropper chain the rules had missed.

The point of the project is to **measure** which approach works, rather than to assume. A hosted model, a model running locally on the homelab, and a few hundred lines of regex were scored against 140 hand-labelled command sequences:

| Classifier | Accuracy | Macro-F1 |
|---|---:|---:|
| Always the commonest class | 0.21 | 0.04 |
| Rule engine | 0.74 | 0.69 |
| Gemini 3.5 Flash-Lite (hosted) | **0.85** | **0.78** |
| Qwen 2.5 1.5B (local, 3.2 GB RAM) | 0.17 | 0.11 |

The hosted model wins, and not by luck (exact McNemar test, p = 0.017); the local model that fits this hardware does worse than guessing. In production the rules label every session as it arrives and Gemini labels each distinct command sequence once a day. How the set was built, what weakens it — including that the reference labels were adjudicated with a language model's help — and how the ranking was checked against that are in [`docs/evaluation-set.md`](docs/evaluation-set.md) and [`docs/model-comparison.md`](docs/model-comparison.md).

## What it has found

The honeypot is not a demo; it is pointed at the internet and the traffic is real. A few things that came out of it:

- **A taxonomy derived from 7,735 real sessions** rather than from a list of plausible categories, with an `other` class that is measured rather than decorative. When it crosses its threshold, the taxonomy is declared wrong, not the session. That has happened three times, and the rules now leave 40 of 156,739 sessions unlabelled — but the number that matters is measured per day, because a campaign is a thing that happens on a date and an average over the corpus hides one.
- **Attackers check whether they are in a honeypot.** `mount`, `env`, `ls /proc/self`, `history` — reconnaissance of the shell rather than of the host. Somebody built the expectation of honeypots into their tooling.
- **A campaign of 2,555 sessions in a single day**, each one command: `echo -e "\x6F\x6B"`, a shell-liveness probe written in hex so a honeypot cannot cheat by recognising `ok`. It exposed both a rule that missed by one character of regex and a way of measuring that hid a one-day spike inside a three-week average.
- **This sensor fails one of those probes.** `echo READY_$((41+1))` returns a `bash`-shaped error where a real shell prints `READY_42`. Seven sessions in the corpus used it; all seven know.
- **Attackers carried their own SSH keys to fetch the payload.** Sessions wrote an OpenSSH private key to disk — two different keys turned up — and used it to pull the next stage over `scp` from one server, which 97 sessions from 54 different addresses were told to fetch from between 3 October and 1 November. The server was reported to its hosting provider; the keys were never used and are not published.
- **The evaluation set nearly published that malware itself.** The first export of the labelled sample contained both private keys and a 64-bit ELF delivered through a base64 heredoc, all of it split one line per command and so under every threshold the anonymiser had. Reviewing the real export with a script before committing it is what caught it, twice; export now runs the rule engine on every item before and after anonymising and refuses to write a file whose meaning changed.
- **A Mirai variant uploaded itself through the shell, 32 bytes at a time.** On 13 October, hundreds of near-identical sessions each ran about 575 commands over two and a half minutes, writing an ARM executable with repeated `echo -ne "\x7F\x45\x4C\x46..." >> .d` — the ELF magic number, then its header, then the code — before `chmod +x` and `./dvrHelper selfrep`. It also swept `/proc` killing every process whose executable had been deleted, which is how in-memory implants look: it was clearing out rival malware before installing. The payload never crossed the network, so there is no hash to look up and no download to block; the binary is in the command log.

## Architecture

```
Internet ──► [VPS: Cowrie sensor] ──(WireGuard)──► [Homelab]
                                                    ├─ Ingestion
                                                    ├─ PostgreSQL
                                                    ├─ Enrichment (GeoIP, ASN, reputation)
                                                    ├─ Classification (rules + LLM)
                                                    └─ Grafana dashboards
```

The homelab always initiates. The sensor holds no credential that reaches into the home network, so a fully compromised sensor gains no foothold at home. Trust boundaries and the full threat model are in [`docs/architecture.md`](docs/architecture.md).

## Roadmap

| Version | Goal | |
|---|---|---|
| v0.1.0 | Base infrastructure and repository tooling | ✅ |
| v0.2.0 | Log ingestion and storage | ✅ |
| v0.3.0 | Enrichment and first dashboard | ✅ |
| v0.4.0 | Rule-based and LLM classification | ✅ |
| v0.5.0 | Evaluation against a hand-labelled dataset | ✅ |
| v0.6.0 | MITRE ATT&CK mapping and weekly reports | |
| v1.0.0 | Stable release and documentation site | |

## Security considerations

Running a honeypot involves real risks, and most of this project's design is about containing them. The sensor is a dedicated VPS, never the home network. Its outbound traffic is blocked, so it cannot be used against anyone else. Malware samples never leave the sensor and never enter this repository — only hashes do. That rule was written for files an attacker downloads, and one campaign found the gap in it: a payload typed into the shell as hex never becomes a file at all, so it arrives as ordinary session text and is subject to no sample-handling rule by default. Command logs from those sessions are treated as samples, which means they are never published verbatim. Attacker-authored text is treated as untrusted when it reaches a language model, and what bounds the damage is not the prompt but the architecture: the model can call no tool, run no command, and anything it invents fails schema validation.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows (Git Bash): source .venv/Scripts/activate
pip install -e ".[dev]"
pytest
```

Deployment is not required to run the tests: no sensor, no database, no API key. The database tests are skipped unless `TEST_DATABASE_URL` points at a PostgreSQL server.

## Documentation

**The findings**

- [The attack taxonomy, and how it was derived](docs/taxonomy.md)
- [Hosted and local models on this hardware, and which one won](docs/model-comparison.md)
- [The evaluation set: how it was sampled, anonymised and labelled](docs/evaluation-set.md)
- [Prompt injection: threat model and measurements](docs/prompt-injection.md)

**The system**

- [Architecture and threat model](docs/architecture.md)
- [Sensor setup](docs/sensor-setup.md)
- [Homelab setup](docs/homelab-setup.md)
- [Tunnel between sensor and homelab](docs/tunnel.md)
- [Privacy and data retention](docs/privacy.md)

## Attribution

Geolocation and network data come from [MaxMind](https://www.maxmind.com)'s GeoLite2 databases, used under their licence. The databases themselves are not redistributed in this repository.

## License

[MIT](LICENSE)
