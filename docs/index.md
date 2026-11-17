# IA-Honeypot

An SSH and Telnet honeypot on the public internet, and a pipeline at home that works out what the attackers were trying to do. Running against live traffic since 30 September 2026.

A [Cowrie](https://github.com/cowrie/cowrie) sensor on a VPS records every connection, login and command. A homelab pulls the logs over a private tunnel, stores them in PostgreSQL, enriches each source address with its country, network and reputation, and labels every session twice: once by a rule engine and once by a language model. Behaviours are mapped to MITRE ATT&CK techniques, and every Monday a one-page report summarises the week.

The point is to **measure** which approach works rather than assume it. Three classifiers were scored against 140 hand-labelled command sequences:

| Classifier | Accuracy | Macro-F1 |
|---|---:|---:|
| Always the commonest class | 0.21 | 0.04 |
| Rule engine | 0.74 | 0.69 |
| Gemini 3.5 Flash-Lite (hosted) | **0.85** | **0.78** |
| Qwen 2.5 1.5B (local, 3.2 GB RAM) | 0.17 | 0.11 |

The hosted model wins, and not by luck (exact McNemar test, p = 0.017). The local model that fits this hardware does worse than always guessing the commonest class.

## Where to start

**To see what the honeypot found**

- [The attack taxonomy](taxonomy.md): the labels, derived from real sessions, and every revision the data forced.
- [The ATT&CK mapping](attack.md): which techniques each behaviour evidences, and why a table rather than a model decides.
- [The weekly report](weekly-report.md): what it contains, what it never contains, and how to read it without being misled by one large campaign.

**To check the measurements**

- [The evaluation set](evaluation-set.md): how 140 sequences were sampled, anonymised and labelled, and what weakens the result.
- [Hosted and local models](model-comparison.md): the comparison, its caveats, and the decision it led to.
- [Prompt injection](prompt-injection.md): attacker text reaches a language model, and what stops it doing harm.

**To build one**

- [Architecture and threat model](architecture.md)
- [Sensor setup](sensor-setup.md) and [homelab setup](homelab-setup.md)
- [The tunnel between them](tunnel.md)
- [Privacy and data retention](privacy.md)
- Deployment notes for the [sensor](https://github.com/DDMalo/IA-Honeypot/blob/main/deploy/sensor/README.md) and the [homelab](https://github.com/DDMalo/IA-Honeypot/blob/main/deploy/homelab/README.md), with every systemd unit.

The code, the [changelog](https://github.com/DDMalo/IA-Honeypot/blob/main/CHANGELOG.md) and the [releases](https://github.com/DDMalo/IA-Honeypot/releases) are on [GitHub](https://github.com/DDMalo/IA-Honeypot).

## What is never published

No attacker address, no raw command log and no captured file appears on this site or in the repository. Only aggregates and file hashes leave the homelab. The rules, and the reasons for them, are in [the privacy notes](privacy.md).
