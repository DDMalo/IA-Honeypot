# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-10-27

Fourth milestone: sessions stop being events and become labelled behaviour. A taxonomy derived from the honeypot's own traffic, a deterministic rule engine, three language-model backends behind one interface, an adversarial corpus to measure the prompt against, and labels in the database — one row per session per classifier, so the disagreements survive to be evaluated in 0.5.0.

### Added

- **An attack taxonomy, derived from 7,735 real sessions** rather than chosen from a list of plausible-sounding categories. Two axes: one `Intent` per session, answering how far the actor got, and any number of `Behaviour`s, answering what they did. Intent is single-valued because evaluation needs one correct answer per session; behaviours are the unit that will map to ATT&CK in 0.6.0, so the mapping can grow without renegotiating what the classifier predicts. The tie-break is **the furthest point reached** — a session that fingerprints and then writes an SSH key is `persistence`, because the fingerprinting was in service of the rest. Written up in `docs/taxonomy.md`.
- **`other` as a measured escape valve.** A category meaning "the taxonomy has no word for this", with a threshold above which the taxonomy is declared wrong rather than the session. It has fired three times and changed the taxonomy or the rules every time.
- **A rule-based classifier**, deterministic, auditable and fast, as the baseline every model is measured against. It carries a single-byte XOR deobfuscator under two constraints that matter: the decoded text must be printable, and it must match a rule that already exists — so the decoder can surface a missed match but can never invent a category. Operator inference is deliberately asymmetric: fast command intervals prove automation, slow ones prove nothing, so a human is never asserted.
- **`SessionFacts`, the single view both classifiers get.** It deliberately excludes the source address. Country, network and reputation are known by this point and would improve apparent accuracy — which is exactly why they are withheld. A model that learns "addresses in this ASN are malicious" has learned about the address, not the session.
- **A provider-agnostic language-model interface.** One `Provider` protocol, one prompt, one parser, one validator; backends are implementations. Replies are validated against the taxonomy with `extra="forbid"`, so an invented field rejects the whole reply rather than being partially trusted, and an invented label fails validation instead of widening the vocabulary by assertion.
- **A Gemini provider**, with the response schema generated from the taxonomy enums so the model is constrained to the vocabulary, the model pinned rather than aliased — a benchmark whose model changes underneath it is not a benchmark — and backoff split by cause.
- **An Ollama provider**, running a model locally so attacker data never leaves the homelab, and `docs/model-comparison.md`: the measured answer to whether that is usable here. It is, at five times the latency and a good deal of accuracy, and the honest version of "we used a hosted model" is "we tried both, here is the table".
- **An adversarial corpus of twelve prompt injections**, each a carrier session plus a payload, run twice so the verdict is the difference between the clean and attacked answers rather than the attacked answer alone. With `docs/prompt-injection.md`: the threat model, what bounds the damage, what raises the cost, and an explicit list of what is not being claimed.
- **Classification is stored.** `session_labels` keeps one row per session *per classifier*, so the rule engine and each model record their own conclusion and a human analyst joins them as another classifier in 0.5.0 rather than needing a table of their own. Storing a single "best" label would discard the only part worth keeping: agreement carries no information, and the disagreement is what the evaluation is made of — it has already found a dropper chain the rules missed.
- **Labels carry the taxonomy version they were written under**, so a change to the vocabulary marks the affected rows for relabelling. Without it nothing looks wrong: every row stays well-formed, every constraint still passes, and the counts quietly become a mixture of two schemes.
- `python -m honeypot_ai.classify`, with `--dry-run`, `--limit`, `--reclassify` and `--audit`. Only the rule engine is scheduled; the metered and the slow classifiers are run deliberately over a bounded number of sessions, because a timer that quietly spends a quota is a worse failure than a timer that does not exist.
- `--audit` reports the unlabelled share **per day** and flags the days over threshold. Averaged over the corpus, a campaign of 2,555 sessions in one day read as 8% of three weeks — a taxonomy apparently broken for a fortnight — and a year from now the same campaign would be 0.2% and invisible. A campaign is a thing that happens on a date.
- A staleness check on the GeoLite2 databases, read from the `build_epoch` in the file's own metadata rather than its modification time, because a copied or restored file gets a new mtime and the same stale data.

### Changed

- **The README now says what the project does rather than what it will do.** ATT&CK mapping and weekly reports are 0.6.0 and were being advertised as present; a reader who clones the repository looking for them and does not find them has been told something false, which is worse than saying less. It also links the three documents that are the actual output of this milestone.
- Dependabot updates are grouped, so a runtime bump and a dev-tool bump stop conflicting with each other every week.
- Local generation is seeded. Temperature zero is not reproducibility: two runs of the injection suite an hour apart disagreed on two of twelve cases, which is enough to move a published number and not enough to notice.

### Fixed

- **The GeoLite2 updater had failed on every run since 5 October and nothing said so.** Enrichment carried on labelling every session with a country and a network from a frozen file — it never errored, it just stopped being right. Three faults chained: the Debian package enables a second timer that races this one for the database lock and the loser exits without retrying; that unit runs under `ProtectSystem=strict` with `ReadWritePaths=/var/lib/GeoIP`, so with the databases relocated it downloaded each one in full and failed with `EROFS`; and `geoipupdate` retries that permanent local failure for five minutes, re-fetching 64 MB each time, which exhausted the free tier's daily quota and left HTTP 429 for every later run. This unit now carries the same hardening with the correct `ReadWritePaths`, and `RetryFor` is zero.
- **`marker_echo` required three or more hex escapes and missed `echo -e "\x6F\x6B"`**, which spells `ok` in two. The threshold had been written around the markers then in the corpus — `GAYFGT` is six bytes, `auth_ok` eight — and 2,555 sessions in a single day walked through a gap one character of regex wide.
- **`process_enumeration` carried no intent**, so a session whose only command was `ps aux` had nothing to resolve and fell to `other`. Intent is the furthest point reached, so a low rank can never lower a session that went further; carrying none was the bug.
- Arithmetic expansion (`$(( ))`) and `docker ps` now count as `sandbox_check`. This sensor fails the arithmetic probe, answering `-bash: 41+1: command not found` where a real shell prints `READY_42` — an emulator issue, recorded in `docs/taxonomy.md`.
- **An unbounded `behaviours` array let a grammar-constrained local model repeat enum values until it ran out of tokens.** Every reply came back truncated mid-string, and the parse error read as "the model cannot produce JSON" when it was "the model produced valid JSON and we cut it in half". Bounding the array took availability from 20% to 100% and median latency from 190 seconds to 23. Truncation is now treated as permanent: at temperature zero a retry is the same request with the same answer.
- The default Gemini model had been retired and returned 404 on every call. Permanent failures — a retired model, a bad key, a 4xx — are no longer retried, and the API's own message survives to the surface, which is how the replacement model's name was found.
- An injected `httpx.Client` lost the authentication header, and stripping `ESC` left `[2J` litter in rationales. Both were found by the project's own tests before they reached a real run.
- The rehearsal exits quietly when piped into `head`. It prints one line per session and there are tens of thousands, so the obvious way to read it is `| head` — and the traceback printed over the output looked exactly like the classifier crashing on session 20.

## [0.3.0] - 2026-10-05

Third milestone: the captured sessions stop being a pile of addresses and start saying something. Where the traffic comes from, whose network it rents, what others have reported about it, what files it drops — and a dashboard that answers those without opening `psql`.

### Added

- **Geolocation and network.** Country, city, ASN and the organisation that owns the range, resolved from MaxMind's GeoLite2 databases. Those are files on disk queried offline, which was chosen over a web API so that tens of thousands of addresses resolve in seconds and nothing about the honeypot's traffic is sent anywhere. A timer keeps the databases current.
- **Reputation.** Each address is checked against AbuseIPDB. The field worth the API call is not the score but `usage_type`, which separates a rented datacentre machine from a residential address — almost always a compromised router rather than an attacker's own computer.
- **File identification.** Hashes of captured files are looked up on VirusTotal. A hash nobody has ever submitted is recorded as a finding rather than a failed lookup: for a honeypot, a sample no sandbox has seen is the most interesting result available.
- **Dashboard.** Grafana reading PostgreSQL directly, with the datasource and all eleven panels provisioned from files in this repository. A Grafana that is lost or rebuilt comes back identical, and what each panel queries is visible in review rather than buried in a container.
- **Retention.** Sessions past the window are deleted, along with the addresses and file reports nothing refers to any more. Raw logs and captured samples are pruned on the machines that hold them. The reasoning is in `docs/privacy.md`.

### Changed

- Enrichment is split into three stages on three timers, because the constraints differ: GeoIP reads local files and runs every half hour, reputation crosses the network against 1,000 checks a day, and hash lookups are limited to four a minute. Coupling them would mean one rate limit stalling the others.
- Work is done per address and per hash rather than per session. A single bot accounts for hundreds of sessions, so this is the difference between a few hundred lookups and tens of thousands — and it is what makes the free tiers sufficient.

### Fixed

- Grafana's admin credentials are passed through `env_file` instead of Compose interpolation. Written as `${VARIABLES}` they were resolved against `deploy/homelab/.env` rather than the repository's, so the container refused to start — the same mistake already fixed for PostgreSQL in 0.2.0.
- Restored the package version, which a stale `pyproject.toml` had reverted to `0.1.0` during the 0.2.0 cycle.

### Security

- Only the address is sent to AbuseIPDB, and only the hash to VirusTotal. Samples are never uploaded: doing so publishes someone else's file to everyone with a paid account and, for a targeted sample, tells the attacker it was found. `docs/privacy.md` now states plainly that reputation checks share data with a third party, and what bounds that.
- No Python package is named `samples`, because `.gitignore` excludes any directory with that name so a captured sample can never reach the repository by accident.

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

[Unreleased]: https://github.com/DDMalo/IA-Honeypot/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/DDMalo/IA-Honeypot/releases/tag/v0.3.0
[0.2.0]: https://github.com/DDMalo/IA-Honeypot/releases/tag/v0.2.0
[0.1.0]: https://github.com/DDMalo/IA-Honeypot/releases/tag/v0.1.0
