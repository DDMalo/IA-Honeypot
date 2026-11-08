# The weekly report

Every Monday morning the homelab writes a one-page Markdown report on the ISO week that just ended, and sends a three-line summary to a phone. The report is for a person to read in two minutes and decide whether anything needs a closer look. Dashboards are for the closer look.

```bash
python -m honeypot_ai.report weekly                    # the last complete week
python -m honeypot_ai.report weekly --week 2026-W45    # a given ISO week
python -m honeypot_ai.report weekly --notify           # and a summary to ntfy
```

Weeks are ISO weeks in UTC, Monday 00:00 to the next Monday 00:00. On a Sunday the "last complete week" is the one before, because the current week has not ended. A report for the current week, asked for by name, covers only what has arrived so far.

## What is in it

Eight short sections, each compared with the week before where a comparison means something:

1. **The week in numbers.** Sessions, source addresses, countries, sessions that ran commands, and command sequences never seen before.
2. **What they were trying to do.** Intent from the rule engine, the furthest step each session reached.
3. **ATT&CK techniques.** Derived from behaviours through the [hand-written mapping](attack.md), one row per technique with its tactics, in matrix order. Techniques not seen the week before are marked **new**.
4. **The largest campaigns.** A campaign is one exact command sequence. The five largest are described by their intent and techniques, how many sources ran them, and when the sequence was first seen. A first sighting this week is marked.
5. **Where it came from.** Countries and networks, by sessions.
6. **Credentials tried most.**
7. **Files captured for the first time,** by SHA-256, with VirusTotal's verdict where one was looked up.
8. **Rules and model.** How often the rule engine and the language model agree, and the commonest disagreements.

Building it reads the database with a dozen aggregate queries. Over 230,000 sessions it takes about a second.

## What is never in it

The report follows [the privacy notes](privacy.md): aggregates only.

- **No addresses.** Sources are counted, never listed. A test fills the database with a session from a known address and a command containing another, and fails if either reaches the page.
- **No commands.** A campaign is described by what it did, not by what it typed. Some command logs carry a payload typed into the shell, and those are treated as samples.
- **Attacker-chosen text is quoted inert.** Usernames and passwords are the only attacker text on the page, and the page is Markdown. Each is cut short and put in a code span. Backticks inside it become quotes so the span cannot close early, `|` becomes `¦` so a table cell cannot be split, and control characters become `?`. A password written as a Markdown link stays text.
- **Hashes, not files.** A captured file appears as its SHA-256. The file itself never left the sensor.

MITRE's copyright notice and licence close every report, because the technique names come from ATT&CK.

## Where it goes

`cowrie-report.timer` runs on Mondays at 07:10 UTC. By then the night's sessions have been ingested, the rules have run several times since midnight and the language model has had its daily run, so the week is fully labelled. The timer writes the report to `~/honeypot-reports/` on the homelab, outside the clone, and sends the summary to the same ntfy topic as the [freshness checks](../deploy/homelab/README.md#freshness-checks).

The report is **not committed automatically**. It is safe to publish, but which weeks go into the repository is a decision for a person, made after reading it. To publish one, copy it from the homelab, read it, and add it under `reports/` through a pull request like any other change:

```bash
# PC
scp david@192.168.1.130:honeypot-reports/weekly-2026-W45.md reports/
```

Reports are written outside the clone so that publishing one from another machine never collides with an untracked copy of the same file when the homelab next runs `git pull`.

## Reading it honestly

**Percentages describe sessions, and sessions are dominated by campaigns.** In the week of 2 November, one address ran a single shell-probing sequence 12,150 times. That was about a quarter of all the week's sessions, and most of that week's +572% in `shell_probing`. The campaigns table exists so that a jump in the intents table can be traced to its cause before it is read as a trend.

**Agreement between the rules and the model is high because campaigns repeat.** The first report showed 99.2% agreement over 49,598 sessions. The language model labels each distinct command sequence once and the answer is copied to every session that shares it, so one large campaign the two agree on contributes thousands of agreements. The evaluation counted each sequence once, on a sample drawn to cover every class, and there the two classifiers were eleven points of accuracy apart: see [the model comparison](model-comparison.md). The disagreements table is the useful part. It lists where to look first, and on the evaluation set the model was right more often.

**"Change" is relative to one week.** A class that went from 7 sessions to 49 shows +600%. Small counts make large percentages, so the counts sit next to them.
