# The evaluation set

Until this point every comparison in the project was between classifiers: the rule engine against a hosted model, a hosted model against a local one. Agreement was a smoke test, and every document that reported it said so. This is the part that replaces agreement with correctness — a set of sessions labelled by a person, against which every classifier is scored.

A labelled set is easy to build badly, and the ways it goes wrong do not show in the results. Each decision below exists because the alternative would have produced plausible numbers that meant something else.

## Labelling is blind

The person labelling sees nothing a classifier could not see: the commands, whether the login succeeded, the download attempts, the timing between commands. Not the rule engine's label, not any model's, not the country or reputation of the address, and not how many other sessions shared the sequence.

Each of those would anchor the answer. A label formed by glancing at the rules' output and agreeing with it measures how persuadable the labeller was, and an evaluation built on such labels flatters the rules by exactly that amount. The tool enforces this rather than trusting it: the stratum is in the sample file, because the evaluation needs it, and the review screen never prints it. There is a test that fails if it ever does.

The intent definitions shown to the labeller are the same lines the language model is given, from one shared source. A human reading one description and a model reading another produces disagreements about wording that look exactly like disagreements about sessions.

## Distinct behaviours, with their weights

The corpus is dominated by repetition. One campaign was 2,555 sessions of a single command; credential-only sessions with no commands number in the tens of thousands. Labelling thirty copies of the same thing is thirty labels spent learning one fact.

Sessions are therefore grouped by a fingerprint of what they did — the exact command sequence and whether the login succeeded — and one representative of each group is a candidate. The group's size is kept as the item's weight. That gives the evaluation two numbers that are both worth reporting and must not be confused:

- **per behaviour** — how often a classifier is right about a distinct kind of thing attackers do;
- **per session** — how often it is right about what actually arrives, weighted by frequency.

A classifier that handles the one enormous campaign correctly and fumbles the long tail scores well on the second and badly on the first. Neither number alone describes it.

## Two components, for two questions

A sample drawn uniformly over sessions would be about two-thirds `fingerprinting` and contain one or two `persistence` sessions. Per-class precision for the rare classes would then rest on one or two labels — not a measurement. A sample drawn only by class gives every class coverage but describes no population that exists.

So the sample has both:

| Part | Drawn | Answers |
|---|---|---|
| **uniform** | in proportion to session count | what does the real traffic look like, and how well is it classified? |
| **stratified** | a fixed number of distinct sequences per class | is there enough of every class to say anything about it? |

Every item records which part drew it, and the evaluation keeps them apart.

## The caveat that comes with stratifying

Strata come from the only label available before anyone has labelled anything: the rule engine's. That has a cost, and it is easy to lose between the code and the results table, so it is stated here.

Sampling by the rules' label gives an **unbiased estimate of the rules' precision** in each class — everything they called `staging` had the same chance of being drawn. It gives a **biased estimate of their recall**, because a session the rules put in the wrong class was sampled from that wrong class, and the classes the rules under-predict are under-represented. The uniform part does not have this problem, which is the other reason it exists. Recall figures for the rule engine come from the uniform part, or are reported with that caveat attached.

## The classifiers are frozen before labelling begins

Changing a rule because of something seen in the data is ordinary development — until the data in question is the evaluation set. After that it is fitting the test, and the numbers it produces are worthless.

So the order is fixed: rules and prompts are frozen, the sample is drawn, and only then does labelling start. A change after that point is not forbidden, but it is reported as what it is — the old version and the new one scored on the same labels — and never silently replaces the old figure.

That rule was exercised before it was written down. Testing the labelling tool against the real corpus showed the 13 October dropper — an ARM binary written through `echo -ne`, made executable and run — filed as `shell_probing`, because the rule for running a payload only recognised files ending in `.sh` or `.bin`, and IoT payloads are called `.d` and `dvrHelper`. That was fixed before the sample was drawn. Had it surfaced while labelling, it would have been a finding to report, not a bug to fix.

## Safe to commit

The set lives in `eval/` and is committed, because an evaluation nobody else can rerun is a claim rather than a result. Committing it means publishing attacker sessions, so export goes through an anonymiser that cannot be skipped:

- **Public IP addresses** become documentation addresses (RFC 5737, RFC 3849), consistently within an export, so two sessions using one server still visibly use one server. Private and loopback addresses are kept; they identify nobody and rewriting them would change what a session means.
- **Payloads typed in as text** — long runs of hex escapes, long base64 blobs — are cut to their first few units and replaced with their length and a short hash. Four bytes keep `\x7F ELF` recognisable and keep every hex-marker rule matching; they are nowhere near enough to reconstruct anything.

A test checks that anonymising a session never changes what the rule engine concludes about it. An anonymiser that did would alter the evaluation without anyone noticing, which is the failure this whole document is about.

Kept deliberately: hostnames in URLs, which are attacker infrastructure; file hashes, which the project already publishes; and passwords an attacker sets, which belong to nobody. The mapping from real address to placeholder exists only in memory during one export and is never written down.

## Using it

```bash
# On the homelab, once, with the classifiers frozen
python -m honeypot_ai.label sample --per-class 20 --uniform 60 --seed 1

# Anywhere with a copy of the repository — no database needed
python -m honeypot_ai.label review --labeller david
python -m honeypot_ai.label status
```

`sample` refuses to overwrite an existing sample without `--force`: redrawing it would orphan every label written against it. Labels are append-only — changing your mind adds a line, the latest line per labeller wins, and the history of second thoughts is kept, because a session two careful readings disagreed about is worth knowing about.

## Labelling criteria

The precedence rule decides most cases; these are the ones it does not settle on its own.

**The furthest point reached, not the most prominent.** A session that spends forty commands surveying the hardware and then writes and runs a script is `staging`. This is the single least intuitive rule in the taxonomy and the one the small local model got wrong most often.

**Downloads are attempts.** The sensor blocks outbound traffic, so nothing a session tries to fetch ever arrives. Label what the attacker was doing, which is attempting the download; the attempt is what the data shows.

**A payload is a payload however it arrives.** Written through `echo -ne` and run is `staging` exactly as a `wget` and run is.

**`sh` alone is a shell escape; `sh file` is execution.** The first is the escape word for a restricted device menu and belongs to `shell_probing`.

**Interactive needs evidence.** Typos, hesitation, exploration, commands that react to earlier output. Slow is not evidence of a person. When unsure, `unknown` is the right answer, not a guess.

**`other` is for genuinely nothing.** Not for "unsure between two" — pick the furthest of the two — but for sessions no category describes. If `other` starts to fill up, that is the taxonomy asking to change, which is the reason it exists.

**Notes for anything you hesitated over.** A label you would defend in an argument and a label you picked at random look identical in a file. The note is how the difference survives.
