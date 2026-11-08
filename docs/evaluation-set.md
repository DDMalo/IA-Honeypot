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

## Known rule gaps, written down before labelling

The rules were frozen when the sample was drawn, so gaps found after that are recorded rather than fixed. Recording them here, before any label exists, turns each into a prediction the evaluation can confirm or refute — which is worth more than the fix, because a gap announced in advance and then measured is a result, while a gap discovered afterwards and quietly patched is a number nobody can trust.

- **Delivery through a base64 heredoc is not recognised.** A session that writes a binary with `base64 -d > file <<.` and is cut off before running it is filed by the rules as `resource_profiling`. Writing a payload to disk is `staging`. Expected: the rules are wrong on every such item.
- **`scp` is not recognised as a download.** The sessions in this sample that use it still reach `staging` through their other commands, so the gap is expected to show in behaviours rather than in intent.

**Outcome.** The first prediction was confirmed exactly: the rules filed all three heredoc sessions as `resource_profiling`, and the reference labels say `staging`. The second was confirmed for intent — the rules got both `scp` sessions right — and could not be tested for behaviours, because behaviours were not labelled in this round (below).

## Safe to commit

The set lives in `eval/` and is committed, because an evaluation nobody else can rerun is a claim rather than a result. Committing it means publishing attacker sessions, so export goes through an anonymiser that cannot be skipped:

- **Public IP addresses** become documentation addresses (RFC 5737, RFC 3849), consistently within an export, so two sessions using one server still visibly use one server. Private and loopback addresses are kept; they identify nobody and rewriting them would change what a session means.
- **Payloads typed in as text.** Long runs of hex escapes are cut to their first four bytes — enough to keep `\x7F ELF` recognisable and every hex-marker rule matching, nowhere near enough to reconstruct anything. Base64 runs of 40 characters or more, in the mixture of cases and digits that encoded data has and paths and digests do not, are replaced entirely by their length and a short hash. Nothing of them is kept.
- **Private keys**, tracked across commands: from a `BEGIN … PRIVATE KEY` marker to its `END`, everything is replaced, and the markers themselves are rewritten.

### What the first real sample found

The anonymiser was written against cases invented for its tests, and the first sample drawn from the real corpus showed what that is worth. Reviewed before it was committed, it contained:

- **two OpenSSH private keys**, which sessions wrote to disk and used to fetch their payloads over `scp`. One was pasted a line per command, the other as one multi-line command; every line was shorter than the 80-character threshold then in force;
- **a 64-bit ELF binary**, delivered as `base64 -d > /tmp/hum <<.` followed by sixty-four characters of base64 per command, and two more sessions using the same technique that were cut off part-way.

None of it had an IP address in it, which is what the anonymiser had been built to find. All of it was caught by reviewing the real export with a script before it reached the repository, and the rules that now catch it were checked against all 143 real items: nothing left in clear, and not one rule-engine label changed.

### What the second sample found

The fix was reviewed the same way, and the review was not clean either:

- **four more lines of the same ELF binary.** The anonymiser called a run "encoded" only if it mixed upper case, lower case and digits. A binary is full of zero padding, which base64 writes as `AAAA…`, so the lines that were mostly padding had none of the three and went through. The rule was tuned on text that looks like a key and missed data that looks like nothing. A heredoc that decodes base64 is now treated as payload by what it is, not by what each line looks like.
- **`Chrome/120.0.0.0` read as an IP address.** Seven User-Agents had their browser versions replaced by documentation addresses. It consumed placeholders, and it put an address where no server ever was — which a reader of the published set would reasonably take for data.

Export now re-runs the rule engine on every item before and after anonymising and stops if any answer differs.

### The sample that was labelled

The fixes meant drawing the sample again, with the same seed and the same frozen rules. It came back with 140 items rather than 143. Between the two draws the population had grown by one distinct sequence, 949 to 950, and a seeded draw is reproducible only over the same population: the uniform part is chosen by giving every sequence a random key in a fixed order, so one more sequence shifts every key after it. A different uniform part overlaps the strata differently, and the stratified part adds only what each class still lacks, so the total moves. Nothing was lost; the population a sample describes is recorded beside it in `eval/sample-meta.json` for exactly this reason.

The 140 items stand for 155,001 of the 156,739 sessions in that population. One of them alone stands for 103,209.

The lesson is the one this document keeps arriving at. A safeguard tested only against the cases its author imagined is tested against its author's imagination. The export is reviewed, every time, before it is committed.

A test checks that anonymising a session never changes what the rule engine concludes about it. An anonymiser that did would alter the evaluation without anyone noticing, which is the failure this whole document is about.

Kept deliberately: hostnames in URLs, which are attacker infrastructure; file hashes, which the project already publishes; and passwords an attacker sets, which belong to nobody. The mapping from real address to placeholder exists only in memory during one export and is never written down.

## Using it

```bash
# On the homelab, once, with the classifiers frozen
python -m honeypot_ai.label sample --per-class 20 --uniform 60 --seed 1

# Anywhere with a copy of the repository — no database needed
python -m honeypot_ai.label review --labeller david --intent-only
python -m honeypot_ai.label status

# Score the classifiers — also no database needed
python -m honeypot_ai.evaluate report eval/predictions/*.jsonl
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

## How the set was actually labelled

Everything above is the method. This is what happened when it was applied, including the parts that weaken it, because a reader deciding how far to trust the numbers needs those more than anything else.

**Intent only.** The labelling tool asks for intent, behaviours and operator. Intent is one choice among eight and the metric the evaluation is built on; behaviours are any of thirty, and they were most of the time a sitting took. The first round labelled intent only (`--intent-only`), and the tool records behaviours as *not labelled* rather than as *none*, so that an evaluation cannot mistake one for the other and count every behaviour a classifier finds as a false positive. Behaviours are not evaluated in v0.5.0.

**The first labeller is not a security specialist.** All 140 items were labelled blind by the project's author, with a one-page glossary of what common commands do — `uname`, `/proc/cpuinfo`, `chmod +x`, `authorized_keys`, `busybox` — written before labelling began and referring to no item in the sample. The glossary explains commands; it does not say what any session is.

**A second labeller, which is a language model.** Claude labelled the same 140 items without reading the first labeller's answers. It is not a fully independent second opinion, for two reasons recorded here rather than left out. It had seen the rules' strata while reviewing the sample for the anonymiser, so it was not blind to the rules. And while the first labeller worked, it answered questions about what commands do, and on five items it gave the intent outright — `4bdb8dc0df42`, `a22940d51f55`, `de93501df612`, `3a8128e90925` and `07e0b22a5eb2`. On those five the two labels are not independent; they agree, as they would.

**Agreement: 105 of 140 (75%), Cohen's kappa 0.70.** Most of the disagreement was one systematic difference: eleven sequences that download or upload a program and run it were labelled `persistence` by the first labeller and `staging` by the second. Persistence is installing a way back in — a key, a cron job, an account — and none of the eleven does that. Three more were slips that contradicted the first labeller's own answers on identical sequences, five were settled by the definitions, and sixteen were genuinely arguable.

**Adjudication.** The first labeller reviewed all 35 disagreements and accepted the second labeller's answer on every one. The reference labels the classifiers are scored against (`labeller: adjudicated`) are therefore identical to the language model's. Operator is kept where the two agreed and set to `unknown` where they did not, because it was not reviewed.

That last fact is the largest limitation in the evaluation, and it bears directly on the result: a reference written by one language model may favour another. It is tested rather than assumed — every classifier is also scored against the first labeller's independent labels, and the ranking does not change. The results and that check are in [`model-comparison.md`](model-comparison.md).
