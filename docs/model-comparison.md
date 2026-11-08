# Hosted and local models on this hardware

Two measurements, months apart, answering two different questions. The first asked whether a model running on the homelab was usable at all, on three sessions, against the rule engine. The second, in v0.5.0, scored all three classifiers against 140 hand-labelled sequences and decided which one runs in production.

The short answer to both is the same — the hosted model, and the local one is not usable here — and the second measurement is the one that makes it a result rather than an impression.

## The evaluation (v0.5.0)

How the 140 sequences were chosen and labelled, and everything that can go wrong with that, is in [`evaluation-set.md`](evaluation-set.md). The full report, generated from the committed predictions, is [`eval/results.md`](../eval/results.md).

| Classifier | Accuracy | Macro-F1 | Accuracy, uniform part | Accuracy by session | Median latency |
|---|---:|---:|---:|---:|---:|
| Majority class (baseline) | 0.21 | 0.04 | 0.40 | 0.74 | — |
| Rules | 0.74 | 0.69 | 0.80 | 0.90 | <0.01 s |
| `gemini-3.5-flash-lite` | **0.85** | **0.78** | 0.80 | 0.89 | 4.0 s |
| `qwen2.5:1.5b` | 0.17 | 0.11 | 0.17 | 0.05 | 11.5 s (p90 32 s) |

**Gemini is more accurate than the rules, and not by luck.** On the items where exactly one of the two is right, Gemini is the right one 28 times and the rules 12 (exact McNemar test, p = 0.017). Macro-F1, which weights the rare classes as much as the flood, moves from 0.69 to 0.78.

**By session they tie.** One sequence stands for 67% of all sessions in the sample, and both classifiers get it right. Accuracy by session therefore says little beyond "that one is right", which is why the report prints how much the largest item weighs.

**On the uniform part alone they also tie**, at 0.80, and there the rules have the better macro-F1 (0.72 against 0.64). The uniform part is the 60 items drawn in proportion to traffic without looking at any label; most of its classes have one or two items, so its macro-F1 swings on single answers. The difference is in the stratified part, drawn to cover every class: rules 0.69, Gemini 0.89. Gemini's advantage is the long tail — the rare classes, and the delivery techniques the rules were never written for — not the traffic that dominates by volume.

**The local model is worse than guessing.** Qwen 2.5 1.5B scores below a classifier that always answers the commonest class. It labels most sessions `resource_profiling`, never answers `staging`, `persistence` or `fingerprinting`, and takes three times as long as Gemini to do it. The first measurement suspected this from three sessions; 140 confirm it.

### Where each one fails

- **The rules** file 12 of 26 shell-probing sequences as `other`: escape words and markers in combinations no rule was written for. And they miss payloads that do not arrive by `wget`: the three sessions that wrote a binary through `base64 -d <<.` are filed as `resource_profiling`, exactly as [predicted before labelling](evaluation-set.md#known-rule-gaps-written-down-before-labelling).
- **Gemini** gets every one of the 29 staging sequences right, the heredoc ones included. Its weak spot is the boundary between `fingerprinting` and `shell_probing`: eight sequences that only identify the host are called shell probing. It is the line in the taxonomy that most depends on a convention rather than on what the commands do.

### The caveat that matters most

The reference labels were adjudicated between two labellers, and on every one of the 35 disagreements the first labeller accepted the second's answer — and the second labeller is a language model (Claude). The reference is therefore identical to one model's labels, and part of Gemini's lead could be two models agreeing with each other rather than both being right.

That is checked rather than assumed. Scored against the first labeller's own labels, written blind and before any comparison, the ranking holds and the gap widens: Gemini 0.73, rules 0.56, McNemar p = 0.0003. The absolute figures move with the reference; the order does not. Both are in the report, and anyone can re-score against either with `--reference`.

### The decision

The rules label every session as it arrives: they are instant, free, deterministic and need nothing outside the homelab. Gemini adds a second label once per distinct command sequence, on a daily timer capped at 200 calls, and the answer is copied to every session that shares the sequence. New distinct sequences arrive at about a hundred a day — between 69 and 124 a day in the fortnight before this release — so the cap has room to spare, and that spare half works through the 1,951 sequences that were pending at the first run. Both labels are kept, as they always have been, so the disagreement between them stays queryable.

The local provider stays in the code — it is still the only configuration where attacker data never leaves the machine — but it is not scheduled. On 3.2 GB of RAM the model that fits is not good enough, and that is a statement about this hardware, not about local models.

### Reproducing it

```bash
python -m honeypot_ai.evaluate predict --classifier rules
python -m honeypot_ai.evaluate predict --classifier gemini      # needs GEMINI_API_KEY
python -m honeypot_ai.evaluate predict --classifier ollama      # needs Ollama running
python -m honeypot_ai.evaluate report eval/predictions/*.jsonl
python -m honeypot_ai.evaluate report eval/predictions/*.jsonl --reference david
```

The predictions are committed, so only the last two lines are needed to check the numbers. Neither needs the database.

## The first measurement (v0.4.0)

### What was measured

Three real sessions, drawn with `--seed 1` so every provider got the same three, through the same prompt, the same parser and the same validation. The sessions were a shell-escape sequence, a hardware-survey-then-execute script, and a twenty-four command session that ends in staging.

| | Size | Availability | Median latency | Agreement with the rules |
|---|---:|---:|---:|---:|
| `gemini-3.5-flash-lite` (hosted) | — | 3/3 | 4.4 s | 3/3 |
| `qwen2.5:1.5b` (local) | 986 MB | 3/3 | 23.3 s | 1/3 |
| `llama3.2:3b` (local) | 2.0 GB | 0/3 | — | 0/2 |

The homelab is a laptop with 3.2 GB of RAM and no GPU, with about 2.5 GB free after PostgreSQL and Grafana.

**Agreement with the rules is not accuracy.** The rule engine is a baseline, not ground truth, and it has been wrong before — a model spotted a complete dropper chain that the rules had missed entirely. This column says how often the two agreed, which is a smoke test. Which of them was *right* was measured against labelled data in v0.5.0, above, and that is a different number.

Three sessions is also not a sample. These figures say "this configuration works at all / does not", not "this model scores X".

### The local 3B model did not run, it thrashed

`llama3.2:3b` is 2.0 GB of weights on a machine with 2.5 GB free. It answered two sessions in 208 and 274 seconds and then exceeded a five-minute timeout on the third. That is not a slow model; that is a machine swapping to disk.

Its answers were also wrong in a way worth recording. For a session of `enable`, `linuxshell`, `system`, `sh` it answered `protocol_probe`, justifying it with "the session data contains HTTP requests and network discovery attempts". There were no HTTP requests. The model invented the evidence for the label it had chosen.

That is the failure mode to watch for in every model used here, and it is far more dangerous than being slow: a wrong label is visible in a comparison, while a wrong label with a confident explanation attached is the kind of thing that ends up quoted in a report.

### The local 1.5B model runs, and gets the taxonomy wrong

`qwen2.5:1.5b` answered every session, in 11 to 42 seconds, with no truncation and no retries. It is genuinely usable on this hardware.

It also disagreed with the rules on two of three, and both disagreements are the same mistake: it chose the **most prominent** behaviour rather than the **furthest point reached**. For the hardware survey that ends by writing and executing a script it answered `resource_profiling`; for the twenty-four-command session it answered `shell_probing`. In both the session goes further, and the precedence rule in [`taxonomy.md`](taxonomy.md) says the furthest point wins.

The prompt states that rule explicitly. A 1.5-billion-parameter model appears not to hold it against a wall of shell commands.

**The prompt was deliberately not tuned to fix this.** Rewriting it until the local model agrees with the rule engine would not measure whether the model is better; it would measure how well it had been made to imitate the baseline. The rule engine is the thing being compared against, not the answer key.

### Getting the local model to run at all

Two bugs stood between "it does not work" and the numbers above, and both were ours rather than the model's.

**An unbounded array.** The response schema let `behaviours` be any length. A model generating under a grammar will happily repeat enum values until it runs out of tokens, and every answer came back truncated mid-string. The parse error read as "the model cannot produce JSON" and was actually "the model produced valid JSON and we cut it in half." Bounding the array fixed it outright: availability went from 20% to 100% and median latency fell from 190 seconds to 23.

**Retrying a deterministic failure.** Generation runs at temperature zero, so a retry is the same request with the same answer. Two thirds of that 190 seconds was the same truncation being reproduced at a cost of ninety seconds a time. Truncation is now treated as permanent.

Neither bug would have been visible with a hosted model: a large model does not loop on an unbounded array, so the schema defect was latent until something smaller ran against it.

### What this means for the project

The pitch for a local model was that it has no quota, no queue and no vendor, and that attacker data never leaves the homelab. All of that is still true. What the measurement adds is that on *this* hardware it costs five times the latency and, on the evidence so far, a good deal of accuracy.

That is worth stating plainly rather than quietly dropping the local provider: the honest version of "we used a hosted model" is "we tried both and here is the table."

The local provider stays in the project. It is the only configuration where nothing leaves the machine, which matters for anyone wanting to reproduce this on data they cannot send to a third party, and the cost of keeping it is one more implementation behind an interface that already existed.

### Reproducing this

```bash
python -m honeypot_ai.classify.llm --provider gemini --sample 3 --seed 1
python -m honeypot_ai.classify.llm --provider ollama --sample 3 --seed 1
OLLAMA_MODEL=llama3.2:3b python -m honeypot_ai.classify.llm --provider ollama --sample 3 --seed 1
```

Deployment notes, including how to start Ollama and which model sizes fit, are in [`deploy/homelab/README.md`](../deploy/homelab/README.md).
