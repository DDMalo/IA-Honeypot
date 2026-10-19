# Hosted and local models on this hardware

A first measurement, run to answer one question before building anything on top of it: is a model running on the homelab a usable alternative to a hosted one?

The short answer is no, and the interesting part is why.

## What was measured

Three real sessions, drawn with `--seed 1` so every provider got the same three, through the same prompt, the same parser and the same validation. The sessions were a shell-escape sequence, a hardware-survey-then-execute script, and a twenty-four command session that ends in staging.

| | Size | Availability | Median latency | Agreement with the rules |
|---|---:|---:|---:|---:|
| `gemini-3.5-flash-lite` (hosted) | — | 3/3 | 4.4 s | 3/3 |
| `qwen2.5:1.5b` (local) | 986 MB | 3/3 | 23.3 s | 1/3 |
| `llama3.2:3b` (local) | 2.0 GB | 0/3 | — | 0/2 |

The homelab is a laptop with 3.2 GB of RAM and no GPU, with about 2.5 GB free after PostgreSQL and Grafana.

**Agreement with the rules is not accuracy.** The rule engine is a baseline, not ground truth, and it has been wrong before — a model spotted a complete dropper chain that the rules had missed entirely. This column says how often the two agreed, which is a smoke test. Which of them was *right* is measured against human labels in v0.5.0, and that is a different number.

Three sessions is also not a sample. These figures say "this configuration works at all / does not", not "this model scores X".

## The local 3B model did not run, it thrashed

`llama3.2:3b` is 2.0 GB of weights on a machine with 2.5 GB free. It answered two sessions in 208 and 274 seconds and then exceeded a five-minute timeout on the third. That is not a slow model; that is a machine swapping to disk.

Its answers were also wrong in a way worth recording. For a session of `enable`, `linuxshell`, `system`, `sh` it answered `protocol_probe`, justifying it with "the session data contains HTTP requests and network discovery attempts". There were no HTTP requests. The model invented the evidence for the label it had chosen.

That is the failure mode to watch for in every model used here, and it is far more dangerous than being slow: a wrong label is visible in a comparison, while a wrong label with a confident explanation attached is the kind of thing that ends up quoted in a report.

## The local 1.5B model runs, and gets the taxonomy wrong

`qwen2.5:1.5b` answered every session, in 11 to 42 seconds, with no truncation and no retries. It is genuinely usable on this hardware.

It also disagreed with the rules on two of three, and both disagreements are the same mistake: it chose the **most prominent** behaviour rather than the **furthest point reached**. For the hardware survey that ends by writing and executing a script it answered `resource_profiling`; for the twenty-four-command session it answered `shell_probing`. In both the session goes further, and the precedence rule in [`taxonomy.md`](taxonomy.md) says the furthest point wins.

The prompt states that rule explicitly. A 1.5-billion-parameter model appears not to hold it against a wall of shell commands.

**The prompt was deliberately not tuned to fix this.** Rewriting it until the local model agrees with the rule engine would not measure whether the model is better; it would measure how well it had been made to imitate the baseline. The rule engine is the thing being compared against, not the answer key.

## Getting the local model to run at all

Two bugs stood between "it does not work" and the numbers above, and both were ours rather than the model's.

**An unbounded array.** The response schema let `behaviours` be any length. A model generating under a grammar will happily repeat enum values until it runs out of tokens, and every answer came back truncated mid-string. The parse error read as "the model cannot produce JSON" and was actually "the model produced valid JSON and we cut it in half." Bounding the array fixed it outright: availability went from 20% to 100% and median latency fell from 190 seconds to 23.

**Retrying a deterministic failure.** Generation runs at temperature zero, so a retry is the same request with the same answer. Two thirds of that 190 seconds was the same truncation being reproduced at a cost of ninety seconds a time. Truncation is now treated as permanent.

Neither bug would have been visible with a hosted model: a large model does not loop on an unbounded array, so the schema defect was latent until something smaller ran against it.

## What this means for the project

The pitch for a local model was that it has no quota, no queue and no vendor, and that attacker data never leaves the homelab. All of that is still true. What the measurement adds is that on *this* hardware it costs five times the latency and, on the evidence so far, a good deal of accuracy.

That is worth stating plainly rather than quietly dropping the local provider: the honest version of "we used a hosted model" is "we tried both and here is the table."

The local provider stays in the project. It is the only configuration where nothing leaves the machine, which matters for anyone wanting to reproduce this on data they cannot send to a third party, and the cost of keeping it is one more implementation behind an interface that already existed.

## Reproducing this

```bash
python -m honeypot_ai.classify.llm --provider gemini --sample 3 --seed 1
python -m honeypot_ai.classify.llm --provider ollama --sample 3 --seed 1
OLLAMA_MODEL=llama3.2:3b python -m honeypot_ai.classify.llm --provider ollama --sample 3 --seed 1
```

Deployment notes, including how to start Ollama and which model sizes fit, are in [`deploy/homelab/README.md`](../deploy/homelab/README.md).
