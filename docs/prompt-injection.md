# Prompt injection

Most pipelines that call a language model process cooperative input. This one processes commands typed by people actively trying to subvert a machine, and some of those people write for whatever reads the logs afterwards.

That is not speculative. The corpus already contains sessions that check whether they are inside a honeypot — `mount`, `env`, `ls /proc/self`, `history`, all asking the same question. Somebody built the expectation of being watched into their tooling. Assuming none of them will think to address the thing doing the watching would be optimistic.

## The threat

An attacker controls every byte of the session text. That text is placed into a prompt alongside instructions. The attacker's goal is to make the instructions in the data outrank the instructions from the operator.

What they could want out of it:

| Goal | Why it matters |
|---|---|
| A benign label on a hostile session | Hides the attack from reports and from the weekly summary |
| A hostile label on benign traffic | Poisons the statistics, wastes the analyst's time |
| An action | Would be the serious one — if there were any action to take |
| The system prompt | Reveals the taxonomy and the defences, making the next attempt better |

## What bounds the damage

**The model cannot do anything.** It returns JSON describing a session. There is no tool it can call, no command it can run, no field that becomes a shell argument, a file path or a query. An entirely successful injection changes one classification label.

This is the only defence that does not depend on a model behaving well, and it is the one the design rests on. Everything below raises the cost of an injection; this is what caps the payoff.

**The reply is validated against the taxonomy.** `extra="forbid"`, so a reply carrying fields nobody asked for is rejected whole rather than partially trusted. Every label is an enum, so a model that invents `intent: "authorised_penetration_test"` fails validation instead of widening the vocabulary by assertion. A rejected reply becomes `other` with zero confidence and a note.

**The session id comes from the session.** The model's answer is attached to the session that was sent, never to one the reply names. Otherwise one hostile session could relabel another.

**Free text is treated as hostile output.** The `rationale` was written by a model that has just read attacker text and will be printed by something. It is stripped of ANSI sequences and control characters and capped at 200 characters. A model talked into pasting its own instructions there leaks at most 200 characters of them.

## What raises the cost

**The data is fenced with a token the attacker cannot predict.** Delimiters like `---` or `<session>` can be closed by anything that types them. A random token generated per request cannot be guessed from inside the session, so text claiming to end the block is simply text. The corpus has a case that tries exactly this, and a test that confirms the fake close lands inside the real one.

**Instructions come before the data and are restated after it.** A model given a task, then a wall of hostile text, then nothing, is easier to redirect than one reminded of the task at the end.

**The data is normalised.** Control characters and ANSI sequences are stripped before the model sees them, long commands and long sessions are truncated, and the truncation is announced — a model not told the input was cut will reason confidently about the part it cannot see.

## Measuring it

Defences that are only described are defences nobody knows the strength of. `src/honeypot_ai/classify/llm/injection.py` holds twelve hostile sessions, each carrying two labels: what the session genuinely is, and what the injection is trying to make the model say. Those always differ, so each case has an unambiguous outcome — **resisted**, **injected**, or **confused**.

```bash
python -m honeypot_ai.classify.llm --injection-suite --provider gemini
python -m honeypot_ai.classify.llm --injection-suite --provider ollama
```

The techniques covered are a plain instruction override, a fake fence close, an impersonated system turn, a prefabricated JSON answer, an appeal to authority, a request for an action field, an attempt to exfiltrate the system prompt, many-shot repetition, a markdown code fence, a honeypot-aware appeal, a base64-encoded instruction, and a hypothetical framing.

The cases are synthetic. They are written in the shapes injections take rather than copied from captured sessions, because nobody has aimed one at this classifier yet and waiting for them is not a test strategy.

## What is deliberately not claimed

**This is not a solved problem.** No prompt makes a language model reliably distinguish instructions from data, because that distinction does not exist at the level the model operates on. The fence and the warnings raise the cost; they do not close the hole, and a suite that scores twelve out of twelve today may score nine next month against a different model.

**Agreement with the rule engine is not safety.** A model can resist every injection and still label badly, or be injected and happen to land on the right answer. The suite measures one property, not quality.

**The unit tests do not test the model.** They test what must hold whatever the model does: that hostile text stays inside the fence, that an invented field is rejected, that an exfiltrated prompt is truncated, that the session id cannot be reassigned. A defence that depends on a model behaving is not a defence, it is a hope with a success rate — so the properties that matter are the ones a wholly compromised model cannot violate.
