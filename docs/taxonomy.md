# Attack taxonomy

These are the labels this project predicts. They were derived from 7,735 real sessions captured by this honeypot in its first week, not chosen from a list of categories that sounded plausible and fitted to the data afterwards. That ordering is the point: categories invented first tend to describe the analyst rather than the attacks.

The code is in [`src/honeypot_ai/classify/taxonomy.py`](../src/honeypot_ai/classify/taxonomy.py), which everything else imports from, so a category cannot drift between the rule engine, the language model, the labelling tool and the evaluation.

## What the data actually looks like

| | Sessions | Share |
|---|---:|---:|
| Total | 7,735 | |
| Authenticated | 6,924 | 90% |
| Issued at least one command | 6,602 | 85% |
| Issued more than five | 911 | 12% |
| Issued **exactly one** | 5,569 | 72% |

Two things follow from that table, and both shape everything downstream.

**This honeypot is permissive, so almost everyone gets in.** Ninety per cent of sessions authenticate. "Brute force that failed" is therefore not a useful category here — what varies is what happens *after* the door opens.

**Seventy-two per cent of sessions run exactly one command**, and that command is overwhelmingly `uname -s -v -n -r -m`. A classifier that answers "fingerprinting" to everything, always, scores about 68% accuracy while knowing nothing. That number is the floor, and it is why accuracy is not the metric this project reports: **macro-averaged F1** is, because it weights the rare classes — which are the interesting ones — equally with the flood.

It also determines how the labelled set in v0.5.0 gets built. Two hundred sessions drawn at random would be roughly 136 fingerprinting probes and one or two of everything else, which measures nothing. The sample must be **stratified**.

## The two axes

A session gets exactly one **intent** and any number of **behaviours**.

Intent answers *how far did this actor get, and what were they after?* It is single-valued because evaluation needs one correct answer per session.

Behaviour answers *what did they actually do?* It is multi-valued, and it is the unit that maps to MITRE ATT&CK techniques in v0.6.0. Keeping the two apart means the ATT&CK mapping can grow without renegotiating the labels the classifier predicts.

A third, independent field records whether a human appeared to be at the keyboard: `automated`, `interactive` or `unknown`. In this dataset essentially everything is automated, and that is itself a finding worth stating rather than assuming.

## Intents

### `credential_access`

Logged in and nothing more. No command was ever issued.

Not the same as "failed to log in". These mostly authenticated successfully and then disconnected — they were harvesting working credentials, not using them. 1,133 sessions, about 15%.

### `fingerprinting`

Established what the host is, then left.

```
uname -s -v -n -r -m
```

That single line, alone in a session, accounts for 4,874 of them, with another 368 as `/bin/./uname -s -v -n -r -m`. No attempt to act on the machine. This is a census: somebody building an inventory of what is reachable on the internet, to be revisited later.

### `shell_probing`

Tried to obtain or confirm a usable shell.

```
enable ; system ; shell ; sh ; linuxshell
```

Those words are not Unix commands. They are the escape words for the restricted menu shells that routers, DVRs and IP cameras ship with, tried in sequence in the hope that one of them drops the caller into something real. 490 sessions follow this exact nine-command pattern. `busybox` probes belong here too: `/bin/busybox HISILICON` (135 sessions) is checking for a chipset found in cheap surveillance hardware.

The actor does not yet know whether it has a shell. Everything else is contingent on finding out.

### `resource_profiling`

Measured what the machine is worth.

The distinction from fingerprinting is identity versus value: one asks what the host *is*, this asks what it is *good for*. One script in this dataset, appearing 271 times, collects architecture, uptime, core count, CPU model from `lscpu` and `/proc/cpuinfo`, login history via `last` — and then this:

```sh
gpu_info=$( (lspci | grep -i vga; lspci | grep -i nvidia; ...) )
```

A GPU probe on a random internet host is mining reconnaissance. Nothing else wants to know whether an anonymous SSH box has an NVIDIA card.

### `staging`

Prepared the ground for a payload.

```sh
>/dev/.f && chmod 777 /dev/.f && /dev/.f && cd /dev/;
>/var/.f && chmod 777 /var/.f && /var/.f && cd /var/;
>/var/run/.f && chmod 777 /var/run/.f && /var/run/.f && cd /var/run/;
```

Forty-four sessions sweep eleven directories this way, looking for one that is both writable and executable — the place a dropped binary will be able to run from. The same intent appears as a shell-capability test, writing a throwaway script and executing it to confirm the machine can run what it is about to be sent.

The payload need not have arrived. Outbound traffic is blocked on this sensor, so `wget` and `curl` fail; the *attempt* is what is recorded, and for classification the attempt is what matters.

### `persistence`

Installed a way back in.

```sh
cd ~; chattr -ia .ssh; lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA…mdrfckr" >> .ssh/authorized_keys
```

Seventy-nine sessions, three commands each, always the same key. Note the order: the immutable flags come off first, in case a previous occupant locked the directory. This is the furthest an actor gets, and the only intent that outlives the session.

### `other`

Does not fit the above. Deliberately not a dumping ground: every `other` is a prompt to ask whether the taxonomy is missing something. **If this class grows past a few per cent of the labelled set, the taxonomy is wrong and should change** — rather than the sessions being forced into categories that do not fit them.

## The precedence rule

Most sessions do more than one thing, so the single label needs a tie-break that two different people would apply the same way.

**The intent is the furthest point reached**, in this order:

```
credential_access → fingerprinting → shell_probing → resource_profiling → staging → persistence
```

A session that runs `uname`, then writes an SSH key, is `persistence` — not `fingerprinting` — because the fingerprinting was in service of the rest.

That is a decision, not a fact. The alternative, labelling by whatever the session spent most of its commands on, would classify that same session as fingerprinting, which is useless for triage: the thing you need to know is that somebody left a key behind. Recorded here so the choice stays visible instead of living in one labeller's habits.

## Behaviours

| Group | Labels |
|---|---|
| Discovery | `host_enumeration`, `user_enumeration`, `architecture_detection`, `cpu_profiling`, `gpu_detection`, `uptime_check`, `login_history_check`, `process_enumeration` |
| Shell acquisition | `shell_escape`, `busybox_probe`, `marker_echo` |
| Staging | `writable_dir_hunt`, `permission_change`, `execution_test`, `payload_download`, `payload_execution` |
| Persistence | `ssh_dir_reset`, `immutable_flag_clear`, `authorized_keys_write`, `cron_install`, `account_creation` |
| Holding the box | `competitor_kill`, `history_clearing` |
| Reaching outwards | `lateral_scan` |

Two of these deserve a note.

`marker_echo` covers a session echoing a fixed string to confirm the shell executes and to announce itself to its own operator. In this dataset that is `echo -e "\x47\x41\x59\x46\x47\x54"` (84 sessions) — the hex spells a word that identifies a well-known botnet family — and `echo xsec` (135 sessions).

`competitor_kill` is malware removing other malware. Thirty sessions here run a loop over `/proc`, find every process whose executable has been deleted from disk, and kill it — a precise description of a fileless cryptominer, and of nothing legitimate. It is a behaviour rather than an intent because it is almost never the point of a session, only something done on the way.

Behaviours are the layer that gets ATT&CK technique identifiers attached in v0.6.0, validated against the official data rather than typed from memory. No identifiers appear here, so there is one place to get them wrong instead of two.

## What this taxonomy does not do

It does not attribute sessions to campaigns or families. The data clearly contains distinct, recognisable actors — the nine-command escape sequence, the `.f` directory sweep, the single recurring SSH key — but naming them is clustering, which is v1.2.0, and guessing at family names from fragments is how threat reports end up wrong.

It does not describe severity. A persistence attempt is further along than a fingerprint, which is what precedence captures; whether it is *worse* depends on a real system's context, and this honeypot has none.
