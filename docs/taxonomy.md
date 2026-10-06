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

### `protocol_probe`

Spoke a different protocol at the port entirely.

```
User-Agent: Mozilla/5.0 zgrab/0.x
Accept: */*
Accept-Encoding: gzip
```

```
From: <sip:nm@nm>;tag=root
CSeq: 42 OPTIONS
Max-Forwards: 70
```

Internet-wide census scanners send HTTP or SIP at whatever port answers, so the honeypot records request headers where commands would be. The actor never engaged with the emulated shell and may not know what it reached.

This has its own category rather than living in `other` because conflating "ran `uname` on my host" with "spoke HTTP at my SSH port" would quietly inflate every attack statistic this project produces. It sits at the bottom of the precedence order: this is the least engagement a session can have.

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
protocol_probe → credential_access → fingerprinting → shell_probing
    → resource_profiling → staging → persistence
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

## Revision: what the first full run changed

The rules were run over the whole corpus — 11,991 sessions by then — and 2.5% came back as `other`, above the threshold this document sets for "the taxonomy is wrong and should change". Reading those sessions produced four findings, which is the loop working rather than failing.

**Scanners speaking other protocols.** HTTP and SIP requests arriving at ports 22 and 23, from census tools like zgrab. Not attacks on the honeypot in any sense this taxonomy was built for, and counting them as reconnaissance would have inflated every figure. Now `protocol_probe`.

**Ordinary looking around.** `pwd`, `ls -la /`, `netstat -tulpn`, `hostname`, `ssh -V`. Fingerprinting, plainly, but the first pass had no patterns for filesystem or network discovery — and the host-enumeration pattern required `hostnamectl`, so bare `hostname` fell straight through. Two new behaviours and one fixed pattern.

**The same attack, obfuscated.** Eleven of the first twenty unlabelled sessions were this:

```
lghkel
zpz}ld
zalee
za
```

Decoded with a single-byte XOR of `0x09`, that is `enable`, `system`, `shell`, `sh` — the identical restricted-shell escape sequence as every other Mirai-family session in the corpus, sent through a client that obfuscates it. The rule engine now tries that decode, under two constraints that matter: the decoded text must be printable, and it must match a rule that already exists. The decoder can therefore surface a match that was missed, but can never invent a category or override a plain-text one. A decoder free to reinterpret anything eventually reinterprets something real.

Sessions decoded this way also carry an `obfuscated_command` behaviour, because choosing to obfuscate is itself a thing the actor did and worth counting.

**A number that looks wrong and is not.** `gpu_detection` fires on 344 sessions but `resource_profiling` is the final label on only 72. That is the precedence rule doing its job: most of the hardware surveys go on to write and execute a test script, so they land on `staging`. The behaviour counts and the intent counts answer different questions, and this is the clearest example of why both exist.

## Second pass: the sessions that were asking about us

After those fixes `other` fell from 2.5% to 0.8% and rule coverage rose to 97.4%. What remained was almost entirely one family, four commands, each appearing in its own session:

```
env | head -10
mount | head -5
ls /proc/self 2>/dev/null | wc -l
history | tail -5
```

These are not reconnaissance of the host. They are reconnaissance of the *shell*. `mount` reveals an overlay filesystem, `env` leaks container variables, `/proc/self` is conspicuously thin inside a jail, and an empty `history` means nobody has ever actually used the account. All four ask the same question: **am I in a honeypot?**

That needed no new intent. `shell_probing` was already defined as "tried to obtain or confirm a usable shell", and confirming the shell is genuine is exactly that — so this became a behaviour, `sandbox_check`, under the intent that already covered it. Resisting the urge to add a category for every interesting finding is most of what keeps a taxonomy usable.

It is worth sitting with what these sessions mean. Everything else in this corpus is a bot executing a fixed script against whatever answered. These are checking whether the thing that answered is real — which means somebody, somewhere, built the expectation of honeypots into their tooling. The honeypot is being studied back.

Two smaller fixes came with it. The filesystem pattern anchored to end-of-line, so `ls /proc/self 2>/dev/null | wc -l` fell through for having a pipe after it. And a session whose only command is `exit` is now `credential_access`: issuing nothing but a way out is indistinguishable from issuing nothing at all.

### Where this stops

The remaining `other` is a long tail, and it stays that way. Writing a rule for each surviving session would produce a classifier that scores beautifully on this corpus and generalises to nothing — the rule engine's job is to be a fair baseline, not to win. Reaching the last fraction of a per cent by reading intent rather than matching strings is the work the language model is for, and the comparison is only honest if the baseline stops at a defensible point rather than being tuned until it looks good.
