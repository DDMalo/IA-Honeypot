# Homelab deployment

The homelab analyses what the sensor collects. Its first job is getting the data here.

## Log shipping

### Why the homelab pulls

Three options were considered:

| Approach | Why not |
|---|---|
| Sensor pushes with rsync/scp | The sensor would need a credential that reaches into the home network — exactly what the threat model forbids |
| A log shipper agent (Vector, Fluent Bit) | Another daemon to run, configure and keep updated on an exposed machine, for a single append-only file |
| **Homelab pulls with rsync over SSH** | Chosen |

Pulling keeps the direction of trust right: the sensor holds nothing that can reach home, and the machine that needs the data is the one that asks for it. rsync transfers only what changed and is safe to re-run, so a missed run is corrected by the next one and no state has to be tracked between runs.

A timer runs the sync every 15 minutes. Nothing in this pipeline is real time — sessions are analysed after the fact — so a short delay costs nothing, while a short interval would fill the journal with failures whenever the sensor is briefly unreachable.

### Installation

```bash
sudo install -m 0755 sync-cowrie-logs.sh /usr/local/bin/sync-cowrie-logs.sh
sudo install -m 0644 cowrie-log-sync.service /etc/systemd/system/
sudo install -m 0644 cowrie-log-sync.timer /etc/systemd/system/

sudo install -m 0600 cowrie-log-sync.env.example /etc/default/cowrie-log-sync
sudo nano /etc/default/cowrie-log-sync      # fill in the sensor's tunnel address

sudo mkdir -p /srv/honeypot/raw
sudo chown -R david:david /srv/honeypot

sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-log-sync.timer
```

Run it once by hand before trusting the timer:

```bash
sudo systemctl start cowrie-log-sync.service
journalctl -u cowrie-log-sync.service -n 30 --no-pager
```

### Operations

```bash
systemctl list-timers cowrie-log-sync.timer     # when it last ran, when it runs next
journalctl -u cowrie-log-sync.service -f        # watch a run
wc -l /srv/honeypot/raw/cowrie.json             # events collected so far
du -sh /srv/honeypot/raw                        # disk usage
```

### Restricting the key further

The homelab's key on the sensor is already limited to one source address (see `docs/tunnel.md`). It can be narrowed further so it cannot be used for anything but this transfer, by adding a forced command and disabling the features a file sync never needs:

```
from="<homelab-tailnet-ip>",command="rrsync -ro /srv/cowrie/log",no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA... homelab-to-sensor
```

`rrsync` ships with rsync and confines the transfer to one directory, read-only. Check it is installed on the sensor first (`command -v rrsync`), apply the change, and **verify a sync still works before closing the session that made the edit** — a wrong forced command locks the key out, which is easy to undo only while another session is open.

## Database

PostgreSQL holds the sessions once they are parsed. It runs in a container on this machine and is **bound to loopback only**: Docker publishes ports by inserting firewall rules ahead of `ufw`, so a port published on `0.0.0.0` would be reachable from the whole network no matter what `ufw` says. Reach it from elsewhere with an SSH port forward over the tunnel.

### Starting it

```bash
cp ../../.env.example ../../.env     # once, then edit POSTGRES_PASSWORD
docker compose --env-file ../../.env up -d
docker compose ps
```

### Applying migrations

The schema is managed with Alembic, so the database is built by replaying migrations rather than by hand. `alembic.ini` carries no connection string; the URL is read from the environment at runtime, which keeps the password out of the repository.

```bash
cd ~/IA-Honeypot
source .venv/bin/activate
set -a && . ./.env && set +a
alembic upgrade head
```

Useful checks:

```bash
alembic current                  # which revision is applied
alembic history --verbose        # what exists
alembic check                    # do the models and the database still agree?
```

`alembic check` is the one to run after changing a model: it reports any difference between the code and the migrations, which is how a forgotten migration is caught before it reaches `main`.

### Schema at a glance

| Table | Holds |
|---|---|
| `sessions` | One row per connection; the primary key is Cowrie's own session id |
| `login_attempts` | Every credential pair tried, in order |
| `commands` | Every command typed, flagged when Cowrie could not emulate it |
| `file_transfers` | URLs attackers tried to fetch, and hashes of anything captured |
| `ip_intel` | One row per source address: location, network, reputation |

Two properties the ingestion worker depends on:

- **Re-ingestion is safe.** The session id is the primary key and child rows are unique per `(session_id, seq)`, so reading the same log twice changes nothing. A failed run is fixed by running it again.
- **Deleting a session deletes its contents.** Foreign keys cascade, which is what makes the retention policy a single `DELETE` rather than a script.

`sessions` also stores `authenticated` and `command_count`, duplicating what the child tables already say. That is deliberate: nearly every question asked of this data begins by separating the sessions that got in and did something from the overwhelming majority that only guessed passwords, and that filter should not need a join.

## Ingestion

Parsing the synced log and loading it into PostgreSQL.

```bash
cd ~/IA-Honeypot
source .venv/bin/activate
set -a && . ./.env && set +a
python -m honeypot_ai.ingest /srv/honeypot/raw/cowrie.json
```

The command prints what it did, for example `412 sessions seen, 7 new, 2 updated, 403 unchanged`.

**Running it again is safe and cheap.** The session id is the primary key, and a session is only rewritten when it has actually grown, so a second run over the same file reports everything unchanged and touches nothing. That is what removes the need to remember a position in the file — the usual source of bugs when the log rotates, the sync writes a partial file, or the process dies mid-run.

### On a timer

```bash
sudo install -m 0644 cowrie-ingest.service /etc/systemd/system/
sudo install -m 0644 cowrie-ingest.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-ingest.timer
```

It runs every 20 minutes, offset from the log sync so it reads a file that has just been updated.

```bash
systemctl list-timers 'cowrie-*'
journalctl -u cowrie-ingest.service -n 20 --no-pager
```

### Looking at the data

```bash
docker exec -it honeypot-postgres psql -U honeypot -d honeypot
```

```sql
-- How much is in there
SELECT count(*) FROM sessions;

-- The sessions worth reading: someone got in and ran something
SELECT session_id, src_ip, command_count, started_at
FROM sessions WHERE command_count > 0 ORDER BY started_at DESC LIMIT 10;

-- Most-tried credentials
SELECT username, password, count(*) AS tries
FROM login_attempts GROUP BY 1, 2 ORDER BY tries DESC LIMIT 20;

-- What attackers actually type once inside
SELECT input, count(*) FROM commands GROUP BY 1 ORDER BY 2 DESC LIMIT 20;

-- Busiest source networks (this is why src_ip is `inet` and not text)
SELECT network(set_masklen(src_ip, 24)) AS subnet, count(*)
FROM sessions GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
```

## Enrichment

Sessions carry an address and nothing else. Enrichment turns that address into a country and a network, which is what makes the data answerable: *who* is attacking, not just *how much*.

### What it is, and what it is not

Geolocation places the machine sending the packets. For a botnet that is a compromised router in someone's house, not the person running it. **The country is where the traffic comes from, not where the attacker is**, and this distinction belongs in any conclusion drawn from it. The autonomous system — the network operator — is the sturdier signal: hosting providers and bulletproof hosts show up clearly, and they say more about intent than a flag does.

City-level accuracy is poor and is kept only to draw a map.

### Databases

MaxMind's GeoLite2 databases are files queried offline. That beats a web API here: tens of thousands of addresses resolve in seconds, with no rate limit and nothing about the honeypot's traffic leaving the machine.

They are free but require an account, and their licence requires attribution (see the project README).

```bash
sudo apt install -y geoipupdate
sudo mkdir -p /srv/honeypot/geoip
sudo chown david:david /srv/honeypot/geoip

sudo install -m 0600 GeoIP.conf.example /etc/GeoIP.conf
sudo nano /etc/GeoIP.conf          # AccountID and LicenseKey from maxmind.com
sudo geoipupdate -v
ls -la /srv/honeypot/geoip         # expect GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
```

Keep them current — address blocks are reassigned, and a stale database quietly produces wrong answers:

```bash
sudo install -m 0644 geolite-update.service /etc/systemd/system/
sudo install -m 0644 geolite-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now geolite-update.timer
```

### Running it

```bash
cd ~/IA-Honeypot
source .venv/bin/activate
set -a && . ./.env && set +a
python -m honeypot_ai.enrich -v
```

Work is done per address, not per session: one bot accounts for hundreds of sessions, so resolving it once is the difference between a few thousand lookups and tens of thousands. Addresses already looked up are skipped, including those the databases did not recognise — "looked up, not known" is recorded as such so the lookup is not repeated forever.

On a timer:

```bash
sudo install -m 0644 cowrie-enrich.service /etc/systemd/system/
sudo install -m 0644 cowrie-enrich.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-enrich.timer
systemctl list-timers 'cowrie-*' 'geolite-*'
```

### Questions it opens up

```sql
-- Where the traffic comes from
SELECT i.country_name, count(*) AS sessions
FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip
GROUP BY 1 ORDER BY 2 DESC LIMIT 15;

-- Which networks host the attackers: usually more telling than the country
SELECT i.asn, i.as_org, count(*) AS sessions, count(DISTINCT s.src_ip) AS addresses
FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip
WHERE i.asn IS NOT NULL
GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15;

-- Networks whose traffic actually gets in and runs commands, rather than
-- just guessing passwords
SELECT i.as_org, count(*) AS interactive
FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip
WHERE s.command_count > 0
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- How much of the traffic could not be resolved at all
SELECT count(*) FILTER (WHERE i.country_code IS NULL) AS unknown, count(*) AS total
FROM sessions s LEFT JOIN ip_intel i ON i.ip = s.src_ip;
```

## Reputation

Geolocation says where a machine is. Reputation says whether anyone else has seen it misbehave — and, more usefully, what kind of address it is.

### Why it is a separate stage

Enrichment reads local files and can run every half hour without consequence. Reputation crosses the network against an allowance of 1,000 checks a day, so it has its own worker, its own timer and its own caching rule. Running them together would mean a rate limit on one delaying the other, for no gain.

### Getting a key

Register at [abuseipdb.com](https://www.abuseipdb.com), then *Account* → *API* → *Create Key*. The free tier allows 1,000 checks a day, which is ample: the work is per address, not per session, and each result is trusted for a fortnight.

Put it in `.env`:

```
ABUSEIPDB_API_KEY=...
```

### Running it

Start with the dry run, which costs nothing and tells you how much of the budget a real run would spend:

```bash
cd ~/IA-Honeypot
source .venv/bin/activate
set -a && . ./.env && set +a
python -m honeypot_ai.reputation --dry-run
python -m honeypot_ai.reputation -v
```

The run reports how many checks are left for the day. Addresses are checked busiest first, so if the budget runs out it runs out on the long tail of one-session scanners rather than on the bot that has been hammering the sensor all week.

On a timer — once a day is enough, since the allowance is daily and the data changes slowly:

```bash
sudo install -m 0644 cowrie-reputation.service /etc/systemd/system/
sudo install -m 0644 cowrie-reputation.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-reputation.timer
systemctl list-timers 'cowrie-*'
```

### Reading the result honestly

`abuse_score` is a 0-100 confidence drawn from reports other people filed. It is evidence, not a verdict, and it is biased: ranges that annoy people with the resources to file reports are reported heavily, domestic connections barely. A score of zero means nobody complained, not that the address is innocent — and this honeypot has the logs to prove otherwise.

`abuse_usage_type` is the field worth the API call. It separates a rented datacentre machine, where someone is deliberately scanning the internet, from a residential address, which is almost always a compromised router or camera whose owner has no idea. That distinction is what the classifier in v0.4.0 will want, and it is not something the logs can tell you on their own.

```sql
-- The addresses other people have reported most, among those that got in
SELECT s.src_ip, i.abuse_score, i.abuse_reports, i.abuse_usage_type, count(*) AS sessions
FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip
WHERE i.abuse_score >= 50
GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT 20;

-- Rented infrastructure versus compromised home devices
SELECT i.abuse_usage_type, count(DISTINCT s.src_ip) AS addresses, count(*) AS sessions
FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip
WHERE i.abuse_usage_type IS NOT NULL
GROUP BY 1 ORDER BY 3 DESC;

-- Does a bad reputation predict an attacker who does more than guess passwords?
SELECT
  i.abuse_score >= 50 AS reported,
  count(*) AS sessions,
  count(*) FILTER (WHERE s.command_count > 0) AS interactive
FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip
WHERE i.abuse_checked_at IS NOT NULL
GROUP BY 1;

-- How much of the budget is left to spend
SELECT count(*) AS unchecked
FROM (SELECT DISTINCT src_ip FROM sessions) s
LEFT JOIN ip_intel i ON i.ip = s.src_ip
WHERE i.abuse_checked_at IS NULL;
```

That third query is the one to keep an eye on. If reported and unreported addresses behave identically once they are in the shell, the score is not carrying information about this dataset and should not be fed to the classifier as though it were.

## Retention

Captured sessions contain IP addresses, which are personal data. Keeping them indefinitely needs a justification, so retention is enforced rather than intended. The reasoning, and what is kept where, is in [`docs/privacy.md`](../../docs/privacy.md).

```bash
cd ~/IA-Honeypot
source .venv/bin/activate
set -a && . ./.env && set +a

python -m honeypot_ai.retention --dry-run   # rehearse: reports, changes nothing
python -m honeypot_ai.retention             # enforce
```

Deleting is irreversible, which is why the dry run exists and why the default window is a generous year.

On a timer, weekly:

```bash
sudo install -m 0644 cowrie-retention.service /etc/systemd/system/
sudo install -m 0644 cowrie-retention.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-retention.timer
```

Raw synced logs are pruned by the sync script itself, after `RAW_RETENTION_DAYS` (90 by default). The sensor prunes its own copies on its own timer — see `deploy/sensor/README.md`.

## Data handling

Everything under `/srv/honeypot/raw`, and everything in the database, contains attacker IP addresses and stays on this machine: it is never committed, never published, and subject to the retention policy documented with the project's privacy notes. Only aggregates leave the homelab.
