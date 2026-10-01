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

## Data handling

Everything under `/srv/honeypot/raw`, and everything in the database, contains attacker IP addresses and stays on this machine: it is never committed, never published, and subject to the retention policy documented with the project's privacy notes. Only aggregates leave the homelab.
