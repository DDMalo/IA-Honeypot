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

### Data handling

Everything under `/srv/honeypot/raw` contains attacker IP addresses and stays on this machine: it is never committed, never published, and subject to the retention policy documented with the project's privacy notes. Only aggregates leave the homelab.
