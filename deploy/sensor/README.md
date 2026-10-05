# Sensor deployment

Cowrie honeypot, deployed with Docker Compose on the internet-facing VPS.

Prerequisite: Docker Engine and the Compose plugin, installed from Docker's official repository (see `docs/sensor-setup.md` for the host hardening this assumes).

## Layout

| Path | Contents |
|---|---|
| `/srv/cowrie/log` | Cowrie logs, including `cowrie.json` |
| `/srv/cowrie/downloads` | Files attackers tried to fetch |
| `/srv/cowrie/tty` | Recorded session replays |

These live outside the repository. **Nothing under `/srv/cowrie` is ever committed**: the logs contain IP addresses, and the downloads directory contains live malware.

## First deployment

The container runs as uid/gid 999, so the bind-mounted directories must be owned by that id or Cowrie fails to write its logs and session recordings. Confirm the id rather than assuming it:

```bash
docker run --rm --entrypoint /cowrie/cowrie-env/bin/python cowrie/cowrie:latest \
  -c "import os; print(os.getuid(), os.getgid())"
```

Then:

```bash
sudo mkdir -p /srv/cowrie/{log,downloads,tty}
sudo chown -R 999:999 /srv/cowrie
docker compose up -d
docker compose logs --tail 30
```

A `PermissionError` on `var/lib/cowrie/tty/...` in the logs means the ownership above is wrong: the honeypot still answers attackers, but nothing is recorded.

## Egress containment

Docker inserts its own rules ahead of `ufw`, so the host's outbound policy does not apply to container traffic. The container is therefore confined at the `DOCKER-USER` chain: replies to inbound connections are allowed, new outbound connections from the honeypot network are dropped.

```bash
sudo iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
sudo iptables -I DOCKER-USER 2 -s 172.31.66.0/24 ! -d 172.31.66.0/24 -j DROP
sudo apt install -y iptables-persistent   # answer "Yes" to save current rules
sudo netfilter-persistent save
```

Consequence worth knowing: Cowrie normally *does* fetch the URLs an attacker passes to `wget` or `curl`. With egress blocked the fetch fails, but the attempted URL is still recorded — which is the part that matters for analysis, and it avoids hosting live malware pulled on an attacker's behalf.

Verify from a throwaway container on the same network (the Cowrie image itself is minimal and ships no shell):

```bash
docker run --rm --network honeypot alpine \
  sh -c 'timeout 5 nc -z 1.1.1.1 443; echo "exit: $?"'
```

Expect a non-zero exit from the timeout (124, or 143 when `timeout` has to kill the process). A `0` means the connection succeeded and the rules are not in effect — check them with `sudo iptables -L DOCKER-USER -n --line-numbers`.

## Verifying the honeypot

From a workstation, connect as an attacker would:

```bash
ssh root@<sensor-ip>
```

The host key will have changed if you previously used port 22 for real administration; `ssh-keygen -R <sensor-ip>` clears the stale entry. Host keys are stored per address *and* port, so this does not affect administrative access on the non-standard port.

Cowrie's default userdb accepts any password for `root` **except** `root` and `123456`, which are refused on purpose: the bots that only ever try those are trivial scanners, and turning them away keeps the recorded sessions weighted towards attackers that go on to run commands.

Then, on the sensor:

```bash
tail -f /srv/cowrie/log/cowrie.json
```

Unsolicited login attempts usually start arriving within minutes.

## Pruning captured data

The sensor is a buffer, not an archive: everything it captures is copied to the homelab within minutes. It therefore keeps 30 days and no more — not for disk space, but because it is the most exposed machine in the project and it holds both personal data and live malware.

```bash
sudo install -m 0755 prune-cowrie-data.sh /usr/local/sbin/prune-cowrie-data.sh
sudo install -m 0644 cowrie-prune.service /etc/systemd/system/
sudo install -m 0644 cowrie-prune.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-prune.timer

sudo systemctl start cowrie-prune.service    # run once by hand
journalctl -u cowrie-prune.service -n 20 --no-pager
```

Only rotated logs are touched; the file Cowrie is currently writing is left alone. The window is set with `COWRIE_RETENTION_DAYS` in the unit if 30 days is not right.

The full policy, and why each number is what it is, is in [`docs/privacy.md`](../../docs/privacy.md).

## Operations

```bash
docker compose pull && docker compose up -d   # update
docker compose restart
docker compose down
du -sh /srv/cowrie/*                          # watch disk usage
wc -l /srv/cowrie/log/cowrie.json             # events captured so far
```

Log rotation and shipping to the homelab are handled in the ingestion milestone.
