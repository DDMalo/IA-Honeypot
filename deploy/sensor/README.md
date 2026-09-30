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

```bash
sudo mkdir -p /srv/cowrie/{log,downloads,tty}
sudo chown -R 1000:1000 /srv/cowrie      # the image runs as uid 1000
docker compose up -d
docker compose logs --tail 20
```

## Egress containment

Docker inserts its own rules ahead of `ufw`, so the host's outbound policy does not apply to container traffic. The container is therefore confined at the `DOCKER-USER` chain: replies to inbound connections are allowed, new outbound connections from the honeypot network are dropped.

```bash
sudo iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
sudo iptables -I DOCKER-USER 2 -s 172.31.66.0/24 ! -d 172.31.66.0/24 -j DROP
sudo apt install -y iptables-persistent   # answer "Yes" to save current rules
sudo netfilter-persistent save
```

Consequence worth knowing: Cowrie normally *does* fetch the URLs an attacker passes to `wget` or `curl`. With egress blocked the fetch fails, but the attempted URL is still recorded — which is the part that matters for analysis, and it avoids hosting live malware pulled on an attacker's behalf.

Verify:

```bash
docker exec cowrie sh -c 'timeout 5 nc -z 1.1.1.1 443; echo $?'   # expect 124
```

## Verifying the honeypot

From a workstation, connect as an attacker would (any password is accepted by the default userdb):

```bash
ssh root@<sensor-ip>
```

A fake shell should appear. Then, on the sensor:

```bash
tail -f /srv/cowrie/log/cowrie.json
```

Unsolicited login attempts usually start arriving within minutes.

## Operations

```bash
docker compose pull && docker compose up -d   # update
docker compose restart
docker compose down
du -sh /srv/cowrie/*                          # watch disk usage
```

Log rotation and shipping to the homelab are handled in the ingestion milestone.
