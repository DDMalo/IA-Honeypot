# Sensor firewall

Two layers protect the sensor, and they are managed in different places because they solve different problems.

| Layer | Scope | Managed by |
|---|---|---|
| Hetzner cloud firewall | Inbound, before the packet reaches the instance | Provider console (`fw-sensor`) |
| `ufw` | Host inbound and outbound | `ufw` on the sensor |
| `DOCKER-USER` chain | Container traffic, which bypasses `ufw` | `honeypot-egress.service` |

## Why not iptables-persistent

On Ubuntu 26.04, `iptables-persistent` and `ufw` conflict: installing the former silently removes the latter, leaving its rules loaded in memory with no tool to manage them. This project uses `ufw` for host policy — it has its own boot-time service and a far smaller margin for error — and a systemd unit for the container rules, rather than saving a snapshot of the whole ruleset.

## Host policy

Inbound: only the honeypot ports and the administrative SSH port.

```bash
sudo ufw allow <admin-port>/tcp
sudo ufw allow 22/tcp
sudo ufw allow 23/tcp
```

Outbound: default deny, with a narrow allowlist for what the host itself needs.

```bash
sudo ufw default deny outgoing
sudo ufw allow out 53          # DNS
sudo ufw allow out 80/tcp      # package repositories
sudo ufw allow out 443/tcp     # package repositories, container images, Tailscale control plane
sudo ufw allow out 123/udp     # NTP
sudo ufw allow out 3478/udp    # Tailscale NAT traversal (STUN)
sudo ufw allow out 41641/udp   # Tailscale direct connections
sudo ufw allow out on tailscale0
sudo ufw allow in on tailscale0
```

The last two rules carry traffic that travels inside the tunnel, which is already authenticated and encrypted end to end.

## Container policy

Installed once, then applied automatically on every boot:

```bash
sudo install -m 0755 honeypot-egress.sh /usr/local/sbin/honeypot-egress.sh
sudo install -m 0644 honeypot-egress.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-egress.service
```

## Verification

Host egress — the SMTP probe must time out rather than connect:

```bash
timeout 5 nc -zv 1.1.1.1 25; echo $?     # non-zero (124, or 143 when killed)
sudo apt update                          # must still succeed
```

Container egress, from a throwaway container on the honeypot network:

```bash
docker run --rm --network honeypot alpine \
  sh -c 'timeout 5 nc -z 1.1.1.1 443; echo "exit: $?"'
```

Both checks should be repeated after every reboot, and are the first thing to look at if anything about the network setup changes.
