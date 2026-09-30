# Sensor setup

The sensor is the internet-facing machine that runs the honeypot. It is deliberately exposed so that attackers can reach it, and just as deliberately constrained so that it cannot be used against anyone else.

All addresses, ports and usernames in this document are placeholders. Replace `<sensor-ip>`, `<admin-port>` and `<user>` with your own values, and never commit the real ones.

## Why a dedicated VPS

The sensor is **never** run on a home network. A honeypot invites unauthenticated strangers to interact with a machine; if that machine sits on the same network as personal devices, a container escape or a misconfiguration puts those devices at risk. A cheap VPS from a provider that permits security research isolates the experiment from everything that matters.

| Item | Value |
|---|---|
| Provider | Hetzner Cloud |
| Plan | Smallest shared-vCPU instance |
| OS | Ubuntu 26.04 LTS |
| Hostname | `sensor-01` |
| Location | Helsinki, Finland |
| Access | SSH, public key only, on a non-standard port |

The provider's acceptable use policy permits defensive security research; the restrictions below are what keep this deployment inside it.

## Port layout

Port 22 belongs to the honeypot, not to the administrator. Legitimate access moves elsewhere, which also means every authentication attempt on port 22 is unambiguously hostile — nothing legitimate ever touches it.

| Port | Purpose |
|---|---|
| 22/tcp | Honeypot (SSH emulation) |
| 23/tcp | Honeypot (Telnet emulation) |
| `<admin-port>`/tcp | Real SSH administration |

## Hardening

### Administrative user

The provider's default access is as `root`. An unprivileged user is created, added to `sudo`, and given the SSH key; root login is then disabled.

```bash
adduser <user>
usermod -aG sudo <user>
rsync --archive --chown=<user>:<user> /root/.ssh /home/<user>
```

Access as the new user is verified in a second session **before** root login is disabled.

### SSH

```conf
# /etc/ssh/sshd_config.d/01-hardening.conf
Port <admin-port>
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
```

On Ubuntu with socket activation, `sshd_config` alone does not change the listening port: the socket unit decides it, and the default listens on port 22 only. A drop-in overrides it, and both address families must be listed explicitly or the service ends up reachable over IPv6 only:

```conf
# /etc/systemd/system/ssh.socket.d/listen.conf
[Socket]
ListenStream=
ListenStream=0.0.0.0:<admin-port>
ListenStream=[::]:<admin-port>
BindIPv6Only=ipv6-only
```

The empty `ListenStream=` clears the inherited default before the new values are appended.

```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo ss -tlnp | grep <admin-port>   # expect both 0.0.0.0 and [::]
```

Every SSH change is verified from a **second** session before the first one is closed.

### Automatic security updates

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Inbound filtering

Two layers, deliberately: the provider's cloud firewall drops unwanted traffic before it reaches the instance, and the host firewall enforces the same policy locally in case the cloud rules are ever changed or detached.

Cloud firewall (`fw-sensor`), inbound TCP from any address: `22`, `23`, `<admin-port>`. Everything else is dropped.

Host firewall:

```bash
sudo ufw allow <admin-port>/tcp
sudo ufw allow 22/tcp
sudo ufw allow 23/tcp
sudo ufw enable
```

### Outbound filtering

This is the single most important control in the project. An attacker who believes they have a shell must not be able to reach anyone else: no spam, no scanning, no relaying, no participation in a botnet. Default-deny egress, with a narrow allowlist for what the host itself needs:

```bash
sudo ufw default deny outgoing
sudo ufw allow out 53          # DNS
sudo ufw allow out 80/tcp      # package repositories
sudo ufw allow out 443/tcp     # package repositories, container images
sudo ufw allow out 123/udp     # NTP
sudo ufw reload
```

Verification — the SMTP probe must time out rather than connect or be refused:

```bash
sudo apt update                          # must succeed
ping -c 2 1.1.1.1                        # must fail (ICMP is not allowed)
timeout 5 nc -zv 1.1.1.1 25; echo $?     # must print 124 (timeout)
```

> **Pending:** Docker publishes container ports and inserts its own rules ahead of `ufw`, so container traffic bypasses the policy above. Egress restrictions for the honeypot containers are handled when the honeypot is deployed, and are documented there.

## Responsible operation

- Inbound attack traffic is expected and is the point of the project; outbound traffic to third parties is not, and is blocked.
- Captured samples are never executed and never republished; only their hashes leave the machine.
- Abuse reports are answered promptly, explaining that the host is a research honeypot with egress blocked, and offering the relevant logs.
- Captured data may contain personal data such as IP addresses; retention and publication rules are documented separately.

## Operational notes

- Reboots are expected after kernel updates. Confirm after every reboot that SSH still answers on `<admin-port>`.
- If outbound rules break something, `sudo ufw default allow outgoing && sudo ufw reload` restores the previous behaviour while the cause is investigated.
- Useful checks: `sudo ufw status verbose`, `sudo ss -tlnp`, `journalctl -u ssh`.
