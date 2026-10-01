# Sensor ↔ homelab tunnel

The sensor collects attack data on a public VPS; the homelab analyses it at home. They need a private path between them, and the constraints are awkward on both ends: the homelab sits behind a domestic router with no port forwarding, and the sensor denies outbound traffic by default.

All addresses in this document are placeholders. Replace `<sensor-tailnet-ip>` and `<homelab-tailnet-ip>` with your own, and keep the real ones out of the repository.

## Why a mesh VPN rather than port forwarding

Opening a port on the home router would expose the homelab to the internet — the one thing this project is built to avoid. A WireGuard-based mesh VPN inverts the direction: both machines make *outbound* connections to a coordination service, which introduces them to each other; traffic then flows directly between them, encrypted end to end. Nothing is ever exposed inbound at home.

This deployment uses [Tailscale](https://tailscale.com), which wraps WireGuard with key distribution and NAT traversal. Plain WireGuard would also work and is a worthwhile exercise, but it requires at least one endpoint with a stable, reachable address — which is exactly what the home side does not have.

| Property | Value |
|---|---|
| Transport | WireGuard (via Tailscale) |
| Addressing | CGNAT range `100.64.0.0/10`, one stable address per machine |
| Inbound ports opened at home | none |
| Authentication | per-device keys, issued on login, revocable from the admin console |

## Installation

On both machines:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

`tailscale up` prints a URL; opening it and signing in authorises that machine. Verify from either end:

```bash
tailscale status
```

If the installer fails with `Could not get lock /var/lib/dpkg/lock-frontend`, unattended upgrades are mid-run. Wait and re-run `sudo apt install -y tailscale`; the repository has already been added by then.

## Firewall rules

The homelab allows outbound traffic by default, so it needs only a rule to accept traffic arriving through the tunnel:

```bash
sudo ufw allow in on tailscale0
```

The sensor denies outbound by default, so it needs the ports Tailscale uses to establish a connection, plus the tunnel interface itself:

```bash
sudo ufw allow out 3478/udp    # NAT traversal (STUN)
sudo ufw allow out 41641/udp   # direct peer connections
sudo ufw allow out on tailscale0
sudo ufw allow in on tailscale0
```

Control-plane traffic and the relay fallback both use 443/tcp, which the sensor already allows for package repositories.

Allowing everything on `tailscale0` is deliberate: that traffic is already authenticated and encrypted at the WireGuard layer, and only devices in the tailnet can produce it. The honeypot container's network is a separate concern and remains confined (see `deploy/sensor/firewall.md`).

## Verification

From the homelab, reach the sensor's administrative SSH over the tunnel:

```bash
ssh -p <admin-port> <user>@<sensor-tailnet-ip>
```

A hang rather than a refusal usually means the sensor is missing `ufw allow in on tailscale0`.

## Operational notes

- **Disable key expiry** on both machines in the admin console. Device keys otherwise expire after a few months and the tunnel drops — which, for a sensor abroad and a laptop at home, means losing the pipeline at the worst possible moment.
- Tailscale starts at boot on both machines; no action is needed after a reboot or a power cut.
- A device can be revoked instantly from the admin console, which is the fastest way to isolate the homelab if the sensor is ever suspected of compromise.
- The tunnel carries log shipping from the sensor to the homelab. The homelab initiates the connection and pulls; the sensor never needs to reach into the home network.
