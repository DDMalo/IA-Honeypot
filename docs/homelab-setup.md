# Homelab setup

The homelab is the machine that receives the honeypot logs, stores them and runs the analysis pipeline. It is a repurposed laptop (Intel i3, 8 GB RAM) running Ubuntu Server, kept on a private network and never exposed to the internet.

All addresses in this document are placeholders. Replace `<homelab-ip>` and `<user>` with your own values, and never commit real internal addresses or credentials.

## Hardware and OS

| Item | Value |
|---|---|
| Machine | Repurposed laptop, Intel i3, 8 GB RAM |
| OS | Ubuntu Server 26.04 LTS (no desktop environment) |
| Hostname | `homelab` |
| Network | Wi-Fi, static DHCP reservation on the router |
| Access | SSH with public key authentication only |

A desktop environment is deliberately not installed: the machine is administered over SSH, and the saved memory and CPU cycles go to the containers instead.

## Installation notes

The system was installed from the official Ubuntu Server ISO with:

- Full-disk layout using the installer defaults (LVM).
- OpenSSH server installed during setup.
- The SSH public key imported from GitHub during setup, so password login was never needed.
- No additional snaps; Docker is installed from its official repository instead.

If Wi-Fi is used, the connection is defined in a netplan file readable only by root:

```yaml
# /etc/netplan/60-wifi.yaml  (chmod 600)
network:
  version: 2
  wifis:
    <interface>:
      dhcp4: true
      access-points:
        "<ssid>":
          password: "<password>"
```

## Hardening

### Automatic security updates

Unattended upgrades are enabled so security patches are applied without manual intervention:

```bash
systemctl status unattended-upgrades
```

### SSH

Password and keyboard-interactive authentication are disabled, and root login is not allowed:

```conf
# /etc/ssh/sshd_config.d/01-hardening.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
```

The file is prefixed with `01` on purpose: OpenSSH reads drop-in files in alphabetical order and keeps the first value it finds for each option, so this configuration takes precedence over any defaults shipped by the installer.

Changes are validated before restarting the service, and a second session is always opened to confirm access before closing the current one:

```bash
sudo sshd -t && sudo systemctl restart ssh
```

### Firewall

`ufw` is enabled with SSH as the only allowed inbound service:

```bash
sudo ufw allow OpenSSH
sudo ufw enable
```

> **Note:** published Docker ports bypass `ufw` rules. Services in this project are therefore bound to loopback or to the private tunnel interface rather than to `0.0.0.0`, so the firewall is not the only thing keeping them private.

### Laptop-specific settings

The lid is ignored so the machine keeps running while closed:

```conf
# /etc/systemd/logind.conf.d/lid.conf
[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
```

The laptop stays plugged in; its battery acts as a small UPS during short power cuts.

## Docker

Docker Engine is installed from Docker's official apt repository (the distribution packages are not used, and conflicting `docker.io` / `docker-compose` packages are removed first):

```bash
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verification:

```bash
sudo docker run hello-world
docker compose version
```

The administrative user is added to the `docker` group for convenience. This is equivalent to granting root access on the host, which is acceptable for a single-user homelab but would not be in a shared environment.

## What runs here

Nothing yet beyond Docker itself. Upcoming versions will add, as containers defined in `deploy/homelab/`:

- PostgreSQL for sessions and enrichment data
- The ingestion worker
- Ollama for local model inference
- Grafana for dashboards

## Operational notes

- The homelab has no inbound access from the internet; it reaches the sensor through an outbound tunnel (see the sensor documentation once it is added).
- Reboots are expected after kernel updates; containers are configured with restart policies so services come back automatically.
- Useful checks: `systemctl status docker`, `docker ps`, `sudo ufw status`, `journalctl -xe`.
