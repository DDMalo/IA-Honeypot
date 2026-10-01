#!/usr/bin/env bash
# Confine the honeypot container network.
#
# Docker inserts its own rules ahead of ufw, so the host's outbound policy does
# not apply to container traffic. These rules live in the DOCKER-USER chain,
# which Docker creates at startup and never flushes.
#
# Replies to inbound connections are allowed; new outbound connections from the
# honeypot network are dropped. An attacker who believes they have a shell
# cannot reach anyone else.
#
# Applied by honeypot-egress.service, after docker.service, on every boot.
set -euo pipefail

NET="${HONEYPOT_NET:-172.31.66.0/24}"

# Wait for Docker to create the chain (it does so as it starts).
for _ in $(seq 1 30); do
    if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
    echo "DOCKER-USER chain not present; is Docker running?" >&2
    exit 1
fi

# -C tests for an existing identical rule, so re-running changes nothing.
add_rule() {
    if ! iptables -C DOCKER-USER "${@:2}" 2>/dev/null; then
        iptables -I DOCKER-USER "$1" "${@:2}"
    fi
}

add_rule 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
add_rule 2 -s "$NET" ! -d "$NET" -j DROP

echo "Honeypot egress rules applied for $NET"
