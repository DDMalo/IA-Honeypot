#!/usr/bin/env bash
# Pull Cowrie's logs from the sensor to the homelab.
#
# The homelab pulls; the sensor never pushes. That direction is the whole point:
# a compromised sensor must hold no credential that reaches into the home
# network. It also means this runs on the machine that cares about the data, so
# a sensor outage simply delays a sync instead of losing events.
#
# rsync transfers only what changed, and running it again is harmless, so a
# missed run is corrected by the next one. No state is kept between runs.
#
# Configuration lives in /etc/default/cowrie-log-sync (see README.md).
set -euo pipefail

SENSOR_HOST="${SENSOR_HOST:?SENSOR_HOST is not set}"
SENSOR_USER="${SENSOR_USER:-david}"
SENSOR_PORT="${SENSOR_PORT:-61000}"
SENSOR_LOG_DIR="${SENSOR_LOG_DIR:-/srv/cowrie/log/}"
DEST_DIR="${DEST_DIR:-/srv/honeypot/raw}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"

mkdir -p "$DEST_DIR"

# Only one sync at a time: a slow transfer must not be overtaken by the next
# timer tick, which would have two rsyncs writing the same files.
exec 9>"${DEST_DIR}/.sync.lock"
if ! flock -n 9; then
    echo "A sync is already running; skipping this run."
    exit 0
fi

ssh_cmd=(ssh -p "$SENSOR_PORT" -i "$SSH_KEY"
         -o BatchMode=yes
         -o ConnectTimeout=15
         -o StrictHostKeyChecking=accept-new)

start=$(date +%s)

# --archive preserves timestamps, which is what lets rsync skip unchanged files.
# --partial keeps a half-transferred file so a dropped connection resumes
# instead of starting over; honeypot logs grow and home links are not reliable.
rsync \
    --archive \
    --compress \
    --partial \
    --human-readable \
    --stats \
    --exclude='.sync.lock' \
    --rsh="${ssh_cmd[*]}" \
    "${SENSOR_USER}@${SENSOR_HOST}:${SENSOR_LOG_DIR}" \
    "${DEST_DIR}/"

elapsed=$(( $(date +%s) - start ))

# Rotated copies pulled from the sensor are kept longer here than there, but
# not forever: they hold IP addresses, and the database is the thing that is
# meant to last.
RAW_RETENTION_DAYS="${RAW_RETENTION_DAYS:-90}"
removed=$(find "$DEST_DIR" -type f -name 'cowrie.json.*' -mtime "+$RAW_RETENTION_DAYS" | wc -l)
if (( removed > 0 )); then
    find "$DEST_DIR" -type f -name 'cowrie.json.*' -mtime "+$RAW_RETENTION_DAYS" -delete
    echo "Pruned $removed raw logs older than $RAW_RETENTION_DAYS days"
fi

if [[ -f "${DEST_DIR}/cowrie.json" ]]; then
    events=$(wc -l < "${DEST_DIR}/cowrie.json")
    echo "Sync finished in ${elapsed}s; ${events} events in cowrie.json"
else
    echo "Sync finished in ${elapsed}s; no cowrie.json yet"
fi
