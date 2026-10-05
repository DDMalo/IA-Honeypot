#!/usr/bin/env bash
# Delete captured data the sensor no longer needs to hold.
#
# Everything here has already been copied to the homelab, so the sensor is a
# buffer, not an archive. Keeping it short matters for two reasons that have
# nothing to do with disk space:
#
#   * The logs contain IP addresses, which are personal data. A public machine
#     that anyone may eventually get into should hold as little of it as
#     possible.
#   * The downloads directory contains live malware uploaded by attackers.
#     Its hash is kept in the database forever; the file itself does not need
#     to be.
#
# Cowrie rotates cowrie.json daily into cowrie.json.YYYY-MM-DD, so this prunes
# the rotated copies and leaves the file currently being written alone.
set -euo pipefail

LOG_DIR="${COWRIE_LOG_DIR:-/srv/cowrie/log}"
DOWNLOAD_DIR="${COWRIE_DOWNLOAD_DIR:-/srv/cowrie/downloads}"
TTY_DIR="${COWRIE_TTY_DIR:-/srv/cowrie/tty}"
DAYS="${COWRIE_RETENTION_DAYS:-30}"

prune() {
    local directory="$1" pattern="$2" label="$3"
    [[ -d "$directory" ]] || return 0

    local count
    count=$(find "$directory" -type f -name "$pattern" -mtime "+$DAYS" | wc -l)
    if (( count > 0 )); then
        find "$directory" -type f -name "$pattern" -mtime "+$DAYS" -delete
    fi
    echo "$label: removed $count files older than $DAYS days"
}

# Rotated logs only: cowrie.json itself is open for writing.
prune "$LOG_DIR" 'cowrie.json.*' "rotated logs"
prune "$LOG_DIR" 'cowrie.log.*' "rotated text logs"
prune "$DOWNLOAD_DIR" '*' "malware samples"
prune "$TTY_DIR" '*' "session recordings"

echo "Remaining: $(du -sh "$(dirname "$LOG_DIR")" 2>/dev/null | cut -f1)"
