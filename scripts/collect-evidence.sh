#!/usr/bin/env bash
# Run on your HOST (Git Bash) from anywhere inside the repo.
# Usage: ./scripts/collect-evidence.sh <server|monitor|siem|all> [label]
#   label (optional): e.g. "before" or "after" -> saves into an evidence/<label>/ subfolder
#                     (useful for remediation validation)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---- Edit these to match your lab (or override via environment variables) ----
SIEM_IP="${SIEM_IP:-192.168.152.10}";      SIEM_USER="${SIEM_USER:-SIEM-VM}"
SERVER_IP="${SERVER_IP:-192.168.152.40}";  SERVER_USER="${SERVER_USER:-Server-VM}"
MONITOR_IP="${MONITOR_IP:-192.168.152.60}"; MONITOR_USER="${MONITOR_USER:-User-VM}"
# ------------------------------------------------------------------------------

TARGET="${1:-}"
LABEL="${2:-}"

collect() {  # name ip user gather_script dest_dir
  local name=$1 ip=$2 user=$3 script=$4 dest=$5
  [ -n "$LABEL" ] && dest="$dest/$LABEL"
  echo ">> Collecting from $name ($ip) -> $dest"
  scp -q "scripts/vm/$script" "$user@$ip:/tmp/$script"
  ssh -t "$user@$ip" "sudo bash /tmp/$script $user"
  local tmp; tmp="$(mktemp -d)"
  scp -q "$user@$ip:/tmp/evidence-$name.tar.gz" "$tmp/"
  tar -xzf "$tmp/evidence-$name.tar.gz" -C "$tmp"
  mkdir -p "$dest"
  cp -r "$tmp/evidence-$name/." "$dest/"
  ssh "$user@$ip" "rm -rf /tmp/$script /tmp/evidence-$name /tmp/evidence-$name.tar.gz"
  rm -rf "$tmp"
  echo "   Saved: $(ls "$dest" | wc -l) files in $dest"
}

case "$TARGET" in
  server)  collect linux-server    "$SERVER_IP"  "$SERVER_USER"  gather-linux-server.sh    detections/ssh-bruteforce/evidence ;;
  monitor) collect wazuh-suricata  "$MONITOR_IP" "$MONITOR_USER" gather-wazuh-suricata.sh  wazuh-suricata/evidence ;;
  siem)    collect splunk          "$SIEM_IP"    "$SIEM_USER"    gather-splunk.sh          splunk/exports ;;
  all)
    "$0" server  ${LABEL:+"$LABEL"}
    "$0" monitor ${LABEL:+"$LABEL"}
    "$0" siem    ${LABEL:+"$LABEL"}
    exit 0 ;;
  *) echo "Usage: $0 <server|monitor|siem|all> [label]"; exit 1 ;;
esac

echo
echo "Next: review the files, edit anything sensitive, then run ./scripts/check-secrets.sh"
