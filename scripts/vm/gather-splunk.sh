#!/usr/bin/env bash
# Runs ON the Splunk VM (SIEM-VM, 192.168.152.10).
# Exports saved searches/alerts and dashboards referenced by splunk/README.md
# and the SPL query in splunk/ssh-bruteforce.spl. Does NOT copy license files,
# passwd, or auth settings — only config that documents what you built.
#   sudo bash gather-splunk.sh <your_username>
set -uo pipefail
OWNER="${1:-${SUDO_USER:-root}}"
NAME=splunk
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
OUT="/tmp/evidence-$NAME"
rm -rf "$OUT"; mkdir -p "$OUT/saved-searches" "$OUT/dashboards"

{
  echo "Host: $(hostname)"
  echo "IP: 192.168.152.10 (SIEM-VM)"
  echo "Collected (UTC): $(date -u +%FT%TZ)"
  cat "$SPLUNK_HOME/etc/splunk.version" 2>/dev/null
} > "$OUT/collection-info.txt"

find "$SPLUNK_HOME/etc/apps" "$SPLUNK_HOME/etc/users" -name savedsearches.conf 2>/dev/null | while read -r f; do
  flat="$(echo "$f" | sed "s|$SPLUNK_HOME/etc/||; s|/|_|g")"
  cp "$f" "$OUT/saved-searches/$flat"
done

find "$SPLUNK_HOME/etc/apps" "$SPLUNK_HOME/etc/users" -path '*data/ui/views/*.xml' 2>/dev/null | while read -r f; do
  flat="$(echo "$f" | sed "s|$SPLUNK_HOME/etc/||; s|/|_|g")"
  cp "$f" "$OUT/dashboards/$flat"
done

cp "$SPLUNK_HOME/etc/system/local/inputs.conf" "$OUT/inputs.conf" 2>/dev/null
cp "$SPLUNK_HOME/etc/system/local/indexes.conf" "$OUT/indexes.conf" 2>/dev/null
ls "$SPLUNK_HOME/var/lib/splunk" > "$OUT/indexes-on-disk.txt" 2>/dev/null

# Confirm the forwarder from Server-VM (.40) is actually connected before trusting any search result
echo "Forwarders currently connected (port 9997):" > "$OUT/forwarder-connections.txt"
sudo netstat -tnp 2>/dev/null | grep ':9997' >> "$OUT/forwarder-connections.txt" || echo "(none found — check Server-VM's forward-server config)" >> "$OUT/forwarder-connections.txt"

# Strip any password-like lines that slipped in
grep -rlEi 'password|pass4SymmKey|sslPassword' "$OUT" 2>/dev/null | while read -r f; do
  sed -i -E 's/^(.*(password|pass4SymmKey|sslPassword).*=).*/\1 REDACTED/I' "$f"
done

tar -czf "/tmp/evidence-$NAME.tar.gz" -C /tmp "evidence-$NAME"
chown "$OWNER" "/tmp/evidence-$NAME.tar.gz"
chmod -R a+rX "$OUT"
echo "Done: /tmp/evidence-$NAME.tar.gz"
echo "Copy into: splunk/exports/"
echo ""
echo "NOTE: this script exports CONFIG, not search RESULTS. For the actual numbers your"
echo "README needs (alert fire time, matching event count), run splunk/ssh-bruteforce.spl"
echo "in the Splunk UI after the attack and paste the result table into"
echo "detections/ssh-bruteforce/README.md yourself — Splunk search results aren't on disk"
echo "as a flat file the way logs are."
