#!/usr/bin/env bash
# Runs ON the Splunk VM (.10). Exports saved searches/alerts, dashboards and input configs.
# Does NOT copy license files, passwd, or auth settings.
#   sudo bash gather-splunk.sh <your_username>
set -uo pipefail
OWNER="${1:-${SUDO_USER:-root}}"
NAME=splunk
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
OUT="/tmp/evidence-$NAME"
rm -rf "$OUT"; mkdir -p "$OUT/saved-searches" "$OUT/dashboards"

{
  echo "Host: $(hostname)"
  echo "Collected (UTC): $(date -u +%FT%TZ)"
  cat "$SPLUNK_HOME/etc/splunk.version" 2>/dev/null
} > "$OUT/collection-info.txt"

# Saved searches and alerts (app-level and user-level)
find "$SPLUNK_HOME/etc/apps" "$SPLUNK_HOME/etc/users" -name savedsearches.conf 2>/dev/null | while read -r f; do
  flat="$(echo "$f" | sed "s|$SPLUNK_HOME/etc/||; s|/|_|g")"
  cp "$f" "$OUT/saved-searches/$flat"
done

# Dashboards (Simple XML)
find "$SPLUNK_HOME/etc/apps" "$SPLUNK_HOME/etc/users" -path '*data/ui/views/*.xml' 2>/dev/null | while read -r f; do
  flat="$(echo "$f" | sed "s|$SPLUNK_HOME/etc/||; s|/|_|g")"
  cp "$f" "$OUT/dashboards/$flat"
done

# Data inputs and receiving config (no credentials in these)
cp "$SPLUNK_HOME/etc/system/local/inputs.conf" "$OUT/inputs.conf" 2>/dev/null
cp "$SPLUNK_HOME/etc/system/local/indexes.conf" "$OUT/indexes.conf" 2>/dev/null
ls "$SPLUNK_HOME/var/lib/splunk" > "$OUT/indexes-on-disk.txt" 2>/dev/null

# Safety: strip any password-like lines that slipped in
grep -rlEi 'password|pass4SymmKey|sslPassword' "$OUT" 2>/dev/null | while read -r f; do
  sed -i -E 's/^(.*(password|pass4SymmKey|sslPassword).*=).*/\1 REDACTED/I' "$f"
done

tar -czf "/tmp/evidence-$NAME.tar.gz" -C /tmp "evidence-$NAME"
chown "$OWNER" "/tmp/evidence-$NAME.tar.gz"
chmod -R a+rX "$OUT"
echo "Done: /tmp/evidence-$NAME.tar.gz"
