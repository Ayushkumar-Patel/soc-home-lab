#!/usr/bin/env bash
# Runs ON the Wazuh/Suricata VM (.60). Called by collect-evidence.sh, or run manually:
#   sudo bash gather-wazuh-suricata.sh <your_username>
set -uo pipefail
OWNER="${1:-${SUDO_USER:-root}}"
NAME=wazuh-suricata
OUT="/tmp/evidence-$NAME"
rm -rf "$OUT"; mkdir -p "$OUT"

FAST=/var/log/suricata/fast.log
EVE=/var/log/suricata/eve.json
WAZUH_ALERTS=/var/ossec/logs/alerts/alerts.json

{
  echo "Host: $(hostname)"
  echo "Collected (UTC): $(date -u +%FT%TZ)"
  command -v suricata >/dev/null && suricata -V 2>&1
  [ -x /var/ossec/bin/wazuh-control ] && /var/ossec/bin/wazuh-control info 2>&1
} > "$OUT/collection-info.txt"

# ---- Suricata ----
if [ -f "$FAST" ]; then
  tail -n 50 "$FAST" > "$OUT/suricata-fast-log-sample.txt"
  # Alert counts by signature
  grep -oP '\[\*\*\] \[[0-9:]+\] \K.*?(?= \[\*\*\])' "$FAST" | sort | uniq -c | sort -rn | head -20 > "$OUT/suricata-alerts-by-signature.txt"
  echo "Total alerts in fast.log: $(wc -l < "$FAST")" >> "$OUT/suricata-alerts-by-signature.txt"
else
  echo "fast.log not found at $FAST" > "$OUT/suricata-fast-log-sample.txt"
fi
[ -f "$EVE" ] && grep '"event_type":"alert"' "$EVE" | tail -n 10 > "$OUT/suricata-eve-alert-sample.json"
grep -E '^\s*-?\s*interface:' /etc/suricata/suricata.yaml 2>/dev/null | head -n 5 > "$OUT/suricata-interface.txt"
command -v suricata-update >/dev/null && suricata-update list-enabled-sources > "$OUT/suricata-enabled-rule-sources.txt" 2>&1

# ---- Wazuh ----
[ -x /var/ossec/bin/agent_control ] && /var/ossec/bin/agent_control -l > "$OUT/wazuh-agents.txt" 2>&1
grep -B2 -A3 'eve.json' /var/ossec/etc/ossec.conf > "$OUT/wazuh-suricata-integration-config.txt" 2>/dev/null \
  || echo "No eve.json block found in ossec.conf" > "$OUT/wazuh-suricata-integration-config.txt"

if [ -f "$WAZUH_ALERTS" ]; then
  if command -v jq >/dev/null 2>&1; then
    # Count of alerts by rule ID / level / description (record these in your README)
    jq -r '[.rule.id, .rule.level, .rule.description] | @tsv' "$WAZUH_ALERTS" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -30 > "$OUT/wazuh-alerts-by-rule.txt"
    # Recent SSH-related alerts with source IP
    jq -c 'select(.rule.description|test("ssh|authentication";"i")) | {time:.timestamp, rule:.rule.id, level:.rule.level, desc:.rule.description, agent:.agent.name, srcip:.data.srcip}' \
      "$WAZUH_ALERTS" 2>/dev/null | tail -n 20 > "$OUT/wazuh-ssh-alerts-sample.json"
  else
    echo "jq not installed. Run: sudo apt install jq   then re-run." > "$OUT/wazuh-alerts-by-rule.txt"
  fi
else
  echo "alerts.json not found at $WAZUH_ALERTS" > "$OUT/wazuh-alerts-by-rule.txt"
fi

tar -czf "/tmp/evidence-$NAME.tar.gz" -C /tmp "evidence-$NAME"
chown "$OWNER" "/tmp/evidence-$NAME.tar.gz"
chmod -R a+rX "$OUT"
echo "Done: /tmp/evidence-$NAME.tar.gz"
