#!/usr/bin/env bash
# Runs ON the Wazuh/Suricata VM (User-VM, 192.168.152.60).
# Called by collect-evidence.sh, or run manually:
#   sudo ATTACKER_IP=192.168.152.20 bash gather-wazuh-suricata.sh <your_username>
#
# Pulls evidence for BOTH detections that reference this VM:
#   - detections/ssh-bruteforce/README.md  (section: 4. Suricata, 5. Wazuh)
#   - detections/nmap-recon/README.md      (section: 2. Suricata, 3. Wazuh)
# Split into subfolders so each copies straight into its matching detection folder.
set -uo pipefail
OWNER="${1:-${SUDO_USER:-root}}"
ATTACKER_IP="${ATTACKER_IP:-192.168.152.20}"   # Kali
SERVER_IP="192.168.152.40"                      # Server-VM (the attacked host)
NAME=wazuh-suricata
OUT="/tmp/evidence-$NAME"
rm -rf "$OUT"; mkdir -p "$OUT/ssh-bruteforce" "$OUT/nmap-recon"

FAST=/var/log/suricata/fast.log
EVE=/var/log/suricata/eve.json
WAZUH_ALERTS=/var/ossec/logs/alerts/alerts.json

{
  echo "Host: $(hostname)"
  echo "IP: 192.168.152.60 (User-VM)"
  echo "Collected (UTC): $(date -u +%FT%TZ)"
  command -v suricata >/dev/null && suricata -V 2>&1
  [ -x /var/ossec/bin/wazuh-control ] && /var/ossec/bin/wazuh-control info 2>&1
} > "$OUT/collection-info.txt"

# ---------------- Wazuh agent status (shared) ----------------
[ -x /var/ossec/bin/agent_control ] && /var/ossec/bin/agent_control -l > "$OUT/wazuh-agents.txt" 2>&1
grep -B2 -A3 'eve.json' /var/ossec/etc/ossec.conf > "$OUT/wazuh-suricata-integration-config.txt" 2>/dev/null \
  || echo "No eve.json block found in ossec.conf" > "$OUT/wazuh-suricata-integration-config.txt"

# ---------------- SSH brute-force evidence (-> detections/ssh-bruteforce/) ----------------
if [ -f "$EVE" ]; then
  grep '"event_type":"ssh"' "$EVE" 2>/dev/null | tail -n 10 > "$OUT/ssh-bruteforce/suricata-ssh-session-metadata.json"
  [ -s "$OUT/ssh-bruteforce/suricata-ssh-session-metadata.json" ] || echo "No SSH protocol events logged by Suricata — confirm the ssh app-layer parser is enabled in suricata.yaml." > "$OUT/ssh-bruteforce/suricata-ssh-session-metadata.json"
fi

if [ -f "$WAZUH_ALERTS" ] && command -v jq >/dev/null 2>&1; then
  jq -c --arg ip "$ATTACKER_IP" 'select(.rule.description|test("ssh|authentication";"i")) | {time:.timestamp, rule:.rule.id, level:.rule.level, desc:.rule.description, agent:.agent.name, srcip:.data.srcip}' \
    "$WAZUH_ALERTS" 2>/dev/null | tail -n 20 > "$OUT/ssh-bruteforce/wazuh-ssh-alerts-sample.json"
  jq -r 'select(.rule.description|test("ssh|authentication";"i")) | [.rule.id, .rule.level, .rule.description] | @tsv' "$WAZUH_ALERTS" 2>/dev/null \
    | sort | uniq -c | sort -rn > "$OUT/ssh-bruteforce/wazuh-alerts-by-rule.txt"
else
  echo "alerts.json not found or jq not installed (sudo apt install jq)" > "$OUT/ssh-bruteforce/wazuh-alerts-by-rule.txt"
fi

# ---------------- Nmap-recon evidence (-> detections/nmap-recon/) ----------------
if [ -f "$FAST" ]; then
  tail -n 50 "$FAST" > "$OUT/nmap-recon/suricata-fast-log-sample.txt"
  grep -oP '\[\*\*\] \[[0-9:]+\] \K.*?(?= \[\*\*\])' "$FAST" | sort | uniq -c | sort -rn | head -20 > "$OUT/nmap-recon/suricata-alerts-by-signature.txt"
  echo "Total alerts in fast.log: $(wc -l < "$FAST")" >> "$OUT/nmap-recon/suricata-alerts-by-signature.txt"
else
  echo "fast.log not found at $FAST" > "$OUT/nmap-recon/suricata-fast-log-sample.txt"
fi

if [ -f "$EVE" ]; then
  # README Filter B (HTTP) -> real HTTP transactions logged by Suricata, alert or not
  grep '"event_type":"http"' "$EVE" 2>/dev/null | tail -n 10 > "$OUT/nmap-recon/suricata-eve-http-sample.json"
  [ -s "$OUT/nmap-recon/suricata-eve-http-sample.json" ] || echo "No HTTP events logged — confirm Apache is reachable on .40:80 during the scan." > "$OUT/nmap-recon/suricata-eve-http-sample.json"
  # Scan/portscan alerts specifically
  grep '"event_type":"alert"' "$EVE" 2>/dev/null | tail -n 15 > "$OUT/nmap-recon/suricata-eve-alert-sample.json"
fi
grep -E '^\s*-?\s*interface:' /etc/suricata/suricata.yaml 2>/dev/null | head -n 5 > "$OUT/nmap-recon/suricata-interface.txt"
command -v suricata-update >/dev/null && suricata-update list-enabled-sources > "$OUT/nmap-recon/suricata-enabled-rule-sources.txt" 2>&1

if [ -f "$WAZUH_ALERTS" ] && command -v jq >/dev/null 2>&1; then
  jq -r 'select(.rule.groups[]? == "suricata" or (.rule.description|test("scan|nmap";"i"))) | [.rule.id, .rule.level, .rule.description] | @tsv' "$WAZUH_ALERTS" 2>/dev/null \
    | sort | uniq -c | sort -rn > "$OUT/nmap-recon/wazuh-scan-alerts-by-rule.txt"
  [ -s "$OUT/nmap-recon/wazuh-scan-alerts-by-rule.txt" ] || echo "No scan-related Wazuh alerts found in this window." > "$OUT/nmap-recon/wazuh-scan-alerts-by-rule.txt"
fi

tar -czf "/tmp/evidence-$NAME.tar.gz" -C /tmp "evidence-$NAME"
chown "$OWNER" "/tmp/evidence-$NAME.tar.gz"
chmod -R a+rX "$OUT"
echo "Done: /tmp/evidence-$NAME.tar.gz"
echo "Split copy: evidence-$NAME/ssh-bruteforce/* -> detections/ssh-bruteforce/evidence/"
echo "            evidence-$NAME/nmap-recon/*     -> detections/nmap-recon/evidence/"
