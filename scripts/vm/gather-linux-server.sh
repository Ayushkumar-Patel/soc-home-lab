#!/usr/bin/env bash
# Runs ON the Linux server VM (Server-VM, 192.168.152.40).
# Called by collect-evidence.sh, or run manually:
#   sudo ATTACKER_IP=192.168.152.20 bash gather-linux-server.sh <your_username>
#
# Output filenames match what detections/ssh-bruteforce/README.md references directly —
# copy this folder's contents into detections/ssh-bruteforce/evidence/ as-is.
set -uo pipefail
OWNER="${1:-${SUDO_USER:-root}}"
ATTACKER_IP="${ATTACKER_IP:-192.168.152.20}"   # Kali
NAME=linux-server
OUT="/tmp/evidence-$NAME"
rm -rf "$OUT"; mkdir -p "$OUT"

authlog() { cat /var/log/auth.log.1 /var/log/auth.log 2>/dev/null; }

{
  echo "Host: $(hostname)"
  echo "IP: 192.168.152.40 (Server-VM)"
  echo "Collected (UTC): $(date -u +%FT%TZ)"
  echo "Kernel: $(uname -sr)"
  echo "OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
} > "$OUT/collection-info.txt"

# detections/ssh-bruteforce/README.md -> "See evidence/auth-log-failed-sample.txt"
authlog | grep "Failed password" | tail -n 20 > "$OUT/auth-log-failed-sample.txt"

# detections/ssh-bruteforce/README.md Findings -> "N failed login attempts in M minutes"
{
  echo "Total 'Failed password' lines: $(authlog | grep -c 'Failed password')"
  echo "  ...from attacker ($ATTACKER_IP): $(authlog | grep 'Failed password' | grep -c "$ATTACKER_IP")"
  echo "First failed login: $(authlog | grep 'Failed password' | head -n 1 | cut -c1-15)"
  echo "Last failed login:  $(authlog | grep 'Failed password' | tail -n 1 | cut -c1-15)"
} > "$OUT/failed-login-summary.txt"

authlog | grep "Failed password" | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn > "$OUT/failed-by-source-ip.txt"
authlog | grep "Failed password" | sed -E 's/.*Failed password for (invalid user )?([^ ]+) from.*/\2/' | sort | uniq -c | sort -rn | head -20 > "$OUT/failed-by-username.txt"

# Impact assessment section in the incident report needs this directly
authlog | grep "Accepted" | tail -n 20 > "$OUT/accepted-logins.txt"
[ -s "$OUT/accepted-logins.txt" ] || echo "No 'Accepted' lines found — no successful authentication observed." > "$OUT/accepted-logins.txt"

# SSH hardening state — compare before/after remediation (sshd_config section)
sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|logingracetime)' > "$OUT/sshd-effective-config.txt"

if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd > "$OUT/fail2ban-status.txt" 2>&1
else
  echo "fail2ban not installed" > "$OUT/fail2ban-status.txt"
fi

tar -czf "/tmp/evidence-$NAME.tar.gz" -C /tmp "evidence-$NAME"
chown "$OWNER" "/tmp/evidence-$NAME.tar.gz"
chmod -R a+rX "$OUT"
echo "Done: /tmp/evidence-$NAME.tar.gz"
echo "Copy into: detections/ssh-bruteforce/evidence/"
