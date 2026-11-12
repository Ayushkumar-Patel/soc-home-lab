#!/usr/bin/env bash
# Runs ON the Linux server VM (.40). Called by collect-evidence.sh, or run manually:
#   sudo bash gather-linux-server.sh <your_username>
set -uo pipefail
OWNER="${1:-${SUDO_USER:-root}}"
NAME=linux-server
OUT="/tmp/evidence-$NAME"
rm -rf "$OUT"; mkdir -p "$OUT"

authlog() { cat /var/log/auth.log.1 /var/log/auth.log 2>/dev/null; }

{
  echo "Host: $(hostname)"
  echo "Collected (UTC): $(date -u +%FT%TZ)"
  echo "Kernel: $(uname -sr)"
  echo "OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
} > "$OUT/collection-info.txt"

# 1. Last 20 failed SSH logins
authlog | grep "Failed password" | tail -n 20 > "$OUT/auth-log-failed-sample.txt"

# 2. Totals and time window
{
  echo "Total 'Failed password' lines: $(authlog | grep -c 'Failed password')"
  echo "First failed login: $(authlog | grep 'Failed password' | head -n 1 | cut -c1-15)"
  echo "Last failed login:  $(authlog | grep 'Failed password' | tail -n 1 | cut -c1-15)"
} > "$OUT/failed-login-summary.txt"

# 3. Failed attempts per source IP and per username
authlog | grep "Failed password" | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn > "$OUT/failed-by-source-ip.txt"
authlog | grep "Failed password" | sed -E 's/.*Failed password for (invalid user )?([^ ]+) from.*/\2/' | sort | uniq -c | sort -rn | head -20 > "$OUT/failed-by-username.txt"

# 4. Did any login succeed? (key for the incident report's impact section)
authlog | grep "Accepted" | tail -n 20 > "$OUT/accepted-logins.txt"
[ -s "$OUT/accepted-logins.txt" ] || echo "No 'Accepted' lines found." > "$OUT/accepted-logins.txt"

# 5. SSH hardening state (before/after remediation)
sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|logingracetime)' > "$OUT/sshd-effective-config.txt"

# 6. fail2ban status if installed
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd > "$OUT/fail2ban-status.txt" 2>&1
else
  echo "fail2ban not installed" > "$OUT/fail2ban-status.txt"
fi

tar -czf "/tmp/evidence-$NAME.tar.gz" -C /tmp "evidence-$NAME"
chown "$OWNER" "/tmp/evidence-$NAME.tar.gz"
chmod -R a+rX "$OUT"
echo "Done: /tmp/evidence-$NAME.tar.gz"
