#!/usr/bin/env bash
# Run before every push. Fails if likely secrets are found; lists unusual IPs for review.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EXCL=(--exclude-dir=.git --exclude=check-secrets.sh --exclude=*.pcap --exclude=*.pdf)
FAIL=0

echo "== Checking for likely secrets =="
PATTERNS='(password|passwd|pwd|secret|token|api[_-]?key)[[:space:]]*[=:][[:space:]]*[^[:space:]]+|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|pass4SymmKey|sslPassword'
if grep -rEin "${EXCL[@]}" "$PATTERNS" . ; then
  echo "!! Possible secrets above. Remove or redact them, then re-run."; FAIL=1
else
  echo "None found."
fi

echo
echo "== IPs other than your lab range (review each; lab 192.168.152.x is fine) =="
grep -rEoh "${EXCL[@]}" '([0-9]{1,3}\.){3}[0-9]{1,3}' . 2>/dev/null \
  | grep -Ev '^(192\.168\.152\.|127\.|0\.0\.0\.0|255\.)' | sort | uniq -c | sort -rn | head -30
echo "(Version numbers like 4.2.0.1 can show up here; real public IPs should be redacted.)"

exit $FAIL
