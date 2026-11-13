# Splunk Enterprise (SIEM-VM, 192.168.152.10)

## Role in this lab
Central log collection and correlation point. Receives forwarded logs from `Server-VM`
(.40, SSH/auth) and the Windows 11 endpoint (.30, Sysmon/Security), and runs the detection
search used by `detections/ssh-bruteforce/README.md`.

## Install
<!-- EDIT: Splunk Enterprise version installed, install method (e.g. .deb package),
     any sizing/license notes (free trial / Dev license, etc.) -->

## Data inputs

| Source | Forwarder | Index | Sourcetype |
|---|---|---|---|
| Server-VM (.40) `/var/log/auth.log` | Splunk Universal Forwarder | `linux` | `linux_secure` |
| Windows 11 (.30) Sysmon + Security logs | Splunk Universal Forwarder | `windows` | `XmlWinEventLog` |

Forwarder port: **9997** (default). Confirm a forwarder is actually connected before trusting
any search result:
```bash
# On SIEM-VM:
sudo netstat -tnp | grep :9997
# On Server-VM:
sudo /opt/splunkforwarder/bin/splunk list forward-server
```
<!-- EDIT: confirm connected, note any config changes made to inputs.conf / outputs.conf -->

## Index configuration
<!-- EDIT: index names created (e.g. "linux", "windows"), retention settings if changed from
     default, any `props.conf` / sourcetype customization -->

## Searches and alerts

### SSH brute-force detection
Query: [`ssh-bruteforce.spl`](ssh-bruteforce.spl)
```spl
index=linux "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count by _time, src_ip, user
| where count > 10
```
- **Logic:** buckets failed SSH logins into 5-minute windows, grouped by source IP and
  targeted username; flags any window with more than 10 failures from one source as a
  likely brute-force.
- **Threshold rationale:** 10 failures / 5 minutes distinguishes automated guessing (Hydra
  running multiple threads) from a user mistyping their password a couple of times.
- **Saved as alert:** <!-- EDIT: alert name, schedule (e.g. every 5 min), trigger action
  (e.g. email, add to triggered alerts list) -->
- **Result when run against real attack data:** <!-- EDIT: paste the result table —
  _time, src_ip, user, count columns -->

### Planned / possible additional searches
<!-- EDIT optional, only if you build these:
- Failed-then-succeeded pattern (brute-force followed by a valid login) for impact assessment
- Sysmon process-creation search cross-referenced with the ssh-bruteforce timeframe
-->

## Dashboards
<!-- EDIT: if you built a Splunk dashboard (Simple XML), name it and describe panels,
     e.g. "SSH Failed Logins Over Time" line chart + "Top Source IPs" table -->

## Status
<!-- EDIT: Not started / Forwarders configured / Search tested / Alert triggered on live attack -->
_Not started._

## Troubleshooting notes
<!-- EDIT: anything you had to fix — e.g. forwarder not connecting, wrong index name in
     search, timestamp parsing issues on auth.log, firewall blocking port 9997 -->

## Files in this folder
- `README.md` — this file
- `ssh-bruteforce.spl` — the detection query used above, kept as a standalone file so it can
  be copied directly into Splunk's search bar
