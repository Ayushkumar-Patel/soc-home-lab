# Splunk Enterprise (SIEM-VM, 192.168.152.10)

## Role in this lab
Central log collection and correlation point. Receives forwarded logs from `Server-VM`
(.40, SSH/auth) and the Windows 11 endpoint (.30, Sysmon/Security), and runs the detection
search used by `detections/ssh-bruteforce/README.md`.

## Install
<!-- EDIT: Splunk Enterprise version installed, install method (e.g. .deb package) -->

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
<!-- EDIT: confirm connected -->

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
- **Saved as alert:** <!-- EDIT: alert name, schedule, trigger action -->
- **Result when run against real attack data:** <!-- EDIT: paste the result table —
  _time, src_ip, user, count columns -->

## Troubleshooting notes

- No events in `index=linux`? Check the forwarder is listed under `netstat -tnp | grep :9997`
  on SIEM-VM first — a broken forwarder is the most common cause of an empty search.
- Search returns 0 results but events exist? Confirm the sourcetype matches what's actually
  being indexed: `index=linux | stats count by sourcetype`.
- Timestamps look wrong/out of order? Check `auth.log`'s year isn't being misparsed — add
  `TIME_FORMAT` to `props.conf` for the sourcetype if needed.
- Alert never fires? Lower the threshold temporarily (`count > 2`) to confirm the search
  logic works, then raise it back to 10 once confirmed.

<!-- EDIT: replace/add with the real issues you actually hit -->

## Files in this folder
- `README.md` — this file
- `ssh-bruteforce.spl` — the detection query used above, kept as a standalone file so it can
  be copied directly into Splunk's search bar
