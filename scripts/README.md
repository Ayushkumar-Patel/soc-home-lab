# scripts/

Pulls real lab evidence off the VMs into the right folders of this repo, using the exact
filenames your detection READMEs reference. Run everything from the **host**, in Git Bash,
from the `soc-home-lab/` repo root.

## Your lab's VMs (already set in collect-evidence.sh)

| VM | Username | IP | Role |
|---|---|---|---|
| SIEM-VM | `SIEM-VM` | 192.168.152.10 | Splunk Enterprise |
| Attacker | — (Kali, not an evidence source) | 192.168.152.20 | Nmap, Hydra |
| Server-VM | `Server-VM` | 192.168.152.40 | SSH target — Hydra brute-force, Nmap scan |
| Endpoint | — (Windows, uses the PowerShell script instead) | 192.168.152.30 | Sysmon |
| User-VM | `User-VM` | 192.168.152.60 | Wazuh + Suricata |

If any username changes later, edit the three `*_USER` lines at the top of
`collect-evidence.sh` — nothing else needs to change.

## What each script collects, and where it lands

| Script | Runs on | Writes into (matches the README's own file references) |
|---|---|---|
| `vm/gather-linux-server.sh` | Server-VM (.40) | `detections/ssh-bruteforce/evidence/` — `auth-log-failed-sample.txt`, `failed-login-summary.txt`, `failed-by-source-ip.txt`, `failed-by-username.txt`, `accepted-logins.txt`, `sshd-effective-config.txt`, `fail2ban-status.txt` |
| `vm/gather-wazuh-suricata.sh` | User-VM (.60) | Splits into two subfolders in one run: `.../ssh-bruteforce/` (SSH session metadata, Wazuh SSH alerts) and `.../nmap-recon/` (Suricata fast.log, HTTP events, scan alerts, Wazuh scan alerts) |
| `vm/gather-splunk.sh` | SIEM-VM (.10) | `splunk/exports/` — saved searches, dashboards, forwarder-connection check. Does **not** export search results (see note in that script) — paste those from the Splunk UI yourself |
| `windows/Collect-Sysmon.ps1` | Windows 11 (.30), admin PowerShell | `sysmon/evidence/` — Event IDs 1, 3, 11, 22 plus Security 4625, matching `sysmon/README.md`'s table |
| `check-secrets.sh` | Host | Scans everything for passwords/keys/tokens and non-lab IPs before you push |

## One-time setup: SSH keys

```bash
ssh-keygen -t ed25519
cat ~/.ssh/id_ed25519.pub | ssh SIEM-VM@192.168.152.10   "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
cat ~/.ssh/id_ed25519.pub | ssh Server-VM@192.168.152.40 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
cat ~/.ssh/id_ed25519.pub | ssh User-VM@192.168.152.60   "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```
Confirm each works without a password prompt:
```bash
ssh SIEM-VM@192.168.152.10 "echo ok"
ssh Server-VM@192.168.152.40 "echo ok"
ssh User-VM@192.168.152.60 "echo ok"
```
The collector scripts still use `sudo` on each VM, so you'll be asked for that VM's sudo
password once per run — that's expected.

## Usage

```bash
chmod +x scripts/*.sh scripts/vm/*.sh
```

**SSH brute-force detection:**
```bash
# 1. baseline — before you attack
./scripts/collect-evidence.sh server before

# 2. run Hydra from Kali against 192.168.152.40, then:
./scripts/collect-evidence.sh server
./scripts/collect-evidence.sh monitor
./scripts/collect-evidence.sh siem
```

**Nmap recon detection** (monitor again — it collects both detections' evidence each run):
```bash
# run nmap from Kali against 192.168.152.40, then:
./scripts/collect-evidence.sh monitor
```

**Remediation validation** (after hardening SSH):
```bash
./scripts/collect-evidence.sh server after
```
Compare `detections/ssh-bruteforce/evidence/before/` vs `.../after/`.

**Windows (manual, not through collect-evidence.sh):**
1. Copy `windows/Collect-Sysmon.ps1` into the Windows 11 VM (shared folder or drag-and-drop).
2. In an **admin** PowerShell on that VM:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\Collect-Sysmon.ps1
   ```
3. Move `Desktop\evidence-windows` back to the host, then into `sysmon/evidence/`.

**Before every commit:**
```bash
./scripts/check-secrets.sh
```

## After collecting

Open the new files and transfer the real numbers into the matching README's placeholders:

| Evidence folder | Fill into |
|---|---|
| `detections/ssh-bruteforce/evidence/` | `detections/ssh-bruteforce/README.md` — Findings, Detection sections 2–5 |
| `wazuh-suricata/evidence/ssh-bruteforce/` | same file, sections 4 (Suricata) and 5 (Wazuh) |
| `wazuh-suricata/evidence/nmap-recon/` | `detections/nmap-recon/README.md` — sections 2 (Suricata) and 3 (Wazuh) |
| `splunk/exports/` | `detections/ssh-bruteforce/README.md` — section 3 (Splunk); paste the actual search result from the Splunk UI too |
| `sysmon/evidence/` | `sysmon/README.md` — Event IDs table |

Then update `incident-reports/ssh-bruteforce-incident.md`'s timeline and "not yet confirmed"
fields with the same real values.

## Notes

- All scripts are built around this lab's fixed addressing (`architecture/ip-addressing-scheme.md`) — if you re-IP a VM, update the `*_IP` variables at the top of `collect-evidence.sh`, nothing else.
- Keep the Wireshark pcap manual: capture directly on Server-VM (.40) during the attacks — see the visibility note in `architecture/README.md` about why .50/.60 don't see third-party traffic on a host-only vswitch — then trim with `editcap -r in.pcap out.pcap 1-500` before committing.
- These scripts assume your own isolated lab only. Check each output file by eye before committing — usernames, hostnames and IPs are real, not redacted automatically for the fields `check-secrets.sh` doesn't cover.
