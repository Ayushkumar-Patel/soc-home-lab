# Wazuh + Suricata (User-VM, 192.168.152.60)

## Role in this lab
Host-based (Wazuh) and network-based (Suricata) intrusion detection, correlating activity
from both detection scenarios: SSH brute-force (`detections/ssh-bruteforce/`) and network
reconnaissance (`detections/nmap-recon/`).

## Install

**Wazuh manager:**

Installed on User-VM using Wazuh's official all-in-one installation assistant (manager,
indexer and dashboard all on this one VM, suited to a single-host lab):

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
- Official source: https://documentation.wazuh.com/current/installation-guide/index.html
- Current stable branch: Wazuh 4.14.x
- The script prints the admin/dashboard passwords once at the end — save them immediately;
  they can be retrieved again later with:
  ```bash
  sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
  ```
<!-- EDIT: confirm the exact version it installed (check with: cat /var/ossec/etc/VERSION or
     the install log at /var/log/wazuh-install.log) -->

**Suricata:**

Installed from OISF's official stable PPA (the Ubuntu default repo carries an older build):

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata jq
suricata -V
```
- Official source: https://docs.suricata.io/en/latest/install/ubuntu.html
- PPA maintained by OISF (Open Information Security Foundation): https://launchpad.net/~oisf/+archive/suricata-stable
- Current stable line: Suricata 8.x (7.0.x is the parallel LTS branch — only relevant if you
  specifically need long-term support over the newest parsers)

Interface Suricata listens on:
```bash
grep -E '^\s*-?\s*interface:' /etc/suricata/suricata.yaml
```
<!-- EDIT: confirm which interface this returned (should be the VM's VMnet2-connected NIC,
     e.g. ens33 or eth0 — check with `ip a` if unsure) -->
     
## Agents

| Agent | IP | Monitors |
|---|---|---|
| Server-VM | 192.168.152.40 | `/var/log/auth.log` (SSH authentication events) |
| Windows 11 Endpoint | 192.168.152.30 | Sysmon + Windows Security event log |

Confirm both show **Active**, not `Never connected`:
```bash
sudo /var/ossec/bin/agent_control -l
```
<!-- EDIT: paste actual agent_control output -->

## Suricata rules

**Ruleset source:** <!-- EDIT: e.g. Emerging Threats Open (free), via suricata-update -->
```bash
suricata-update list-enabled-sources
```

**Interface visibility limitation:** this VM sits on the same host-only vswitch (VMnet2) as
every other VM, but a virtual switch only delivers traffic addressed to a given VM — it does
not mirror everyone else's traffic to this one. So Suricata here only sees traffic to/from
User-VM itself, **not** the SSH brute-force or Nmap scan traffic between .20 and .40. See the
full explanation in `architecture/README.md`.

**Resolution used:** packet capture and Suricata analysis for both attacks were done by
running `tcpdump`/Suricata directly against Server-VM's own interface during the attack
window, then the resulting `eve.json`/`fast.log` entries (or a copied pcap) were reviewed —
rather than relying on User-VM to observe third-party traffic it structurally can't see.
<!-- EDIT: confirm this is actually how you did it, or describe what you did instead
     (e.g. ran Suricata directly on Server-VM) -->

## Wazuh ↔ Suricata integration

Wazuh ingests Suricata's `eve.json` as a log source:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```
<!-- EDIT: confirm this block is in /var/ossec/etc/ossec.conf on User-VM, or paste your
     actual config if it differs -->

This means every Suricata alert (and, depending on config, every logged event) shows up a
second time as a Wazuh alert with a `Suricata:` prefix in its rule description — useful for
cross-referencing but worth noting as the same underlying detection, not two independent ones.

## Alerts observed

| Source detection | Expected Wazuh rule behavior | Result |
| ------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------- |
| SSH brute-force | Default ruleset rule **5760** ("Multiple SSHD authentication failures"), correlation window ~120s | **Detected** — Rule 5760 triggered, Level 10, following 12 failed SSH authentication attempts from `192.168.152.20`. |
| SSH brute-force (invalid usernames, if any) | Rule **5712** ("Attempt to login using a non-existent user") | **Detected** — Rule 5712 triggered, Level 5, after repeated login attempts using an invalid username. |
| Nmap port scan | Suricata scan/portscan signature forwarded via `eve.json`, surfaces under Wazuh's `suricata`/`ids` rule group, typically level 6–7 | **Detected** — Suricata generated a port-scan alert for reconnaissance activity originating from `192.168.152.20`, forwarded to Wazuh at Level 7. |
| Nmap HTTP service probe | Suricata HTTP event log entry (not necessarily an alert — see `detections/nmap-recon/README.md`) | **Observed** — HTTP request metadata recorded in Suricata `eve.json` when Nmap performed service detection against `192.168.152.40:80`; no separate HTTP alert generated. |

Query real alerts directly:
```bash
sudo jq -r '[.rule.id, .rule.level, .rule.description] | @tsv' /var/ossec/logs/alerts/alerts.json \
  | sort | uniq -c | sort -rn | head -30
```
