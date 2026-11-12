# Detection: SSH Brute-Force (T1110)

## Objective
Simulate an SSH brute-force attack against the Linux server and verify it is detected across
packet capture, Splunk, Suricata and Wazuh.

## Setup
- Target: 192.168.152.40, test account `labtest`
- Attacker: Kali Linux, 192.168.152.20, Hydra
- Capture point: tcpdump/Wireshark run directly on .40 (see `architecture/README.md` — the
  host-only vswitch doesn't mirror third-party traffic to .50/.60)

## Attack
```bash
hydra -l labtest -P wordlist.txt ssh://192.168.152.40 -t 4
```
<!-- EDIT: date/time run, outcome (credential found or not), total attempts made -->

## Detection

### 1. Network traffic analysis (Wireshark)

SSH traffic is encrypted, so you can't read usernames/passwords in the capture — but the
**connection pattern** itself is the evidence: many short TCP sessions in quick succession from
one source is distinctive of brute-forcing, independent of payload content.

**Filter A — all SSH traffic to the target:**
```
tcp.port==22 && ip.dst==192.168.152.40
```
Baseline view of every SSH session in the capture.

**Filter B — SSH traffic from the attacker specifically:**
```
tcp.port==22 && ip.src==192.168.152.20 && ip.dst==192.168.152.40
```
<!-- EDIT: number of distinct TCP sessions (Follow > TCP Stream count), average session
     duration, time span of the burst -->

**What to look for:** each Hydra attempt opens a new TCP connection, completes the SSH key
exchange, attempts auth, and closes — so you should see a repeating pattern of
SYN → SYN/ACK → ACK → (SSH banner/KEX packets) → FIN, one cycle per attempt, with very short
gaps between cycles (sub-second if `-t 4` ran 4 threads in parallel).

### 2. Linux auth log
See `evidence/auth-log-failed-sample.txt`.
<!-- EDIT: total failed attempts, time window, source IP, whether login eventually succeeded -->

### 3. Splunk
Query: [`../../splunk/ssh-bruteforce.spl`](../../splunk/ssh-bruteforce.spl)
<!-- EDIT: alert fired? timestamp? result count? -->

### 4. Suricata

Suricata's SSH protocol parser logs every session's client/server software string to
`eve.json` even without an alert — useful corroborating evidence alongside the auth log:
```bash
grep '"event_type":"ssh"' /var/log/suricata/eve.json | tail -n 10
```
Expect the `ssh.client.software_version` field to show Hydra's or your SSH client's banner
string, repeated once per connection attempt.

**Default ET ruleset note:** most free Suricata rulesets don't include a dedicated
"SSH brute force" signature out of the box (brute-force detection is usually left to Wazuh's
log-correlation rules instead). If nothing fires here, that's expected — document it rather
than treating it as a gap, and cross-reference the custom rule in Remediation below if you add
one.
<!-- EDIT: confirm what did/didn't fire -->

### 5. Wazuh
<!-- EDIT: rule ID, rule level, description from alerts.json (expect something like
     "Multiple SSHD authentication failures" once several failures land inside the
     correlation window) -->

## Findings
<!-- EDIT with real numbers, for example:
- N failed login attempts in M minutes from 192.168.152.20, confirmed in both auth.log and
  the Wireshark session count
- Splunk alert triggered at HH:MM:SS, N matching events
- Suricata: no dedicated brute-force signature fired (expected with default ruleset); SSH
  session metadata logged to eve.json for every attempt
- Wazuh rule <ID>, level <N>, fired after N failures within the correlation window
- [Successful / no successful] authentication observed
-->
_To be completed after running the attack._

## MITRE ATT&CK

| Technique | ID | How it applies |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Sequential password attempts from a wordlist against one known username |
| Brute Force: Password Spraying | T1110.003 | If the wordlist also targeted other usernames (e.g. `admin`), this becomes spraying rather than pure guessing |
| Valid Accounts | T1078 | If a weak-but-real credential was found, that credential becomes a valid account usable for further access |
| Remote Services: SSH | T1021.004 | The access vector itself — SSH as the remote service being abused |

<!-- EDIT: keep only the rows that actually applied to your run; e.g. drop T1078/T1021.004
     if no login ever succeeded -->

## Remediation / hardening

**1. Disable password authentication, require keys:**
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
```
```bash
sudo systemctl restart sshd
```

**2. Rate-limit connection attempts (ufw):**
```bash
sudo ufw limit 22/tcp
```

**3. Add fail2ban for automatic blocking:**
```bash
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban
fail2ban-client status sshd
```

**4. Optional: custom Suricata rule**, since the default ruleset doesn't flag this (see
Detection section 4):
```
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH brute force - high connection rate"; \
  flow:to_server; flags:S; threshold:type threshold, track by_src, count 10, seconds 30; \
  classtype:attempted-recon; sid:9000002; rev:1;)
```

**5. Validation — re-run the same attack after remediation:**
```bash
hydra -l labtest -P wordlist.txt ssh://192.168.152.40 -t 4
```
Expected result with password auth disabled: Hydra reports connection refused / no valid
passwords found, since it can no longer authenticate by password at all.
<!-- EDIT: paste the actual before/after Hydra output and compare auth.log entry volume -->
