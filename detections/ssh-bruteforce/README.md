# Detection: SSH Brute-Force (T1110)

## Objective
Simulate an SSH brute-force attack against the Linux server and verify it is detected by
Splunk and Wazuh.

## Setup
<!-- EDIT: test account created on .40, wordlist used -->
- Target: 192.168.152.40, user `labtest`
- Attacker: Kali Linux 192.168.152.20, Hydra

## Attack
```bash
hydra -l labtest -P wordlist.txt ssh://192.168.152.40 -t 4
```
<!-- EDIT: date/time run, outcome (credential found or not) -->

## Detection

### Linux auth log
See `evidence/auth-log-failed-sample.txt`.
<!-- EDIT: total failed attempts, time window, source IP -->

### Splunk
Query: [`../../splunk/ssh-bruteforce.spl`](../../splunk/ssh-bruteforce.spl)
<!-- EDIT: alert fired? timestamp? -->

### Wazuh
<!-- EDIT: rule ID, rule level, description from alerts.json -->

## Findings
<!-- EDIT real numbers, e.g.:
- N failed login attempts in M minutes from 192.168.152.20
- Splunk alert triggered at HH:MM:SS
- Wazuh rule <ID>, level <N>
- No successful authentication observed
-->
_To be completed after running the attack._

## MITRE ATT&CK
T1110 – Brute Force

## Remediation
<!-- EDIT: e.g. disabled password auth, added fail2ban -->

## Validation
<!-- EDIT: re-ran Hydra after remediation, compare evidence/before vs evidence/after -->
