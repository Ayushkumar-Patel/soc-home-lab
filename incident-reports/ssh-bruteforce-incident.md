# Incident Report: SSH Brute-Force Against Linux Server

**Severity:** Medium (simulated security event; final severity depends on whether authentication succeeded and the target's exposure)
**Status:** Resolved in the isolated lab after the test was stopped; remediation actions should be recorded only after they are verified.
**MITRE ATT&CK:** T1110.001 – Brute Force: Password Guessing

## Summary

A controlled SSH password-guessing exercise was conducted from the Kali Linux attacker VM (`192.168.152.20`) against the Ubuntu Server (`192.168.152.40`) using Hydra and the test account `labtest`. Repeated SSH connection and authentication attempts were examined using packet captures, Linux authentication logs, Splunk, Suricata and Wazuh to assess detection coverage and support incident investigation. This is a lab simulation, not evidence of an external compromise.

## Timeline (UTC)

> **Illustrative timeline:** The timestamps below are sample UTC times to provide a coherent incident sequence. Replace them with timestamps from your actual packet capture, Linux authentication log, Splunk events and Wazuh alerts before publishing this as a factual incident report.

| Time (UTC) | Event |
|---|---|
| 14:02:00 | Controlled Hydra SSH password-guessing test started from `192.168.152.20` against `192.168.152.40:22`. |
| 14:02:03 | First failed SSH authentication attempt recorded in the Ubuntu authentication log. |
| 14:02:15 | Repeated SSH connections observed in the Wireshark/tcpdump capture, showing recurring TCP connection and SSH session patterns. |
| 14:02:30 | Linux authentication events reviewed in Splunk for repeated failures associated with the source IP and `labtest` account. |
| 14:02:45 | Wazuh alert review performed for correlated SSH authentication failures; record the actual rule ID and alert time if an alert was generated. |
| 14:03:10 | Hydra test stopped and the target's authentication logs and packet capture preserved for analysis. |
| 14:05:00 | Lab review and containment/hardening checks initiated; verify each action before marking it completed. |

## Detection source

- **Linux authentication log:** Primary evidence of failed SSH authentication attempts, including timestamps, targeted account and source address. Evidence file referenced by the lab notes: `evidence/auth-log-failed-sample.txt`.
- **Wireshark / tcpdump:** Packet-level evidence of repeated SSH connections from `192.168.152.20` to `192.168.152.40` on TCP port 22. SSH payloads are encrypted, so usernames and passwords cannot be read from the packet capture.
- **Splunk Enterprise:** Search and alert workflow defined in `splunk/ssh-bruteforce.spl`. Record the actual alert name, trigger time and matching event count after checking the search results.
- **Suricata:** SSH session metadata can be reviewed in `/var/log/suricata/eve.json`. The default ruleset may not generate a dedicated SSH brute-force alert; do not report an alert unless one appears in the logs.
- **Wazuh:** Review correlated SSH authentication-failure alerts. Record the actual rule ID, level and description from `alerts.json`; do not assume a rule fired.

## Indicators

- **Source IP:** `192.168.152.20` (Kali Linux)
- **Target IP:** `192.168.152.40` (Ubuntu Server)
- **Target service:** SSH, TCP port `22`
- **Account targeted:** `labtest`
- **Tool / command:** Hydra — `hydra -l labtest -P wordlist.txt ssh://192.168.152.40 -t 4`
- **Attempt count:** Not yet confirmed; calculate from the authentication log and correlate with distinct SSH sessions in the packet capture.
- **Observed behavior:** Repeated SSH connection and authentication attempts from one source against a known account.
- **MITRE ATT&CK technique:** T1110.001 – Password Guessing.

## Impact assessment

The exercise targeted a test account on an isolated lab server. The available project notes do not establish whether Hydra discovered a valid password or whether any authentication succeeded. Therefore, successful access and data exposure must be recorded as **unconfirmed** until the Hydra output and server authentication logs are reviewed. No impact to production systems is indicated by this lab scenario.

If the logs confirm that every attempt failed, record that no unauthorized session was established. If a successful login occurred, document the successful-login timestamp, account, subsequent commands or activity, and any files or services accessed.

## Response / containment

1. Stop the Hydra process and end the controlled test.
2. Preserve the relevant packet capture, Linux authentication log, Splunk search results, Suricata `eve.json` entries and Wazuh alerts as investigation evidence.
3. Review the Ubuntu authentication log for any successful login associated with the test account and source IP.
4. If the test account's password was discovered, disable or reset that credential and review the account's authorized access. Do not assume compromise without confirming a successful authentication event.
5. Harden SSH by using key-based authentication, disabling password authentication where operationally appropriate, disabling root login and limiting authentication attempts.
6. Apply connection rate limiting or a tool such as Fail2ban, then validate the configuration with a controlled re-test.
7. Confirm that Splunk and Wazuh searches detect repeated authentication failures. If the default Suricata ruleset does not alert on the behavior, document that limitation and consider a tested local detection rule.

## Lessons learned

- Repeated SSH connection patterns can indicate brute-force activity even though SSH payloads are encrypted and credentials are not visible in packet captures.
- Linux authentication logs provide the key evidence for counting failed attempts, identifying targeted accounts and confirming whether authentication succeeded.
- Correlating packet captures with host logs improves confidence in the source, timing and nature of the activity.
- SIEM detection depends on correct log collection, field extraction, search logic and alert thresholds; a query or integration alone does not prove that an alert fired.
- Suricata's default ruleset may log SSH session metadata without producing a dedicated brute-force alert. Detection coverage should be tested and gaps documented.
- Wazuh correlation rules can help identify repeated authentication failures, but the actual rule ID, severity and alert details must be verified from the generated events.
- SSH hardening, rate limiting and automated blocking should be validated through a before-and-after test rather than assumed effective.

---

**Evidence to attach before finalizing:** Hydra output; timestamped authentication-log excerpt; Wireshark session/packet counts; Splunk alert result; Suricata event or alert excerpt; Wazuh alert JSON including rule ID and level. Replace all illustrative timeline times and unconfirmed outcomes with values from the actual lab run.
