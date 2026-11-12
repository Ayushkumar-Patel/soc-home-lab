# Virtual Cybersecurity Home Lab – SIEM Monitoring & Threat Detection

<!-- EDIT: one paragraph. What the lab is, what you built it to practice. -->
A virtual SOC environment simulating an enterprise network, built to practice log analysis,
threat detection, incident investigation and vulnerability management.

## Tools
VMware Workstation, Kali Linux, Ubuntu Server, Windows 11, Splunk Enterprise, Wireshark, Wazuh,
Sysmon, Nmap, Suricata, Greenbone OpenVAS.

## Architecture
See [`architecture/README.md`](architecture/README.md) for the network diagram and VM roles.

| VM | OS | IP | Role |
|---|---|---|---|
| SIEM | Ubuntu Server | 192.168.152.10 | Splunk Enterprise |
| Attacker | Kali Linux | 192.168.152.20 | Nmap, Hydra |
| Endpoint | Windows 11 | 192.168.152.30 | Sysmon, Event Logs |
| Linux Server | Ubuntu Server | 192.168.152.40 | SSH, Authentication Logs |
| Network Monitoring | Ubuntu/Kali | 192.168.152.50 | Wireshark |
| Security Monitoring | Ubuntu Server | 192.168.152.60 | Wazuh, Suricata |

Network: Host-only (VMnet2), 192.168.152.0/24, no gateway.

## Detections
| Project | Technique (MITRE ATT&CK) | Status |
|---|---|---|
| [SSH Brute-Force Detection](detections/ssh-bruteforce/README.md) | T1110 – Brute Force | <!-- EDIT: Not started / In progress / Complete --> |
| [Network Reconnaissance Detection](detections/nmap-recon/README.md) | T1046 – Network Service Discovery | <!-- EDIT --> |

## Other work
- [Sysmon endpoint monitoring](sysmon/README.md)
- [Wazuh + Suricata setup](wazuh-suricata/README.md)
- [Wireshark traffic analysis](wireshark/README.md)
- [Vulnerability assessment](vuln-assessment/README.md)
- [Incident report](incident-reports/ssh-bruteforce-incident.md)

## Results
<!-- EDIT: fill in once the lab is run. Example:
- Detected N brute-force attempts across M minutes
- Splunk alert fired within X seconds of threshold breach
- Wazuh rule <ID> (level <N>) triggered on the same activity
- N vulnerabilities found via OpenVAS, N remediated and re-verified
-->
_To be completed after running the lab._

## Skills demonstrated
Log analysis, SIEM configuration (Splunk, Wazuh), IDS/IPS (Suricata), endpoint monitoring (Sysmon),
network traffic analysis (Wireshark), vulnerability assessment (Nmap, OpenVAS), incident documentation.
