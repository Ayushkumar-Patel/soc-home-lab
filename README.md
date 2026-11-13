# Virtual Cybersecurity Home Lab – SIEM Monitoring & Threat Detection

A virtual SOC environment built on VMware Workstation, simulating an enterprise network to
practice log analysis, threat detection, intrusion detection, vulnerability assessment and
incident investigation.

## Tools
VMware Workstation, Kali Linux, Ubuntu Server, Windows 11, Splunk Enterprise, Wireshark,
Wazuh, Sysmon, Nmap, Suricata, Greenbone OpenVAS (GVM).

## Architecture

See [`architecture/README.md`](architecture/README.md) for the full network diagram, data
flow, and design notes (including why traffic is captured directly on the target host rather
than on the network-monitoring VM).

| VM | OS | IP | Role |
|---|---|---|---|
| SIEM-VM | Ubuntu Server | 192.168.152.10 | Splunk Enterprise |
| Attacker | Kali Linux | 192.168.152.20 | Nmap, Hydra, Greenbone OpenVAS |
| Endpoint | Windows 11 | 192.168.152.30 | Sysmon, Windows Event Logs |
| Server-VM | Ubuntu Server | 192.168.152.40 | SSH, Apache — attack/scan target |
| Network Monitoring | Ubuntu/Kali | 192.168.152.50 | (see architecture note on visibility) |
| User-VM | Ubuntu Server | 192.168.152.60 | Wazuh, Suricata |

Network: Host-only (VMnet2), 192.168.152.0/24, gateway 192.168.152.1, no DNS.

## Detections and assessments

| Project | Technique (MITRE ATT&CK) | Status |
|---|---|---|
| [SSH brute-force detection](detections/ssh-bruteforce/README.md) | T1110.001 – Password Guessing | Wazuh/Suricata results confirmed; Splunk and packet-capture findings in progress |
| [Network reconnaissance detection](detections/nmap-recon/README.md) | T1595.001/002, T1592.002, T1046 | Detection logic and findings written; packet-capture confirmation in progress |
| [Vulnerability assessment](vuln-assessment/README.md) | — | Scope and tooling documented; scan not yet run |
| [Wireshark traffic analysis](wireshark/README.md) | — | Filters and procedure documented; findings pending real capture |
| [Sysmon endpoint monitoring](sysmon/README.md) | — | Structure documented; test activity not yet captured |

## Supporting infrastructure
- [Splunk Enterprise](splunk/README.md) — log collection and the SSH brute-force detection search
- [Wazuh + Suricata](wazuh-suricata/README.md) — host and network intrusion detection
- [Evidence collection scripts](scripts/README.md) — pulls real log/alert evidence from each VM into the matching folder above
- [Incident report](incident-reports/ssh-bruteforce-incident.md) — SSH brute-force incident writeup (in progress)

## Results

Confirmed so far, from the SSH brute-force attack (Kali → Server-VM):
- Wazuh rule **5760** ("Multiple SSHD authentication failures") triggered at **Level 10**
  after 12 failed SSH authentication attempts from 192.168.152.20.
- Wazuh rule **5712** ("Attempt to login using a non-existent user") triggered at **Level 5**
  for attempts against an invalid username.
- Suricata generated a port-scan alert for the Nmap reconnaissance from the same source,
  forwarded to Wazuh at **Level 7**.
- Suricata logged HTTP request metadata for Nmap's service-detection probe against port 80;
  no separate HTTP alert was generated.

Still pending real data: Splunk search results, packet-capture counts and timings,
vulnerability scan findings, and Sysmon endpoint activity — tracked as "Pending" or
`<!-- EDIT -->` in each folder's own README rather than filled with placeholder numbers.

## Skills demonstrated
Log analysis, SIEM configuration (Splunk, Wazuh), IDS/IPS (Suricata), endpoint monitoring
(Sysmon), network traffic analysis (Wireshark), vulnerability assessment (Nmap, OpenVAS),
MITRE ATT&CK mapping, and incident documentation.
