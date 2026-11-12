# Architecture

## Network
- Platform: VMware Workstation
- Type: Host-only (VMnet2)
- Subnet: 192.168.152.0/24, mask 255.255.255.0
- Broadcast: 192.168.152.255, usable range .1–.254
- Gateway: none (isolated network)

## VM roles
| VM | OS | IP | Role |
|---|---|---|---|
| SIEM | Ubuntu Server | 192.168.152.10 | Splunk Enterprise |
| Attacker | Kali Linux | 192.168.152.20 | Nmap, Hydra |
| Endpoint | Windows 11 | 192.168.152.30 | Sysmon, Windows Event Logs |
| Linux Server | Ubuntu Server | 192.168.152.40 | SSH, Authentication Logs |
| Network Monitoring | Ubuntu/Kali | 192.168.152.50 | Wireshark |
| Security Monitoring | Ubuntu Server | 192.168.152.60 | Wazuh, Suricata |

## Data flow
<!-- EDIT once confirmed: how logs/traffic actually reach the monitoring VMs -->
| Source | Data | Destination |
|---|---|---|
| .30 Windows 11 | Sysmon, Security events | Splunk .10 (Universal Forwarder) |
| .40 Linux server | /var/log/auth.log | Splunk .10 |
| .30, .40 | Endpoint events | Wazuh manager .60 (agent) |
| Network traffic | Packets | Suricata .60 / Wireshark .50 |

## Diagram
```
Kali .20 ──attacks──► Linux Server .40 (SSH)    Windows 11 .30 (Sysmon)
                           │ auth.log                  │ Sysmon + Event Logs
                           ▼                           ▼
                   Splunk .10  ◄── forwarders ─────────┘
                   Wazuh + Suricata .60 ◄── agents (.30, .40) / traffic
                   Wireshark .50 (network monitoring)
```

## Design notes
<!-- EDIT: why host-only, how promiscuous mode / traffic visibility was handled, etc. -->
