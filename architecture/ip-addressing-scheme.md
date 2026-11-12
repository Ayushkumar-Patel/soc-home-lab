# Virtual Cybersecurity Home Lab — IP Addressing Scheme

**Network platform:** VMware Workstation
**Network type:** Host-only (VMnet2)
**Network subnet:** 192.168.152.0/24
**Subnet mask:** 255.255.255.0

## 1. Virtual machine IP configuration

| Virtual machine | Operating system | IP address | Role |
|---|---|---|---|
| VM 1 – SIEM | Ubuntu Server | 192.168.152.10 | Splunk Enterprise |
| VM 2 – Attacker | Kali Linux | 192.168.152.20 | Nmap, Hydra |
| VM 3 – Endpoint | Windows 11 | 192.168.152.30 | Sysmon, Windows Event Logs |
| VM 4 – Linux Server | Ubuntu Server | 192.168.152.40 | SSH, Authentication Logs |
| VM 5 – Network Monitoring | Ubuntu / Kali | 192.168.152.50 | Wireshark |
| VM 6 – Security Monitoring | Ubuntu Server | 192.168.152.60 | Wazuh, Suricata |

## 2. Network addressing details

| Configuration | Value |
|---|---|
| Network ID | 192.168.152.0 |
| Subnet mask | 255.255.255.0 |
| CIDR notation | /24 |
| Broadcast address | 192.168.152.255 |
| Usable IP range | 192.168.152.1 – 192.168.152.254 |
| Gateway | 192.168.152.1 (VMware host-only virtual adapter) |
| DNS | Not configured — static IPs only |

See [`README.md`](README.md) for the data-flow diagram and design rationale.
