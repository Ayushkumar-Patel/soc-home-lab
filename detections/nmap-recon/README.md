# Detection: Network Reconnaissance (T1046)

## Attack
```bash
nmap -sS -sV -p- 192.168.152.40
```
<!-- EDIT: date/time run -->

## Detection

### Wireshark
Filter: `tcp.flags.syn==1 && tcp.flags.ack==0`
<!-- EDIT: packet count, time span, ports scanned -->

### Suricata
<!-- EDIT: alert lines from fast.log / eve.json, or note if nothing fired and which rules were enabled -->

### Wazuh
<!-- EDIT: any forwarded Suricata alerts -->

## Findings
_To be completed after running the scan._

## MITRE ATT&CK
T1046 – Network Service Discovery
