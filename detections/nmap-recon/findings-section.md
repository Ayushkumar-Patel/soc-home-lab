## Findings

- Identified two exposed services on the target Ubuntu server (`192.168.152.40`): SSH (Port 22)
  and Apache HTTP (Port 80).
- Observed TCP SYN scanning activity originating from Kali Linux (`192.168.152.20`), indicating
  systematic network reconnaissance.
- Analyzed TCP connection patterns, open/closed port responses, and HTTP service fingerprinting
  using Wireshark (Filters A1/A2 and B above).
- Identified Nmap-generated HTTP requests used to determine Apache service information.
- Confirmed no reverse-DNS activity was generated during the scan (Filter C), consistent with
  an IP-based scan against a DNS-less isolated network.
- Evaluated Suricata and Wazuh integration for network intrusion detection and security event
  monitoring.
- Identified potential attack surfaces and recommended restricting SSH access, updating exposed
  services, and monitoring suspicious connection attempts (see Remediation / hardening notes).
