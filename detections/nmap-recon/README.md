# Detection: Network Reconnaissance (Nmap Scan)

## Objective
Simulate network and service reconnaissance against the Linux server from the attacker VM,
and verify it is visible in packet capture, Suricata and Wazuh.

## Setup
- Target: 192.168.152.40 (SSH on 22, Apache HTTP on 80)
- Attacker: Kali Linux, 192.168.152.20
- Capture point: tcpdump/Wireshark run directly on .40 (see `architecture/README.md` —
  the host-only vswitch doesn't mirror third-party traffic to .50/.60)

## Attack

```bash
# Full TCP port sweep + service/version detection
nmap -sS -sV -p- 192.168.152.40

# Vulnerability-focused scripts (also feeds the vuln-assessment folder)
nmap --script vuln 192.168.152.40
```
<!-- EDIT: date/time run, scan duration, outcome -->

`-sV` makes Nmap send real protocol probes (including an HTTP GET) to fingerprint each open
service — this is why HTTP traffic shows up in the capture even though no web browsing happened.

## Detection

### 1. Network traffic analysis (Wireshark)

**Filter A1 — all SYN packets (baseline, no source restriction):**
```
tcp.flags.syn==1 && tcp.flags.ack==0
```
Run this first, before narrowing to the attacker. It catches every SYN-only packet in the
capture regardless of source, which is useful to confirm nothing else on the network is also
scanning at the same time, and to see the raw volume before you filter it down.
<!-- EDIT: total SYN packet count across all sources -->

**Filter A2 — SYN scan from the attacker specifically:**
```
tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.152.20
```
Narrows Filter A1 down to just the Kali VM, isolating the actual scan traffic from any
background noise.
<!-- EDIT: packet count, time span, port range swept, response pattern (SYN/ACK on 22 & 80, RST/ACK elsewhere) -->

**Filter B — HTTP (service detection probe on port 80):**
```
http && ip.src==192.168.152.20
```
Nmap's `-sV` sends a real HTTP GET to fingerprint the web server. Expect to see:
- A `GET / HTTP/1.1` request with **User-Agent** left at Nmap's default or a probe string rather
  than a normal browser's — this is a strong indicator the traffic came from a scanning tool,
  not a human visitor.
- The server's HTTP response (status code, `Server:` header) — this is exactly what lets Nmap
  report `Apache httpd 2.4.52` in its output.

<!-- EDIT: paste the actual GET request line and response Server header you captured -->

**Filter C — DNS (confirm scan target resolution behavior):**
```
dns && ip.addr==192.168.152.20
```
By default Nmap performs a reverse-DNS lookup on scanned targets unless `-n` is passed. On this
lab network there's no DNS server configured, so the expected result is **zero DNS packets** —
record that as a finding ("scan proceeded directly against the IP; no reverse-DNS reliance,
consistent with a DNS-less isolated host-only network") rather than treating an empty capture
as a mistake. If you instead ran with a resolver configured, document what reverse-lookup
traffic you see.

<!-- EDIT: confirm empty or paste the DNS query/response you captured -->

### 2. Suricata

| Expected signature | Triggered by | Where to look |
|---|---|---|
| `GPL SCAN PORTSCAN detected` / `ET SCAN Possible Nmap Scan` | the SYN port sweep | `fast.log`, `eve.json` |
| `ET SCAN Possible Nmap User-Agent Observed` | the HTTP probe sent by `-sV` (Nmap's default NSE User-Agent string) | `fast.log`, `eve.json` (`event_type:"alert"` with `http.*` fields) |
| `ET POLICY Suspicious inbound to mySQL port / HTTP on non-standard port` (if applicable) | only if you scanned beyond ports 22/80 | — |

Check `eve.json` `http` log entries too (not just `alert`): even without an alert firing,
Suricata logs every HTTP transaction it sees, which is useful corroborating evidence.
```bash
grep '"event_type":"http"' /var/log/suricata/eve.json | tail -n 5
```
<!-- EDIT: paste real alert lines / confirm which signatures fired, note if default ruleset
     didn't flag the plain SYN scan — that's a valid finding, see architecture/README.md -->

### 3. Wazuh

- Wazuh ingests Suricata's `eve.json` (see `wazuh-suricata/README.md` for the integration
  config), so the same scan and HTTP-probe alerts above should surface as Wazuh alerts with a
  `Suricata:` prefix in the rule description.
- Expected rule group: `suricata` / `ids`, typically **level 6–7** for a scan-type alert.
- Also check the Apache access log on .40 if Wazuh's `localfile` monitor is configured for it —
  the HTTP GET from the `-sV` probe should appear there as a normal-looking but single,
  isolated request with an unusual User-Agent and no referrer or session cookie.

<!-- EDIT: paste the actual Wazuh rule ID/level/description from alerts.json -->

## MITRE ATT&CK

| Technique | ID | How it applies |
|---|---|---|
| Active Scanning: Scanning IP Blocks | T1595.001 | The full `-p-` port sweep against a single host's entire port range |
| Active Scanning: Vulnerability Scanning | T1595.002 | `nmap --script vuln` run against .40 to identify exploitable weaknesses |
| Gather Victim Host Information: Software | T1592.002 | `-sV` service/version fingerprinting (the HTTP GET probe) reveals exact software versions running |
| Network Service Discovery | T1046 | Overall technique: identifying which services are reachable and listening on the target |

Mapping more than one technique here (rather than just T1046) reflects that a single Nmap
command actually performs several distinct reconnaissance behaviors — this is worth calling
out explicitly in interviews.

