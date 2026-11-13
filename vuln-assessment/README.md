# Vulnerability Assessment

## Scope

- **Target:** Ubuntu Server-VM (192.168.152.40)
- **Scanner:** Kali Linux (192.168.152.20)
- **Network:** VMware Host-only (192.168.152.0/24)
- **Exposed services:** SSH (22), Apache HTTP (80)
- **Assessment type:** Network vulnerability assessment

## Tools

### 1. Nmap
Used for service detection and vulnerability scanning.

```bash
nmap -sV --script vuln -oA evidence/nmap-vuln-scan 192.168.152.40
```

### 2. Greenbone OpenVAS
Used to identify known vulnerabilities and CVEs.

Install and configure on Kali:
```bash
sudo apt update
sudo apt install gvm
sudo gvm-setup
sudo gvm-check-setup
sudo gvm-start
```

- **Web interface:** https://127.0.0.1:9392
- **Scan configuration:** Full and fast
- **Target:** 192.168.152.40

## Running the scan

1. Verify connectivity between Kali and Server-VM.
2. Run Nmap vulnerability scripts against the target.
3. Configure the target in Greenbone.
4. Execute a Full and fast vulnerability scan.
5. Review findings by severity, CVE, and affected service.
6. Export scan reports for documentation.

## Findings

The following vulnerabilities were selected for investigation based on recent Apache HTTP Server and OpenSSH security advisories. Applicability must be verified against the installed Ubuntu packages and enabled modules.

| Severity | Finding | CVE / Reference | Status |
|---|---|---|---|
| Critical | Apache HTTP/2 memory corruption potentially leading to remote code execution (`mod_http2`). | CVE-2026-119618 | Requires verification |
| High | OpenSSH password authentication bypass under specific musl libc and no-PAM configurations. | CVE-2026-123158 | Configuration-dependent |
| Medium | Apache `mod_proxy_html` buffer overflow involving untrusted backend content. | CVE-2026-34355 | Requires verification |
| Medium | Apache HTTP/2 use-after-free vulnerability. | CVE-2026-57941 | Ubuntu 26.10-specific advisory; verify applicability |
| Pending | Apache memory-handling vulnerability potentially causing denial of service. | CVE-2026-46729 | Requires verification |
| Pending | Apache session-cookie handling vulnerability potentially exposing sensitive information. | CVE-2026-47360 | Requires verification |
| Pending | Apache authentication-handling vulnerability potentially causing denial of service. | CVE-2026-48005 | Requires verification |
| Pending | OpenSSH agent security vulnerability involving forwarded agent connections. | CVE-2026-73281 | Requires verification |
| Pending | OpenSSH remote-forwarding use-after-free vulnerability. | CVE-2026-73282 | Requires verification |

## Evidence collection

- Nmap scan results (`.nmap`, `.xml`, `.gnmap`)
- OpenVAS vulnerability assessment report
- Identified CVEs and severity ratings
- Screenshots of scan results

## Cross-reference with Nmap

- Compare Nmap and OpenVAS findings.
- Identify vulnerabilities detected by both tools.
- Document findings unique to each scanner.
- Investigate service and version-related weaknesses.

## Remediation Validation

| Finding | Before | Fix Applied | After |
|---|---|---|---|
| SSH weaknesses | Review SSH configuration for password authentication, root login, weak algorithms, and outdated OpenSSH packages. | Disabled password authentication, enforced SSH key-based authentication, disabled root login, and reviewed supported cryptographic algorithms. | Pending — re-run Nmap and OpenVAS; verify SSH configuration and authentication. |
| Apache weaknesses | Review Apache version, enabled modules, HTTP security headers, and applicable CVEs. | Updated Apache packages, disabled unnecessary modules, reviewed server configuration, and implemented recommended security headers. | Pending — re-run vulnerability scans and verify Apache configuration and HTTP response headers. |
| Outdated packages | Identify outdated Ubuntu packages and available security updates. | Executed `sudo apt update` and `sudo apt upgrade`; rebooted if required by kernel or system updates. | Pending — verify package versions and confirm no applicable security updates remain. |
| Vulnerable services | Identify exposed services and unnecessary listening ports. | Disabled unnecessary services and restricted access using UFW firewall rules. | Pending — repeat Nmap service and port scanning. |
| Apache HTTP security | Review HTTP configuration and exposure of sensitive server information. | Reviewed directory listing, server information disclosure, TLS configuration where applicable, and security headers. | Pending — verify with HTTP response checks and OpenVAS. |

### Validation Commands

**1. SSH configuration**

```bash
sudo sshd -t
sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin|pubkeyauthentication'
sudo systemctl status ssh

## Troubleshooting

- **GVM setup failure:** Run `sudo gvm-check-setup`.
- **Feed synchronization incomplete:** Allow initial feed downloads to finish.
- **Web interface unavailable:** Run `sudo gvm-start`.
- **Target unreachable:** Verify connectivity using `ping 192.168.152.40`.
- **No scan results:** Verify target IP, exposed ports, and scan configuration.
