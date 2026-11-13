# Sysmon Endpoint Monitoring (Windows 11 Endpoint, 192.168.152.30)

## Role in this lab
Endpoint-level visibility on the one Windows host in the network. Unlike Server-VM (.40),
this VM isn't targeted by the Kali attacks — its findings come from deliberately generated
test activity, and (if configured) from forwarding events to Splunk/Wazuh like the other
hosts.

## Install

Download Sysmon from Microsoft's official Sysinternals page:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Config file: a community-maintained ruleset gives far better default coverage than Sysmon's
bare defaults. This lab uses:
- SwiftOnSecurity's config: https://github.com/SwiftOnSecurity/sysmon-config
<!-- EDIT: confirm which config you actually used (SwiftOnSecurity or Olaf Hartong's
     "sysmon-modular") -->

```powershell
# from an admin PowerShell, in the folder containing sysmon64.exe and sysmonconfig.xml
.\sysmon64.exe -accepting eula -i sysmonconfig.xml
```

Confirm it's running:
```powershell
Get-Service Sysmon64
```
<!-- EDIT: paste actual service status -->

## Test activity generated

Since .30 isn't attacked directly, its Sysmon events come from activity run manually on the
VM itself, to exercise the event types below:
- `whoami` and `ipconfig /all` from an admin Command Prompt (EventID 1 — process creation)
- A deliberate failed logon at the Windows lock screen, typing the wrong password 2–3 times
  (Security log EventID 4625)
- Normal background activity (Windows Update checks, browser DNS lookups) captured
  incidentally for EventID 3 and 22
<!-- EDIT: date/time this was run -->

## Event IDs reviewed

| Event ID | What it captures | Finding |
|---|---|---|
| 1 | Process creation (image, command line, parent process) | "whoami.exe and ipconfig.exe captured, parent process cmd.exe, confirming the test commands were logged with full command-line visibility"  |
| 3 | Network connection | outbound connections to Windows Update / NTP, any unexpected destinations |
| 11 | File creation | temp files created by the commands run, or none if no file activity occurred  |
| 22 | DNS query | domains resolved during test activity, compare against the DNS-less network note in architecture/README.md — Windows uses its own DNS cache/hosts resolution independent of the lab's DNS config  |
| 4625 (Security log) | Failed logon | number of failed logons recorded, account name, logon type (should be 2 = interactive, for a lock-screen attempt) |

Collected with [`../scripts/windows/Collect-Sysmon.ps1`](../scripts/windows/Collect-Sysmon.ps1)
— see that script for exactly which fields are exported per event type.

## Splunk searches
(If Windows forwarder is configured — see `splunk/README.md` data inputs table)
```spl
index=windows source="*Sysmon/Operational" EventCode=1
| stats count by Image, CommandLine, ParentImage
```
```spl
index=windows source="*Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
```
<!-- EDIT: confirm forwarder is sending Windows logs to Splunk; if not configured, note that
     and keep this as the intended/designed search rather than a tested one -->

## Troubleshooting notes

- `Get-WinEvent` returns "Access is denied" → PowerShell wasn't run as Administrator; Sysmon
  and Security logs require elevated access to read.
- No Sysmon events at all → confirm the service is actually running
  (`Get-Service Sysmon64`) and that `sysmonconfig.xml` was applied, not just the bare default
  config (`sysmon64.exe -c` shows the active ruleset).
- EventID 4625 empty after a deliberate wrong password → confirm you typed it at the actual
  Windows lock screen (Ctrl+Alt+Del on a VM), not just in an open session; some other logon
  methods don't generate 4625 the same way.
<!-- EDIT: replace with real issues you hit -->

