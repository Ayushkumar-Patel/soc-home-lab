# Sysmon Endpoint Monitoring (Windows 11, .30)

## Setup
```
sysmon64.exe -accepting eula -i sysmonconfig.xml
```
Config source: <!-- EDIT: e.g. SwiftOnSecurity / Olaf Hartong -->

## Test activity generated
<!-- EDIT: e.g. ran whoami, ipconfig, a few failed logons -->

## Event IDs reviewed
| Event ID | What it captures | Finding |
|---|---|---|
| 1 | Process creation | <!-- EDIT --> |
| 3 | Network connection | <!-- EDIT --> |
| 11 | File creation | <!-- EDIT --> |
| 22 | DNS query | <!-- EDIT --> |
| 4625 (Security log) | Failed logon | <!-- EDIT --> |

## Splunk searches
```spl
index=windows source="*Sysmon/Operational" EventCode=1
| stats count by Image, CommandLine, ParentImage
```
```spl
index=windows source="*Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
```

_To be completed after running Collect-Sysmon.ps1._
