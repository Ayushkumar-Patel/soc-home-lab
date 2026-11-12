# Runs ON the Windows 11 VM (.30) in an ADMIN PowerShell.
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\Collect-Sysmon.ps1
# Output: Desktop\evidence-windows  -> move to host via VMware shared folder, then into repo sysmon\evidence\
#Requires -RunAsAdministrator

$out = Join-Path $env:USERPROFILE 'Desktop\evidence-windows'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$max = 200

"Host: $env:COMPUTERNAME`nCollected (UTC): $((Get-Date).ToUniversalTime().ToString('s'))Z`nOS: $((Get-CimInstance Win32_OperatingSystem).Caption)" |
  Set-Content (Join-Path $out 'collection-info.txt')

# Sysmon service and effective config
Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String |
  Set-Content (Join-Path $out 'sysmon-service.txt')
try { & sysmon64.exe -c 2>&1 | Set-Content (Join-Path $out 'sysmon-config-dump.txt') }
catch { "sysmon64.exe not on PATH. Run it from its folder: sysmon64.exe -c" | Set-Content (Join-Path $out 'sysmon-config-dump.txt') }

# Event counts by Event ID (shows which Sysmon events are being logged)
try {
  Get-WinEvent -LogName $sysmonLog -MaxEvents 5000 -ErrorAction Stop |
    Group-Object Id | Sort-Object Count -Descending |
    Select-Object Count, @{n='EventID';e={$_.Name}} | Format-Table -AutoSize | Out-String |
    Set-Content (Join-Path $out 'sysmon-event-counts.txt')
  Write-Host 'OK   sysmon-event-counts'
} catch { Write-Host "SKIP sysmon-event-counts: $($_.Exception.Message)" }

function Export-Events($LogName, $Ids, $Name) {
  try {
    Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$Ids} -MaxEvents $max -ErrorAction Stop |
      Select-Object TimeCreated, Id, @{n='Message';e={ $_.Message -replace '\r?\n',' | ' }} |
      Export-Csv -Path (Join-Path $out "$Name.csv") -NoTypeInformation
    Write-Host "OK   $Name"
  } catch { Write-Host "SKIP $Name : $($_.Exception.Message)" }
}

Export-Events $sysmonLog 1  'sysmon-eid1-process-create'
Export-Events $sysmonLog 3  'sysmon-eid3-network-connection'
Export-Events $sysmonLog 11 'sysmon-eid11-file-create'
Export-Events $sysmonLog 22 'sysmon-eid22-dns-query'

# Proof of test activity: process creation for whoami / ipconfig with parent process
try {
  Get-WinEvent -FilterHashtable @{LogName=$sysmonLog; Id=1} -MaxEvents 3000 -ErrorAction Stop |
    Where-Object { $_.Message -match 'whoami|ipconfig' } | Select-Object -First 10 |
    ForEach-Object { $_.Message; '-----' } | Set-Content (Join-Path $out 'sysmon-eid1-whoami-ipconfig.txt')
  Write-Host 'OK   whoami/ipconfig process events'
} catch { Write-Host "SKIP whoami/ipconfig: $($_.Exception.Message)" }

# Failed logons (4625): account, source IP, logon type
try {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents $max -ErrorAction Stop |
    ForEach-Object {
      $d = ([xml]$_.ToXml()).Event.EventData.Data
      [pscustomobject]@{
        Time      = $_.TimeCreated
        Account   = ($d | Where-Object Name -eq 'TargetUserName').'#text'
        SourceIP  = ($d | Where-Object Name -eq 'IpAddress').'#text'
        LogonType = ($d | Where-Object Name -eq 'LogonType').'#text'
      }
    } | Export-Csv -Path (Join-Path $out 'security-4625-failed-logons.csv') -NoTypeInformation
  Write-Host 'OK   security-4625-failed-logons'
} catch { Write-Host "SKIP 4625: $($_.Exception.Message)" }

Write-Host "`nDone. Files in: $out"
Write-Host 'Review the CSVs for your real username/computer name before committing.'
