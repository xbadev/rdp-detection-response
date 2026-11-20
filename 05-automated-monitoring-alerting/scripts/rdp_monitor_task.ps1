<#
.SYNOPSIS
    Register the Phase 05 alert-only monitor as an event-triggered task.

.DESCRIPTION
    Optional. Phase 05 runs the monitor (no firewall action). Use this if
    you want alerting WITHOUT containment — e.g. demo the detection-only
    workflow before showing the full responder in Phase 06.

    For the full demo, use Install.ps1 at the repo root, which registers the
    Phase 06 responder task instead. Running both at once is fine: the
    monitor will alert and the responder will block.

.NOTES
    Equivalent of the Phase 06 task setup, just pointing at the monitor.
    Both register an event-triggered task firing on every Security/4625.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run elevated." -ForegroundColor Red; exit 1 }

$configPath = if ($env:RDP_LAB_CONFIG) { $env:RDP_LAB_CONFIG }
              else { 'C:\HomeLab\rdp-dr\config\lab.config.psd1' }

$cfg = Import-PowerShellDataFile -Path $configPath

$taskName = $cfg.DetectorTaskName
$script   = "$($cfg.InstallRoot)\scripts\rdp_bruteforce_monitor.ps1"

Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue |
    Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

$action = New-ScheduledTaskAction `
    -Execute 'PowerShell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""

$eventXml = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>
'@

$cimTrigger = Get-CimClass -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'MSFT_TaskEventTrigger'
$trigger = New-CimInstance -CimClass $cimTrigger -ClientOnly
$trigger.Enabled      = $true
$trigger.Subscription = $eventXml

$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask `
    -TaskName  $taskName `
    -Action    $action `
    -Trigger   $trigger `
    -Principal $principal `
    -Settings  $settings `
    -Force | Out-Null

Write-Host "Registered event-triggered task: $taskName" -ForegroundColor Green
