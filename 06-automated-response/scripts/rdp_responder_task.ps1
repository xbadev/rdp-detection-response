<#
.SYNOPSIS
    Register the Phase 06 responder as an event-triggered scheduled task.

.DESCRIPTION
    Install.ps1 already does this — this script exists for two reasons:
    (1) re-registering after manually editing the responder, without rerunning
    full install; (2) demonstrating the task setup standalone, which is part of
    the Phase 06 narrative for an interview walkthrough.

    The task fires on every Security/4625 event, so attacker-to-block latency
    is ~2-5 seconds rather than the 2-minute polling interval the original
    repo used.
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

$taskName = $cfg.ResponderTaskName
$script   = "$($cfg.InstallRoot)\scripts\rdp_bruteforce_responder.ps1"

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
Write-Host "Trigger: every Security/4625 event"
