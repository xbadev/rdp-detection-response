<#
.SYNOPSIS
    Register the Phase 05 alert-only monitor as an event-triggered task.

.DESCRIPTION
    Optional. Install.ps1 registers the Phase 06 responder by default. Run this
    to demo detection + alerting without containment. Running both tasks at
    once is fine: the monitor alerts, the responder blocks (and alerts too).

    Requires Install.ps1 to have run (uses the installed module and script).
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module 'C:\HomeLab\rdp-dr\lib\RdpDetection.psm1' -Force
Assert-Administrator
$cfg = Import-LabConfig

$scriptPath = Join-Path $cfg.InstallRoot 'scripts\rdp_bruteforce_monitor.ps1'
Register-LabEventTask -TaskName $cfg.MonitorTaskName -ScriptPath $scriptPath `
    -Description 'RDP lab Phase 05: alert-only monitor, runs on every Security 4625'

Write-Host "Registered '$($cfg.MonitorTaskName)': runs $scriptPath on every Security 4625." -ForegroundColor Green
Write-Host "Alert-only demo? Disable the responder: Disable-ScheduledTask -TaskName '$($cfg.ResponderTaskName)'"
