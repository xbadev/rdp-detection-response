<#
.SYNOPSIS
    (Re-)register the Phase 06 responder as an event-triggered task.

.DESCRIPTION
    Install.ps1 already does this. Use this after editing the installed
    responder, or to walk through the task setup on its own. The trigger
    fires on every Security 4625; queued runs guarantee the full burst of an
    attack is evaluated (see Register-LabEventTask in Lib\RdpDetection.psm1).
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module 'C:\HomeLab\rdp-dr\lib\RdpDetection.psm1' -Force
Assert-Administrator
$cfg = Import-LabConfig

$scriptPath = Join-Path $cfg.InstallRoot 'scripts\rdp_bruteforce_responder.ps1'
Register-LabEventTask -TaskName $cfg.ResponderTaskName -ScriptPath $scriptPath `
    -Description 'RDP lab Phase 06: detect, block, alert; runs on every Security 4625 and every 5 min to expire bans' -SweepMinutes 5

Write-Host "Registered '$($cfg.ResponderTaskName)': runs $scriptPath on every Security 4625 and every 5 minutes." -ForegroundColor Green
