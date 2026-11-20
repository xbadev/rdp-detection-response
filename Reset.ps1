<#
.SYNOPSIS
    Reset runtime state for a clean demo run.

.DESCRIPTION
    - Removes every responder firewall rule (HomeLab-RDPBan-*)
    - Empties the banlist and the Phase 05 alert cooldowns
    - Clears the lab log
    - Records the reset time, so detection ignores failures from before it
      (otherwise the previous attack's events, still inside the MinutesBack
      window, would count toward the next run)

    Config, secrets, scripts, and scheduled tasks are left alone.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module 'C:\HomeLab\rdp-dr\lib\RdpDetection.psm1' -Force
Assert-Administrator
$cfg = Import-LabConfig

Remove-AllLabFirewallRules
Save-LabBanList -List @()
if (Test-Path $cfg.AlertCooldownPath) { Remove-Item $cfg.AlertCooldownPath -Force }
if (Test-Path $cfg.LogPath) { Clear-Content $cfg.LogPath }
(Get-Date).ToString('s') | Set-Content -Path (Join-Path $cfg.StateDir 'last_reset.txt') -Encoding ASCII
Write-LabLog "RESET: bans, cooldowns, and log cleared; earlier failures will be ignored"

Write-Host "Reset complete: no bans, no cooldowns, empty log. Ready for a demo run." -ForegroundColor Green
