<#
.SYNOPSIS
    Reset the RDP lab state for a clean demo run.

.DESCRIPTION
    - Removes all firewall rules created by the responder (HomeLab-RDPBan-*)
    - Empties the banlist JSON
    - Truncates the log file
    - Leaves config, secrets, scripts, and the scheduled task in place

    Equivalent of 'make reset' in the SSH lab.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Reset.ps1 must be run elevated." -ForegroundColor Red
    exit 1
}

$cfg = Import-PowerShellDataFile -Path "$PSScriptRoot\lab.config.psd1"

Write-Host "==> removing firewall rules: $($cfg.FirewallRulePrefix)-*"
Get-NetFirewallRule -DisplayName "$($cfg.FirewallRulePrefix)-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

Write-Host "==> clearing banlist: $($cfg.BanListPath)"
if (Test-Path $cfg.BanListPath) {
    '[]' | Set-Content -Path $cfg.BanListPath -Encoding UTF8
}

Write-Host "==> truncating log: $($cfg.LogPath)"
if (Test-Path $cfg.LogPath) {
    Clear-Content -Path $cfg.LogPath
}

Write-Host ""
Write-Host "Reset complete. Ready for a clean demo run." -ForegroundColor Green
