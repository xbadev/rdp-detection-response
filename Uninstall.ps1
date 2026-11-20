<#
.SYNOPSIS
    Uninstall the RDP Detection & Response lab.

.DESCRIPTION
    - Unregisters the event-triggered scheduled task
    - Removes all firewall rules created by the responder
    - Removes C:\HomeLab\rdp-dr\ tree (config, scripts, logs, state, secrets)
    - Removes the RDP_LAB_CONFIG environment variable

    Pass -KeepLogs to preserve C:\HomeLab\rdp-dr\logs\
#>

[CmdletBinding()]
param(
    [switch]$KeepLogs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Uninstall.ps1 must be run elevated." -ForegroundColor Red
    exit 1
}

$InstallRoot = 'C:\HomeLab\rdp-dr'

# Try to read config for task names + firewall prefix; fall back to defaults if missing.
$taskNames = @('HomeLab-RDP-Detector', 'HomeLab-RDP-Responder')
$fwPrefix  = 'HomeLab-RDPBan'
if (Test-Path "$InstallRoot\config\lab.config.psd1") {
    try {
        $cfg = Import-PowerShellDataFile -Path "$InstallRoot\config\lab.config.psd1"
        $taskNames = @($cfg.DetectorTaskName, $cfg.ResponderTaskName)
        $fwPrefix  = $cfg.FirewallRulePrefix
    } catch { }
}

Write-Host "==> unregistering scheduled tasks"
foreach ($t in $taskNames) {
    Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "==> removing firewall rules: $fwPrefix-*"
Get-NetFirewallRule -DisplayName "$fwPrefix-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

Write-Host "==> removing $InstallRoot"
if (Test-Path $InstallRoot) {
    if ($KeepLogs -and (Test-Path "$InstallRoot\logs")) {
        $backup = "C:\HomeLab\rdp-dr-logs-backup-$(Get-Date -Format 'yyyyMMddHHmmss')"
        Move-Item "$InstallRoot\logs" $backup
        Write-Host "    logs preserved at $backup"
    }
    Remove-Item -Path $InstallRoot -Recurse -Force
}

Write-Host "==> clearing RDP_LAB_CONFIG environment variable"
[Environment]::SetEnvironmentVariable('RDP_LAB_CONFIG', $null, 'Machine')

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
