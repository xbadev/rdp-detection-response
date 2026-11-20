<#
.SYNOPSIS
    Remove the RDP Detection & Response lab.

.DESCRIPTION
    Unregisters both scheduled tasks, removes every responder firewall rule,
    and deletes C:\HomeLab\rdp-dr. Pass -KeepLogs to keep a copy of the log.
    The audit-policy change made by Install.ps1 (failed-logon auditing) is
    left on, since it's a sensible default on its own.
#>

[CmdletBinding()]
param([switch]$KeepLogs)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run Uninstall.ps1 from an elevated PowerShell." -ForegroundColor Red
    exit 1
}

$InstallRoot = 'C:\HomeLab\rdp-dr'
$taskNames = @('HomeLab-RDP-Responder', 'HomeLab-RDP-Monitor')
$fwPrefix  = 'HomeLab-RDPBan'

$cfgPath = "$InstallRoot\config\lab.config.psd1"
if (Test-Path $cfgPath) {
    try {
        $cfg = Import-PowerShellDataFile -Path $cfgPath
        $taskNames = @($cfg.ResponderTaskName, $cfg.MonitorTaskName)
        $fwPrefix  = $cfg.FirewallRulePrefix
    } catch { Write-Host "    (couldn't read installed config; using default names)" }
}

Write-Host "==> unregistering scheduled tasks"
foreach ($t in $taskNames) {
    Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false
}

Write-Host "==> removing firewall rules $fwPrefix-*"
Get-NetFirewallRule -DisplayName "$fwPrefix-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

if (Test-Path $InstallRoot) {
    if ($KeepLogs -and (Test-Path "$InstallRoot\logs")) {
        $backup = "C:\HomeLab\rdp-dr-logs-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Move-Item "$InstallRoot\logs" $backup
        Write-Host "    logs kept at $backup"
    }
    Write-Host "==> removing $InstallRoot"
    Remove-Item $InstallRoot -Recurse -Force
}

Write-Host "Uninstall complete." -ForegroundColor Green
