<#
.SYNOPSIS
    Phase 04 - on-demand RDP brute-force detection (read-only).

.DESCRIPTION
    Pulls recent Security 4625 failures (LogonType 3 or 10), groups them by
    (source IP, target user), and prints the groups at or over the threshold.
    No alerting, no firewall changes: this is the diagnostic tool. The
    Phase 05 monitor and Phase 06 responder call the same module functions.

.PARAMETER MinutesBack
    Look-back window. Default: MinutesBack from lab config.

.PARAMETER Threshold
    Failures needed to flag a group. Default: Threshold from lab config.

.EXAMPLE
    .\rdp_bruteforce_detection.ps1
    .\rdp_bruteforce_detection.ps1 -MinutesBack 30 -Threshold 3
#>

[CmdletBinding()]
param(
    [int]$MinutesBack,
    [int]$Threshold
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$module = @('C:\HomeLab\rdp-dr\lib\RdpDetection.psm1',
            (Join-Path $PSScriptRoot '..\..\Lib\RdpDetection.psm1')) |
          Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $module) {
    Write-Host "ERROR: RdpDetection.psm1 not found. Run Install.ps1 first." -ForegroundColor Red
    exit 2
}
Import-Module $module -Force

Assert-Administrator
$cfg = Import-LabConfig
if (-not $MinutesBack) { $MinutesBack = $cfg.MinutesBack }
if (-not $Threshold)   { $Threshold   = $cfg.Threshold }

Write-Host "Window: last $MinutesBack minute(s). Threshold: $Threshold failures per source IP + user."

$records = @(Get-RdpFailedLogons -MinutesBack $MinutesBack)
if ($records.Count -eq 0) {
    Write-Host "OK: no failed RDP/network logons with a source IP in the window." -ForegroundColor Green
    exit 0
}

$hits = @(Find-BruteForceBursts -Records $records -Threshold $Threshold)
if ($hits.Count -eq 0) {
    Write-Host "OK: $($records.Count) failure(s) in the window; no source/user pair reached $Threshold."
    $records | Group-Object IpAddress, TargetUser | Sort-Object Count -Descending |
        Select-Object Count, Name | Format-Table -AutoSize
    exit 0
}

Write-Host ""
Write-Host "SUSPECT: $($hits.Count) source/user pair(s) at or over the threshold." -ForegroundColor Red
foreach ($h in $hits) {
    Write-Host ""
    Write-Host ("Source IP:     {0}" -f $h.SourceIp)
    Write-Host ("Target user:   {0}" -f $h.TargetUser)
    Write-Host ("Failures:      {0}" -f $h.Count)
    Write-Host ("First / last:  {0}  /  {1}" -f $h.FirstSeen, $h.LastSeen)
    $h.Records | Sort-Object TimeCreated -Descending | Select-Object -First 5 `
        TimeCreated, IpAddress, TargetUser, LogonType, Status, SubStatus, Workstation |
        Format-Table -AutoSize
}
