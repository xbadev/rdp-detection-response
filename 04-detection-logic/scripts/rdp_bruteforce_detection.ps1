<#
.SYNOPSIS
    Phase 04 — interactive RDP brute-force detection.

.DESCRIPTION
    Standalone, on-demand version of the detection logic. Pulls recent
    Event ID 4625 / LogonType 3 records, groups by source IP + target user,
    and prints any groups that exceed the threshold.

    This script does NOT alert and does NOT respond — it's the diagnostic
    /demo tool. Phase 05 (monitor) and Phase 06 (responder) reuse the same
    underlying functions from Lib\RdpDetection.psm1.

.PARAMETER MinutesBack
    Time window. Defaults to lab config (typically 2).

.PARAMETER Threshold
    Failure count to flag. Defaults to lab config (typically 5).

.EXAMPLE
    PS C:\> .\rdp_bruteforce_detection.ps1
    PS C:\> .\rdp_bruteforce_detection.ps1 -MinutesBack 10 -Threshold 3

.NOTES
    Must run elevated. Reads C:\HomeLab\rdp-dr\config\lab.config.psd1
    (or $env:RDP_LAB_CONFIG override).
#>

[CmdletBinding()]
param(
    [int]$MinutesBack,
    [int]$Threshold
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve module path: production path first, then repo path during dev.
$modulePaths = @(
    'C:\HomeLab\rdp-dr\lib\RdpDetection.psm1',
    (Join-Path $PSScriptRoot '..\..\Lib\RdpDetection.psm1')
)
$module = $modulePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $module) {
    Write-Host "ERROR: RdpDetection.psm1 not found. Run Install.ps1 first." -ForegroundColor Red
    exit 2
}
Import-Module $module -Force

Assert-Administrator
$cfg = Import-LabConfig

if (-not $MinutesBack) { $MinutesBack = $cfg.MinutesBack }
if (-not $Threshold)   { $Threshold   = $cfg.Threshold }

Write-Host "Looking back $MinutesBack minute(s); threshold $Threshold failures."

$records = Get-RdpFailedLogons -MinutesBack $MinutesBack
if ($records.Count -eq 0) {
    Write-Host "OK: No failed RDP logons in the window." -ForegroundColor Green
    exit 0
}

$hits = Find-BruteForceBursts -Records $records -Threshold $Threshold
if ($hits.Count -eq 0) {
    Write-Host "OK: $($records.Count) failure(s) seen, but no source crossed the threshold."
    exit 0
}

Write-Host ""
Write-Host "SUSPECT: $($hits.Count) source/user pair(s) above threshold." -ForegroundColor Red
foreach ($h in $hits) {
    Write-Host ""
    Write-Host "Source IP:        $($h.SourceIp)"
    Write-Host "Target User:      $($h.TargetUser)"
    Write-Host "Failed Attempts:  $($h.Count)"
    Write-Host "First seen:       $($h.FirstSeen)"
    Write-Host "Last seen:        $($h.LastSeen)"

    $h.Records |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 5 TimeCreated, IpAddress, TargetUser, Status, SubStatus, Workstation |
        Format-Table -AutoSize
}
