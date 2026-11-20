<#
.SYNOPSIS
    Phase 05 — RDP brute-force monitoring + Discord alerting (no firewall action).

.DESCRIPTION
    Same detection as Phase 04, but runs unattended and posts to Discord on
    threshold crossing. Stays silent during normal operation. Use this phase
    when you want visibility without containment — e.g. an SOC analyst
    triages alerts manually.

    Phase 06 (responder) supersedes this for full automation. They are
    deliberately split so the alert-only mode stays independently runnable.

.PARAMETER TestWebhook
    Send a test alert and exit. Useful for verifying webhook plumbing before
    enabling the event-triggered task.
#>

[CmdletBinding()]
param(
    [int]$MinutesBack,
    [int]$Threshold,
    [switch]$TestWebhook
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

if ($TestWebhook) {
    Send-LabWebhook ":white_check_mark: TEST: RDP monitor webhook is alive on $($cfg.TargetIp)."
    Write-Host "Test alert sent." -ForegroundColor Green
    exit 0
}

$records = Get-RdpFailedLogons -MinutesBack $MinutesBack
if ($records.Count -eq 0) {
    # Stay silent on quiet runs — no log spam.
    exit 0
}

$hits = Find-BruteForceBursts -Records $records -Threshold $Threshold
if ($hits.Count -eq 0) {
    Write-LabLog "OK: $($records.Count) failure(s), none over threshold ($Threshold/${MinutesBack}m)"
    exit 0
}

foreach ($h in $hits) {
    $msg = ":rotating_light: **RDP brute-force detected**`n" +
           "Host: ``$($cfg.TargetIp)```n" +
           "Source IP: ``$($h.SourceIp)```n" +
           "Target user: ``$($h.TargetUser)```n" +
           "Failures: ``$($h.Count)`` in ``${MinutesBack}m```n" +
           "Last seen: ``$($h.LastSeen.ToString('s'))``"

    Write-LabLog "SUSPECT: SourceIP=$($h.SourceIp) User=$($h.TargetUser) Failures=$($h.Count) Window=${MinutesBack}m"
    Send-LabWebhook $msg
}
