<#
.SYNOPSIS
    Phase 05 - RDP brute-force monitor: detect and alert, no firewall action.

.DESCRIPTION
    Same detection as Phase 04, run unattended by an event-triggered task, posting
    to the webhook when a (source IP, user) pair crosses the threshold. Each
    source IP alerts at most once per AlertCooldownMinutes; without that, every
    4625 during an attack would post another copy of the same alert.

    Phase 06 adds containment. The monitor stays separate so alert-only mode
    (an analyst decides what to block) remains runnable on its own.

.PARAMETER TestWebhook
    Send a test message and exit.
#>

[CmdletBinding()]
param(
    [int]$MinutesBack,
    [int]$Threshold,
    [switch]$TestWebhook
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

if ($TestWebhook) {
    $ok = Send-LabWebhook ":white_check_mark: TEST: RDP monitor on $($cfg.TargetIp) can reach this webhook."
    if ($ok) { Write-Host "Test alert sent." -ForegroundColor Green; exit 0 }
    Write-Host "Webhook failed; see $($cfg.LogPath)" -ForegroundColor Red
    exit 1
}

$records = @(Get-RdpFailedLogons -MinutesBack $MinutesBack)
if ($records.Count -eq 0) { exit 0 }

$hits = @(Find-BruteForceBursts -Records $records -Threshold $Threshold)
if ($hits.Count -eq 0) { exit 0 }

foreach ($h in $hits) {
    if (Test-LabAlertCooldown -Key $h.SourceIp) { continue }

    Write-LabLog "SUSPECT: SourceIP=$($h.SourceIp) User=$($h.TargetUser) Failures=$($h.Count) Window=${MinutesBack}m"

    $msg = ":rotating_light: **RDP brute-force detected**`n" +
           "Host: ``$($cfg.TargetIp)```n" +
           "Source IP: ``$($h.SourceIp)```n" +
           "Target user: ``$($h.TargetUser)```n" +
           "Failures: ``$($h.Count)`` in ``${MinutesBack}m```n" +
           "Last seen: ``$($h.LastSeen.ToString('s'))``"
    if (Send-LabWebhook $msg) {
        Set-LabAlertCooldown -Key $h.SourceIp
    }
}
