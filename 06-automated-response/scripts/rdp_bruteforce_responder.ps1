<#
.SYNOPSIS
    Phase 06 - RDP brute-force responder: detect, block, alert.

.DESCRIPTION
    Run by the event-triggered scheduled task on every Security 4625. Each run:
      1. Prunes expired bans (removes their firewall rules).
      2. Reads recent 4625 / LogonType 3+10 failures.
      3. For each (source IP, user) at or over the threshold:
           allowlisted               -> skip, log
           private IP and !LabMode   -> skip, log
           already banned            -> skip, log (bans are not extended)
           otherwise                 -> firewall block on TCP/3389, record the
                                        ban with an expiry, post to the webhook
      4. Saves the banlist.

    Idempotent: a burst of events runs this several times (the task queues
    them), and every run after the first finds the IP already banned.

.PARAMETER ClearBans
    Remove every lab firewall rule and empty the banlist (same as Reset.ps1,
    minus the log/cooldown reset).

.PARAMETER TestWebhook
    Send a test message and exit.

.NOTES
    Must run elevated. Reads C:\HomeLab\rdp-dr\config\lab.config.psd1.
#>

[CmdletBinding()]
param(
    [int]$MinutesBack,
    [int]$Threshold,
    [int]$BanMinutes,
    [switch]$TestWebhook,
    [switch]$ClearBans
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
if (-not $BanMinutes)  { $BanMinutes  = $cfg.BanMinutes }

# --- Operator modes -------------------------------------------------
if ($ClearBans) {
    Remove-AllLabFirewallRules
    Save-LabBanList -List @()
    Write-LabLog "CLEAR_BANS: all lab firewall rules and the banlist removed by operator"
    Write-Host "OK: cleared all bans and firewall rules." -ForegroundColor Green
    exit 0
}

if ($TestWebhook) {
    $ok = Send-LabWebhook ":white_check_mark: TEST: RDP responder on $($cfg.TargetIp) can reach this webhook."
    if ($ok) { Write-Host "Test alert sent." -ForegroundColor Green; exit 0 }
    Write-Host "Webhook failed; see $($cfg.LogPath)" -ForegroundColor Red
    exit 1
}

# --- 1. Prune expired bans -----------------------------------------
$banList = @(Remove-ExpiredBans -BanList @(Read-LabBanList))
Save-LabBanList -List $banList

# --- 2. Detection --------------------------------------------------
$records = @(Get-RdpFailedLogons -MinutesBack $MinutesBack)
if ($records.Count -eq 0) { exit 0 }

$hits = @(Find-BruteForceBursts -Records $records -Threshold $Threshold)
if ($hits.Count -eq 0) {
    Write-LabLog "OK: $($records.Count) failure(s) in ${MinutesBack}m, none at threshold $Threshold"
    exit 0
}

# --- 3. Decide per offender ----------------------------------------
$allow = @(Get-LabAllowList)

foreach ($h in $hits) {
    $ip, $user, $count = $h.SourceIp, $h.TargetUser, $h.Count

    if ($allow -contains $ip) {
        Write-LabLog "SKIP_ALLOWLIST: SourceIP=$ip User=$user Failures=$count"
        continue
    }

    if ((-not $cfg.LabMode) -and (Test-IsPrivateOrLocalIp -Ip $ip)) {
        Write-LabLog "SKIP_PRIVATE_OR_LOCAL: SourceIP=$ip User=$user Failures=$count (LabMode is off)"
        continue
    }

    $existing = @($banList | Where-Object { $_.ip -eq $ip })
    if ($existing.Count -gt 0) {
        Write-LabLog "ALREADY_BANNED: SourceIP=$ip User=$user Failures=$count Until=$($existing[0].expiresAt)"
        continue
    }

    if (-not (Block-LabIp -Ip $ip)) {
        # Don't record a ban that isn't actually enforced; the next run retries.
        continue
    }

    $expires = (Get-Date).AddMinutes($BanMinutes)
    $banList += [pscustomobject]@{
        ip        = $ip
        user      = $user
        count     = [int]$count
        firstSeen = $h.FirstSeen.ToString('s')
        lastSeen  = $h.LastSeen.ToString('s')
        expiresAt = $expires.ToString('s')
    }
    Save-LabBanList -List $banList   # persist before the (slower) webhook call

    $latency = [int]((Get-Date) - $h.LastSeen).TotalSeconds
    Write-LabLog "BAN: SourceIP=$ip User=$user Failures=$count Window=${MinutesBack}m Until=$($expires.ToString('s')) SecondsAfterLastFailure=$latency"

    $msg = ":no_entry: **RDP attacker blocked**`n" +
           "Host: ``$($cfg.TargetIp)```n" +
           "Banned IP: ``$ip```n" +
           "Target user: ``$user```n" +
           "Failures: ``$count`` in ``${MinutesBack}m```n" +
           "Blocked for: ``${BanMinutes}m`` (until ``$($expires.ToString('s'))``)"
    [void](Send-LabWebhook $msg)
}
