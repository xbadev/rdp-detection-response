<#
.SYNOPSIS
    Phase 06 — RDP brute-force responder. Detects, blocks, alerts.

.DESCRIPTION
    Each invocation:
      1. Loads config (LabMode, paths, threshold, ban duration).
      2. Prunes expired bans (removes stale firewall rules).
      3. Pulls recent Event ID 4625 / LogonType 3 events.
      4. For any source IP over threshold:
           - Skip if already banned (no extension)
           - Skip if allowlisted
           - In production mode (LabMode=$false): skip private/local IPs
           - In lab mode (LabMode=$true): block private IPs too — needed
             for the lab because Kali (10.10.10.30) is private
         Then create a Windows Firewall block rule on TCP/3389 and post
         to Discord.
      5. Persist updated banlist.

    Designed to be invoked by an event-triggered scheduled task firing on
    Security/4625, so attacker-to-ban latency is a few seconds.

.PARAMETER ClearBans
    Operator helper: remove every HomeLab-RDPBan-* rule and reset banlist.
    Same effect as Reset.ps1 from the repo root. Kept here for backwards
    compatibility with the original script's interface.

.PARAMETER TestWebhook
    Send a test alert and exit.

.NOTES
    Reads config from $env:RDP_LAB_CONFIG (set by Install.ps1) or falls
    back to C:\HomeLab\rdp-dr\config\lab.config.psd1.
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
if (-not $BanMinutes)  { $BanMinutes  = $cfg.BanMinutes }

# --- Operator modes -------------------------------------------------
if ($ClearBans) {
    Remove-AllLabFirewallRules
    Save-LabBanList -List @()
    Write-LabLog "CLEAR_BANS: operator removed all rules + banlist via -ClearBans"
    Write-Host "OK: cleared all bans + firewall rules." -ForegroundColor Green
    exit 0
}

if ($TestWebhook) {
    Send-LabWebhook ":white_check_mark: TEST: RDP responder webhook is alive on $($cfg.TargetIp)."
    Write-Host "Test alert sent." -ForegroundColor Green
    exit 0
}

# --- Prune expired bans on every run --------------------------------
$banList = Read-LabBanList
$banList = Remove-ExpiredBans -BanList $banList
Save-LabBanList -List $banList

# --- Detection ------------------------------------------------------
$records = Get-RdpFailedLogons -MinutesBack $MinutesBack
if ($records.Count -eq 0) { exit 0 }

$hits = Find-BruteForceBursts -Records $records -Threshold $Threshold
if ($hits.Count -eq 0) {
    Write-LabLog "OK: $($records.Count) failure(s), none over threshold ($Threshold/${MinutesBack}m)"
    exit 0
}

$allow = Get-LabAllowList

foreach ($h in $hits) {
    $ip    = $h.SourceIp
    $user  = $h.TargetUser
    $count = $h.Count

    # 1. Allowlist always wins.
    if ($allow -contains $ip) {
        Write-LabLog "SKIP_ALLOWLIST: SourceIP=$ip User=$user Failures=$count"
        continue
    }

    # 2. Private/local — only skip in production mode.
    if ((-not $cfg.LabMode) -and (Test-IsPrivateOrLocalIp -Ip $ip)) {
        Write-LabLog "SKIP_PRIVATE_OR_LOCAL: SourceIP=$ip User=$user Failures=$count (LabMode=`$false)"
        continue
    }

    # 3. Already banned? Don't extend.
    $existing = $banList | Where-Object { $_.ip -eq $ip } | Select-Object -First 1
    if ($null -ne $existing) {
        $oldExp = [datetime]$existing.expiresAt
        Write-LabLog "ALREADY_BANNED_IGNORE: SourceIP=$ip User=$user Failures=$count Until=$($oldExp.ToString('s'))"
        continue
    }

    # 4. Apply the ban.
    $now     = Get-Date
    $expires = $now.AddMinutes($BanMinutes)

    $banList += [pscustomobject]@{
        ip        = $ip
        user      = $user
        count     = [int]$count
        firstSeen = $h.FirstSeen.ToString('s')
        lastSeen  = $h.LastSeen.ToString('s')
        expiresAt = $expires.ToString('s')
    }

    Block-LabIp -Ip $ip

    Write-LabLog "BAN: SourceIP=$ip User=$user Failures=$count Window=${MinutesBack}m Until=$($expires.ToString('s'))"

    $msg = ":no_entry: **RDP attacker blocked**`n" +
           "Host: ``$($cfg.TargetIp)```n" +
           "Banned IP: ``$ip```n" +
           "Target user: ``$user```n" +
           "Failures: ``$count`` in ``${MinutesBack}m```n" +
           "Block duration: ``${BanMinutes}m```n" +
           "Expires: ``$($expires.ToString('s'))``"
    Send-LabWebhook $msg
}

Save-LabBanList -List $banList
