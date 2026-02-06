<#
Script: rdp_bruteforce_responder.ps1

Purpose
- Automated RDP brute-force response on a Windows endpoint using native telemetry.
- Reads Windows Security Event Log (Event ID 4625) to find repeated failed network logons
  within a short time window, then automatically applies a temporary containment action.

High-level flow
1) Validate prerequisites:
   - Script must run elevated (Administrator) to read Security log and manage firewall rules.
   - Discord webhook URL must exist at: C:\homelab\secrets\discord_webhook_url.txt
2) Create and ensure required directories/files:
   - Logs:   C:\homelab\logs\rdp_monitor.log
   - State:  C:\homelab\state\rdp_banlist.json
   - Config: C:\homelab\config\rdp_allowlist.txt
3) Load allowlist + banlist state:
   - Prune expired bans each run (removes firewall rules when ban expires).
   - Persist updated banlist back to disk.
4) Query recent 4625 events (last $MinutesBack minutes):
   - Parses event XML and filters to LogonType 3 (network logons).
   - Groups by Source IP + Target username and flags groups at/over $Threshold.
5) Response (containment):
   - Skips allowlisted IPs and local/private ranges for safety.
   - If IP is already banned, it logs and ignores it (no ban extension).
   - Otherwise, creates a Windows Firewall inbound block rule for TCP/3389 and records
     the ban in rdp_banlist.json with an expiration timestamp.
   - Sends a Discord alert for each new ban.

Inputs (parameters)
- MinutesBack: How far back to query failed logons.
- Threshold:   Minimum failures in the window to trigger response.
- BanMinutes:  How long to block an offending source IP.
- BanListPath: Persistent state file (JSON array of ban entries).
- AllowListPath: IP allowlist file (one IP per line, # comments allowed).
- TestWebhook: Send a test Discord message then exit.
- ClearBans:   Remove all firewall rules created by this script and reset banlist.json.

Outputs
- Log file:      C:\homelab\logs\rdp_monitor.log
- Firewall rules: DisplayName "Homelab-RDPBan-<IP>" (inbound block, TCP/3389)
- State file:    C:\homelab\state\rdp_banlist.json (persists historical + active bans)
- Discord alerts: One message per new ban.

Safety notes
- The allowlist exists to prevent self-lockouts. Add your management IPs there.
- Private/local IP filtering is intentionally conservative (customize carefully).
- This script is designed to be run repeatedly (scheduled task) and remain idempotent:
  it cleans up expired rules and avoids re-banning already banned IPs during the ban window.
#>

param(
    [int]$MinutesBack = 2,
    [int]$Threshold   = 5,
    [switch]$TestWebhook,
    [int]$BanMinutes = 30,
    [string]$BanListPath = "C:\homelab\state\rdp_banlist.json",
    [string]$AllowListPath = "C:\homelab\config\rdp_allowlist.txt",
    [switch]$ClearBans
)

$LogPath = "C:\homelab\logs\rdp_monitor.log"
# if log file don't exist
$LogDir = Split-Path $LogPath
if (-not (Test-Path $LogDir)) { 
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null 
}

$StateDir = Split-Path $BanListPath
if (-not (Test-Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}

$ConfigDir = Split-Path $AllowListPath
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

# Create starter allowlist and banlist if missing
if (-not (Test-Path $AllowListPath)) {
    @(
        "# One IP per line. Lines starting with # are comments.",
        "# Add your own management IPs here so you never block yourself.",
        "127.0.0.1",
        "::1"
    ) | Set-Content -Path $AllowListPath -Encoding UTF8
}
if (-not (Test-Path $BanListPath)) {
    "[]" | Set-Content -Path $BanListPath -Encoding UTF8
}

# Windows Firewall rule name prefix used by this script
$FwRulePrefix = "Homelab-RDPBan"


function Write-LogLine {
    param([string]$Message)

    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogPath -Value $line
}

# Operator utility mode: remove all script-created firewall rules and reset state.
if ($ClearBans) {
    Get-NetFirewallRule -DisplayName "$FwRulePrefix-*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

    "[]" | Set-Content -Path $BanListPath -Encoding UTF8
    Write-LogLine "CLEAR_BANS: Removed all $FwRulePrefix rules and reset banlist."
    Write-Host "OK: Cleared all bans and removed firewall rules for prefix: $FwRulePrefix"
    exit 0
}


function Get-AllowList {
    $ips = @()
    try {
        $raw = Get-Content $AllowListPath -ErrorAction Stop
        foreach ($line in $raw) {
            $t = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            if ($t.StartsWith("#")) { continue }
            $ips += $t
        }
    } catch {
        Write-LogLine "ALLOWLIST_ERROR: $($_.Exception.Message)"
    }
    return $ips
}

function Load-BanList {
    try {
        $json = Get-Content $BanListPath -Raw -ErrorAction Stop
        $data = $json | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $data) { return @() }
        return @($data)
    } catch {
        Write-LogLine "BANLIST_READ_ERROR: $($_.Exception.Message)"
        return @()
    }
}

# Writes banlist.json in a consistent array format, including the single-entry edge case.
function Save-BanList {
    param([array]$List)

    try {
        $arr = @($List)

        if ($arr.Count -eq 0) {
            "[]" | Set-Content -Path $BanListPath -Encoding UTF8
            return
        }

        if ($arr.Count -eq 1) {
            $one = $arr[0] | ConvertTo-Json -Depth 5
            ("[" + $one + "]") | Set-Content -Path $BanListPath -Encoding UTF8
            return
        }

        ($arr | ConvertTo-Json -Depth 5) | Set-Content -Path $BanListPath -Encoding UTF8
    } catch {
        Write-LogLine "BANLIST_WRITE_ERROR: $($_.Exception.Message)"
    }
}



function Is-IpAllowlisted {
    param([string]$Ip, [string[]]$Allow)
    return $Allow -contains $Ip
}

function Is-PrivateOrLocalIp {
    param([string]$Ip)

    # Skip obvious local markers
    if ($Ip -eq '-' -or $Ip -eq '::1' -or $Ip -eq '127.0.0.1') { return $true }

    # IPv6 local link or unique local address
    if ($Ip -match '^fe80:' -or $Ip -match '^fc' -or $Ip -match '^fd') { return $true }

    # IPv4 private ranges. Comment if want to ignore
    if ($Ip -match '^10\.' ) { return $true } 
    if ($Ip -match '^192\.168\.' ) { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' ) { return $true }
    if ($Ip -match '^169\.254\.' ) { return $true }

    return $false
}

function Get-FwRuleName {
    param([string]$Ip)
    return "$FwRulePrefix-$Ip"
}

function Ensure-BlockedIp {
    param([string]$Ip)

    $ruleName = Get-FwRuleName -Ip $Ip

    try {
        # Idempotent behavior: remove any existing rule with the same name, then recreate cleanly.
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Block `
            -Enabled True `
            -RemoteAddress $Ip `
            -Protocol TCP `
            -LocalPort 3389 `
            | Out-Null
    }
    catch {
        Write-LogLine "FIREWALL_BLOCK_ERROR: Ip=$Ip Err=$($_.Exception.Message)"
    }
}


function Remove-BlockedIp {
    param([string]$Ip)

    $ruleName = Get-FwRuleName -Ip $Ip
    try {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {
        Write-LogLine "FIREWALL_UNBLOCK_ERROR: Ip=$Ip Err=$($_.Exception.Message)"
    }
}

# Removes expired bans from state and also removes their firewall rules.
function Prune-ExpiredBans {
    param([array]$BanList)

    $now = Get-Date
    $kept = @()

    foreach ($b in $BanList) {
        # Expected fields: ip, expiresAt
        $ip = $b.ip
        $expiresAt = $null
        try { $expiresAt = [datetime]$b.expiresAt } catch { $expiresAt = $null }

        if ([string]::IsNullOrWhiteSpace($ip) -or $null -eq $expiresAt) { continue }

        if ($expiresAt -le $now) {
            Remove-BlockedIp -Ip $ip
            Write-LogLine "UNBAN: SourceIP=$ip ExpiredAt=$($expiresAt.ToString('s'))"
        } else {
            $kept += $b
        }
    }

    return $kept
}


$StartTime = (Get-Date).AddMinutes(-$MinutesBack)

# Must run elevated to read the Security log
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "ERROR: Run PowerShell as Administrator to read the Security log." -ForegroundColor Red
    exit 1
}

$WebhookFile = "C:\homelab\secrets\discord_webhook_url.txt"

if (-not (Test-Path $WebhookFile)) {
    Write-Host "ERROR: Webhook URL file not found: $WebhookFile" -ForegroundColor Red
    exit 2
}

$WebhookUrl = Get-Content $WebhookFile -ErrorAction Stop | Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
    Write-Host "ERROR: Webhook URL file is empty." -ForegroundColor Red
    exit 2
}

function Send-DiscordWebhook {
    param([string]$Message)
    
    # Simple payload creation
    $payload = @{ content = $Message } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType "application/json" | Out-Null
    } catch {
        Write-LogLine "WEBHOOK_ERROR: $($_.Exception.Message)"
    }
}

# One-shot mode to validate your webhook plumbing without generating security events.
if ($TestWebhook) {
    Send-DiscordWebhook "TEST: Windows RDP monitor webhook is working."
    Write-Host "OK: Test alert sent to Discord."
    exit 0
}

# Load allowlist + banlist, remove expired bans each run, and persist the cleaned state.
$Allow = Get-AllowList
$BanList = Load-BanList
$BanList = @($BanList)
$BanList = Prune-ExpiredBans -BanList $BanList
$BanList = @($BanList)
Save-BanList -List $BanList


# Pull recent 4625 events from the Security log
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $StartTime
    } -ErrorAction Stop
}
catch {
    # "No events were found..." is a normal outcome when the time window is quiet
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "OK: No failed logons (4625) found in the last $MinutesBack minutes."
        exit 0
    }

    Write-Host "ERROR: Failed to query Security log (4625). Details: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}



# Extract only the fields we need from the event XML
$records = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()

    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    # LogonType 3 = network logon (for failed RDP auth attempts)
    if ($data['LogonType'] -ne '3') { continue }

    $ip   = $data['IpAddress']
    $user = $data['TargetUserName']

    # Skip empty / localhost style entries
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { continue }

    [pscustomobject]@{
        TimeCreated   = $e.TimeCreated
        IpAddress     = $ip
        TargetUser    = $user
        LogonType     = $data['LogonType']
        Status        = $data['Status']
        SubStatus     = $data['SubStatus']
        Workstation   = $data['WorkstationName']
    }
}

# Group and flag suspicious bursts
$hits = $records |
    Group-Object IpAddress, TargetUser |
    Where-Object { $_.Count -ge $Threshold } |
    Sort-Object Count -Descending

if (-not $hits) {
    Write-Host "OK: No suspicious rdp activity detected. No alerts sent. Details logged to rdp_monitor.log."
    Write-LogLine "OK: Someone attempted rdp, but no suspicious bursts (Threshold=$Threshold Window=${MinutesBack}m)"
    exit 0
}

Write-Host "SUSPECT: Possible RDP brute-force activity detected!" -ForegroundColor Red

foreach ($h in $hits) {
    $parts = $h.Name -split ',\s*'
    $ip = $parts[0]
    $user = $parts[1]
    $count = $h.Count

    # Safety: never block allowlisted IPs or private/local ranges
    if (Is-IpAllowlisted -Ip $ip -Allow $Allow) {
        Write-LogLine "SKIP_ALLOWLIST: SourceIP=$ip User=$user Failures=$count"
        continue
    }
    if (Is-PrivateOrLocalIp -Ip $ip) {
        Write-LogLine "SKIP_PRIVATE_OR_LOCAL: SourceIP=$ip User=$user Failures=$count"
        continue
    }

    $now = Get-Date
    $expires = $now.AddMinutes($BanMinutes)

    # Check if already banned (ignore, no extend, no firewall update)
    $existing = $BanList | Where-Object { $_.ip -eq $ip } | Select-Object -First 1
    if ($null -ne $existing) {
        $oldExp = [datetime]$existing.expiresAt
        Write-LogLine "ALREADY_BANNED_IGNORE: SourceIP=$ip User=$user Failures=$count Until=$($oldExp.ToString('s'))"
        continue
    }

    # New ban entry
    $BanList += [pscustomobject]@{
        ip        = $ip
        user      = $user
        count     = [int]$count
        firstSeen = $now.ToString("s")
        lastSeen  = $now.ToString("s")
        expiresAt = $expires.ToString("s")
    }

    Ensure-BlockedIp -Ip $ip

    Write-LogLine "BAN: SourceIP=$ip User=$user Failures=$count Window=${MinutesBack}m Until=$($expires.ToString('s'))"
    Send-DiscordWebhook "BAN: RDP brute-force from $ip targeting $user ($count failures in ${MinutesBack}m). Blocked for ${BanMinutes}m."
}

Save-BanList -List $BanList

$hits | ForEach-Object {
    $parts = $_.Name -split ',\s*'
    $ip = $parts[0]
    $user = $parts[1]

    Write-Host ""
    Write-Host "Source IP: $ip"
    Write-Host "Target User: $user"
    Write-Host "Failed Attempts: $($_.Count)"

    # Show the most recent few events for context
    $records |
        Where-Object { $_.IpAddress -eq $ip -and $_.TargetUser -eq $user } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 5 TimeCreated, IpAddress, TargetUser, Status, SubStatus, Workstation |
        Format-Table -AutoSize
}
