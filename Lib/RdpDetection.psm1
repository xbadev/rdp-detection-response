<#
.SYNOPSIS
    Shared detection logic for the RDP Detection & Response lab.

.DESCRIPTION
    All three operational scripts (Phase 04 detector, Phase 05 monitor,
    Phase 06 responder) import this module so the 4625 query, XML parse,
    grouping, and webhook delivery live in exactly one place.

    Loaded by:
        Import-Module $PSScriptRoot\..\Lib\RdpDetection.psm1

.NOTES
    PowerShell 5.1+ on Windows. Will not run on PowerShell Core / Linux —
    Get-WinEvent and New-NetFirewallRule are Windows-only cmdlets.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# --- Configuration loader ----------------------------------------

function Import-LabConfig {
    <#
    .SYNOPSIS
        Load lab.config.psd1 and return it as a hashtable.

    .PARAMETER ConfigPath
        Optional override. Defaults to $env:RDP_LAB_CONFIG, then to
        C:\HomeLab\rdp-dr\config\lab.config.psd1.
    #>
    param(
        [string]$ConfigPath
    )

    if (-not $ConfigPath) {
        if ($env:RDP_LAB_CONFIG) {
            $ConfigPath = $env:RDP_LAB_CONFIG
        } else {
            $ConfigPath = 'C:\HomeLab\rdp-dr\config\lab.config.psd1'
        }
    }

    if (-not (Test-Path $ConfigPath)) {
        throw "Lab config not found at: $ConfigPath. Run Install.ps1 or set `$env:RDP_LAB_CONFIG."
    }

    return Import-PowerShellDataFile -Path $ConfigPath
}


# --- Privilege check ---------------------------------------------

function Assert-Administrator {
    <#
    .SYNOPSIS
        Halt the script with a clear error if not running elevated.
        Required to read the Security event log and manage firewall rules.
    #>
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: This script must run elevated (Administrator)." -ForegroundColor Red
        exit 1
    }
}


# --- Logging -----------------------------------------------------

function Write-LabLog {
    <#
    .SYNOPSIS
        Append a timestamped line to the lab log file.

    .PARAMETER Message
        Free-form text. Convention: prefix with category in caps (e.g. "BAN:", "SKIP_PRIVATE:", "WEBHOOK_ERROR:").

    .PARAMETER Path
        Log file path. Defaults to lab config LogPath.
    #>
    param(
        [Parameter(Mandatory)] [string]$Message,
        [string]$Path
    )

    if (-not $Path) {
        $cfg = Import-LabConfig
        $Path = $cfg.LogPath
    }

    $dir = Split-Path $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $Path -Value $line
}


# --- 4625 ingestion ---------------------------------------------

function Get-RdpFailedLogons {
    <#
    .SYNOPSIS
        Pull recent RDP-style failed logons (Event ID 4625, LogonType 3)
        from the Security log and return them as flat objects.

    .PARAMETER MinutesBack
        How far back to look. Defaults to lab config.

    .OUTPUTS
        Array of pscustomobject with properties:
            TimeCreated, IpAddress, TargetUser, LogonType,
            Status, SubStatus, Workstation
        Returns empty array if no events match (does NOT throw).
    #>
    param(
        [int]$MinutesBack
    )

    if (-not $MinutesBack) {
        $cfg = Import-LabConfig
        $MinutesBack = $cfg.MinutesBack
    }

    $startTime = (Get-Date).AddMinutes(-$MinutesBack)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $startTime
        } -ErrorAction Stop
    } catch {
        # "No events were found..." is a normal outcome on a quiet box.
        if ($_.Exception.Message -match 'No events were found') {
            return @()
        }
        throw
    }

    $records = foreach ($e in $events) {
        $xml = [xml]$e.ToXml()

        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }

        # LogonType 3 = network logon (RDP failed auth, SMB, WMI, etc).
        # Filtering on this removes local console noise.
        if ($data['LogonType'] -ne '3') { continue }

        $ip = $data['IpAddress']

        # Skip empty / loopback markers.
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') {
            continue
        }

        [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            IpAddress   = $ip
            TargetUser  = $data['TargetUserName']
            LogonType   = $data['LogonType']
            Status      = $data['Status']
            SubStatus   = $data['SubStatus']
            Workstation = $data['WorkstationName']
        }
    }

    # PowerShell unwraps single-element arrays. Force array semantics.
    return @($records)
}


# --- Threshold detection ----------------------------------------

function Find-BruteForceBursts {
    <#
    .SYNOPSIS
        Group failed logon records by source IP + target user; return groups
        meeting or exceeding the threshold.

    .PARAMETER Records
        Output of Get-RdpFailedLogons.

    .PARAMETER Threshold
        Minimum count to flag. Defaults to lab config.

    .OUTPUTS
        Array of objects with: SourceIp, TargetUser, Count, FirstSeen, LastSeen, Records.
    #>
    param(
        [Parameter(Mandatory)] [array]$Records,
        [int]$Threshold
    )

    if (-not $Threshold) {
        $cfg = Import-LabConfig
        $Threshold = $cfg.Threshold
    }

    if ($Records.Count -eq 0) { return @() }

    $groups = $Records | Group-Object IpAddress, TargetUser

    $hits = foreach ($g in $groups) {
        if ($g.Count -lt $Threshold) { continue }

        $parts  = $g.Name -split ',\s*'
        $ip     = $parts[0]
        $user   = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        $sorted = $g.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            SourceIp   = $ip
            TargetUser = $user
            Count      = $g.Count
            FirstSeen  = $sorted[0].TimeCreated
            LastSeen   = $sorted[-1].TimeCreated
            Records    = $sorted
        }
    }

    return @($hits | Sort-Object Count -Descending)
}


# --- Webhook delivery -------------------------------------------

function Send-LabWebhook {
    <#
    .SYNOPSIS
        POST a Discord-compatible webhook message. Logs failures, never throws.

    .PARAMETER Message
        Plain text payload. Discord renders Markdown.
    #>
    param(
        [Parameter(Mandatory)] [string]$Message
    )

    $cfg = Import-LabConfig

    if (-not (Test-Path $cfg.WebhookFile)) {
        Write-LabLog "WEBHOOK_ERROR: webhook file not found: $($cfg.WebhookFile)"
        return
    }

    $url = (Get-Content $cfg.WebhookFile -ErrorAction Stop | Select-Object -First 1).Trim()
    if ([string]::IsNullOrWhiteSpace($url)) {
        Write-LabLog "WEBHOOK_ERROR: webhook file is empty"
        return
    }

    $payload = @{ content = $Message } | ConvertTo-Json -Compress

    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $payload -ContentType 'application/json' -TimeoutSec 10 | Out-Null
    } catch {
        Write-LabLog "WEBHOOK_ERROR: $($_.Exception.Message)"
    }
}


# --- IP classification ------------------------------------------

function Test-IsPrivateOrLocalIp {
    <#
    .SYNOPSIS
        True when the IP is in a private, link-local, or loopback range.

    .PARAMETER Ip
        Dotted quad or IPv6 string.
    #>
    param([Parameter(Mandatory)] [string]$Ip)

    if ($Ip -eq '-' -or $Ip -eq '::1' -or $Ip -eq '127.0.0.1') { return $true }

    # IPv6 link-local / unique-local
    if ($Ip -match '^fe80:' -or $Ip -match '^fc' -or $Ip -match '^fd') { return $true }

    # IPv4
    if ($Ip -match '^10\.') { return $true }
    if ($Ip -match '^192\.168\.') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($Ip -match '^169\.254\.') { return $true }

    return $false
}


# --- Allowlist --------------------------------------------------

function Get-LabAllowList {
    <#
    .SYNOPSIS
        Read the IP allowlist from disk. Lines starting with '#' are comments.
    #>
    param([string]$Path)

    if (-not $Path) {
        $cfg = Import-LabConfig
        $Path = $cfg.AllowListPath
    }

    if (-not (Test-Path $Path)) { return @() }

    $ips = @()
    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($t.StartsWith('#')) { continue }
        $ips += $t
    }
    return $ips
}


# --- Banlist (JSON, persistent) ---------------------------------

function Read-LabBanList {
    param([string]$Path)

    if (-not $Path) {
        $cfg = Import-LabConfig
        $Path = $cfg.BanListPath
    }

    if (-not (Test-Path $Path)) { return @() }

    try {
        $raw = Get-Content $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $data) { return @() }
        return @($data)
    } catch {
        Write-LabLog "BANLIST_READ_ERROR: $($_.Exception.Message)"
        return @()
    }
}

function Save-LabBanList {
    <#
    .SYNOPSIS
        Atomically write banlist JSON. Handles single-element edge case.
    #>
    param(
        [Parameter(Mandatory)] [array]$List,
        [string]$Path
    )

    if (-not $Path) {
        $cfg = Import-LabConfig
        $Path = $cfg.BanListPath
    }

    $arr = @($List)
    $tmp = "$Path.tmp"

    try {
        if ($arr.Count -eq 0) {
            '[]' | Set-Content -Path $tmp -Encoding UTF8
        } elseif ($arr.Count -eq 1) {
            # ConvertTo-Json on a single object emits a bare object, not an array.
            $one = $arr[0] | ConvertTo-Json -Depth 5
            "[`n$one`n]" | Set-Content -Path $tmp -Encoding UTF8
        } else {
            ($arr | ConvertTo-Json -Depth 5) | Set-Content -Path $tmp -Encoding UTF8
        }
        Move-Item -Path $tmp -Destination $Path -Force
    } catch {
        Write-LabLog "BANLIST_WRITE_ERROR: $($_.Exception.Message)"
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}


# --- Firewall enforcement ---------------------------------------

function Get-LabFirewallRuleName {
    param([Parameter(Mandatory)] [string]$Ip)
    $cfg = Import-LabConfig
    return "$($cfg.FirewallRulePrefix)-$Ip"
}

function Block-LabIp {
    <#
    .SYNOPSIS
        Create or recreate a Windows Firewall inbound block rule for TCP/3389
        from a single IP. Idempotent.
    #>
    param([Parameter(Mandatory)] [string]$Ip)

    $name = Get-LabFirewallRuleName -Ip $Ip

    try {
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

        New-NetFirewallRule `
            -DisplayName $name `
            -Direction Inbound `
            -Action Block `
            -Enabled True `
            -RemoteAddress $Ip `
            -Protocol TCP `
            -LocalPort 3389 | Out-Null
    } catch {
        Write-LabLog "FIREWALL_BLOCK_ERROR: Ip=$Ip Err=$($_.Exception.Message)"
    }
}

function Unblock-LabIp {
    param([Parameter(Mandatory)] [string]$Ip)

    $name = Get-LabFirewallRuleName -Ip $Ip
    try {
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {
        Write-LabLog "FIREWALL_UNBLOCK_ERROR: Ip=$Ip Err=$($_.Exception.Message)"
    }
}

function Remove-AllLabFirewallRules {
    <#
    .SYNOPSIS
        Operator helper: delete every firewall rule with the lab prefix.
    #>
    $cfg = Import-LabConfig
    Get-NetFirewallRule -DisplayName "$($cfg.FirewallRulePrefix)-*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
}


# --- Ban expiration ---------------------------------------------

function Remove-ExpiredBans {
    <#
    .SYNOPSIS
        Drop expired entries from the banlist and remove their firewall rules.

    .OUTPUTS
        The pruned banlist (still active entries only).
    #>
    param([Parameter(Mandatory)] [array]$BanList)

    $now  = Get-Date
    $kept = @()

    foreach ($b in $BanList) {
        $ip = $b.ip
        $expiresAt = $null
        try { $expiresAt = [datetime]$b.expiresAt } catch { $expiresAt = $null }

        if ([string]::IsNullOrWhiteSpace($ip) -or $null -eq $expiresAt) { continue }

        if ($expiresAt -le $now) {
            Unblock-LabIp -Ip $ip
            Write-LabLog "UNBAN: SourceIP=$ip ExpiredAt=$($expiresAt.ToString('s'))"
        } else {
            $kept += $b
        }
    }

    return @($kept)
}


# --- Module exports ---------------------------------------------

Export-ModuleMember -Function `
    Import-LabConfig, `
    Assert-Administrator, `
    Write-LabLog, `
    Get-RdpFailedLogons, `
    Find-BruteForceBursts, `
    Send-LabWebhook, `
    Test-IsPrivateOrLocalIp, `
    Get-LabAllowList, `
    Read-LabBanList, `
    Save-LabBanList, `
    Get-LabFirewallRuleName, `
    Block-LabIp, `
    Unblock-LabIp, `
    Remove-AllLabFirewallRules, `
    Remove-ExpiredBans
