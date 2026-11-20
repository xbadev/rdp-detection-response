<#
.SYNOPSIS
    Shared logic for the RDP Detection & Response lab.

.DESCRIPTION
    Every operational script (Phase 04 detector, Phase 05 monitor, Phase 06
    responder, Install/Reset) imports this module, so 4625 ingestion,
    threshold logic, webhook delivery, banlist state, firewall changes, and
    scheduled-task registration each live in exactly one place.

.NOTES
    Windows PowerShell 5.1 (built into Windows Server). Uses Windows-only
    cmdlets: Get-WinEvent, *-NetFirewallRule, *-ScheduledTask.

    CALLING CONVENTION: functions that return collections emit their items
    to the pipeline. PowerShell turns zero items into $null and one item into
    a scalar, so callers MUST wrap the call in @(...):
        $records = @(Get-RdpFailedLogons)
    Under Set-StrictMode -Version Latest, calling .Count on $null throws,
    so skipping the @() is a crash, not just a style issue.

    The flip side: inside a function that returns a collection, ANY output
    not captured becomes part of the result. Helper calls in those functions
    are assigned to $null (`$null = Write-LabLog ...`) so a helper that
    starts emitting something can't leak into the returned items.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefaultConfigPath = 'C:\HomeLab\rdp-dr\config\lab.config.psd1'
$script:LabConfig = $null

# Event-trigger subscription: every Security 4625 (failed logon).
$script:EventSubscriptionXml = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>
'@


# --- Configuration -----------------------------------------------

function Import-LabConfig {
    <#
    .SYNOPSIS
        Load lab.config.psd1 (cached after the first call in a process).

    .PARAMETER ConfigPath
        Override. Defaults to $env:RDP_LAB_CONFIG, then the installed path.
    #>
    param([string]$ConfigPath)

    if (-not $ConfigPath -and $null -ne $script:LabConfig) {
        return $script:LabConfig
    }
    if (-not $ConfigPath) {
        $ConfigPath = if ($env:RDP_LAB_CONFIG) { $env:RDP_LAB_CONFIG } else { $script:DefaultConfigPath }
    }
    if (-not (Test-Path $ConfigPath)) {
        throw "Lab config not found at $ConfigPath. Run Install.ps1 first."
    }
    $script:LabConfig = Import-PowerShellDataFile -Path $ConfigPath
    return $script:LabConfig
}


# --- Privilege check ---------------------------------------------

function Assert-Administrator {
    <# Exit with a clear message unless elevated (Security log + firewall need it). #>
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: run this from an elevated PowerShell (Run as Administrator)." -ForegroundColor Red
        exit 1
    }
}


# --- Logging -----------------------------------------------------

function Write-LabLog {
    <#
    .SYNOPSIS
        Append a timestamped line to the lab log.
        Convention: start Message with a CATEGORY: (BAN:, SKIP_ALLOWLIST:, WEBHOOK_ERROR:, ...).
    #>
    param(
        [Parameter(Mandatory)] [string]$Message,
        [string]$Path
    )
    if (-not $Path) { $Path = (Import-LabConfig).LogPath }

    $dir = Split-Path $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    Add-Content -Path $Path -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}


# --- 4625 ingestion ---------------------------------------------

function Get-RdpFailedLogons {
    <#
    .SYNOPSIS
        Recent failed network logons (Security 4625, LogonType 3 or 10) as flat objects.

    .DESCRIPTION
        LogonType 3  = network logon. RDP with Network Level Authentication
                       (the default) fails here, during CredSSP, before a session exists.
        LogonType 10 = RemoteInteractive. RDP failures land here when NLA is off.
        Both are kept so detection works either way. Console (2) and unlock (7)
        failures are dropped. Events with no usable source IP are dropped and
        counted in the log, because a ban needs an IP.

    .OUTPUTS
        pscustomobject: TimeCreated, IpAddress, TargetUser, LogonType, Status, SubStatus, Workstation.
        Emits nothing when there are no matches. Wrap calls in @().
    #>
    param([int]$MinutesBack)

    $cfg = Import-LabConfig
    if (-not $MinutesBack) { $MinutesBack = $cfg.MinutesBack }

    # Look back MinutesBack, but never past the last Reset.ps1 run: events
    # from the previous demo would otherwise count toward the next one.
    $start = (Get-Date).AddMinutes(-$MinutesBack)
    $marker = Join-Path $cfg.StateDir 'last_reset.txt'
    if (Test-Path $marker) {
        try {
            $resetAt = [datetime](Get-Content $marker -TotalCount 1)
            if ($resetAt -gt $start) { $start = $resetAt }
        } catch { }
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $start
        } -ErrorAction Stop
    } catch {
        # A quiet box is normal. Match the error id, not the (localized) message.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw
    }

    $noIp = 0
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            # InnerText, not '#text': an empty <Data/> element has no '#text'
            # property, and strict mode throws on missing properties.
            $data[$d.Name] = $d.InnerText
        }

        if (@('3', '10') -notcontains $data['LogonType']) { continue }

        $ip = $data['IpAddress']
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') {
            $noIp++
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

    if ($noIp -gt 0) {
        # If this shows up during a known attack, 4625 isn't carrying the source
        # IP on this build; see "Known risk" in the Phase 04 README.
        $null = Write-LabLog "NO_SOURCE_IP: $noIp network-logon failure(s) in the last ${MinutesBack}m had no IpAddress"
    }
}


# --- Threshold detection ----------------------------------------

function Find-BruteForceBursts {
    <#
    .SYNOPSIS
        Group failures by (source IP, target user); emit groups at/over the threshold.

    .OUTPUTS
        pscustomobject: SourceIp, TargetUser, Count, FirstSeen, LastSeen, Records.
        Highest count first. Wrap calls in @().
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [array]$Records,
        [int]$Threshold
    )
    if (-not $Threshold) { $Threshold = (Import-LabConfig).Threshold }
    if ($Records.Count -eq 0) { return }

    $hits = foreach ($g in ($Records | Group-Object IpAddress, TargetUser)) {
        if ($g.Count -lt $Threshold) { continue }
        $first  = $g.Group[0]
        $sorted = @($g.Group | Sort-Object TimeCreated)
        [pscustomobject]@{
            SourceIp   = $first.IpAddress
            TargetUser = $first.TargetUser
            Count      = $g.Count
            FirstSeen  = $sorted[0].TimeCreated
            LastSeen   = $sorted[-1].TimeCreated
            Records    = $sorted
        }
    }
    $hits | Sort-Object Count -Descending
}


# --- Webhook delivery -------------------------------------------

function Send-LabWebhook {
    <#
    .SYNOPSIS
        POST a Discord-compatible message, with retries. Logs failures, never throws.

    .OUTPUTS
        $true if delivered, $false otherwise.
    #>
    param(
        [Parameter(Mandatory)] [string]$Message,
        [int]$Attempts = 3
    )
    $cfg = Import-LabConfig

    if (-not (Test-Path $cfg.WebhookFile)) {
        Write-LabLog "WEBHOOK_SKIPPED: no webhook file at $($cfg.WebhookFile)"
        return $false
    }
    $url = [string](Get-Content $cfg.WebhookFile -TotalCount 1)
    $url = $url.Trim()
    if ([string]::IsNullOrWhiteSpace($url)) {
        Write-LabLog "WEBHOOK_SKIPPED: webhook file is empty"
        return $false
    }

    # Windows PowerShell 5.1 can default to old TLS versions; Discord needs 1.2+.
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $payload = @{ content = $Message } | ConvertTo-Json -Compress
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Invoke-RestMethod -Uri $url -Method Post -Body $payload `
                -ContentType 'application/json' -TimeoutSec 10 | Out-Null
            return $true
        } catch {
            Write-LabLog "WEBHOOK_ERROR: attempt $i/${Attempts}: $($_.Exception.Message)"
            if ($i -lt $Attempts) { Start-Sleep -Seconds ([math]::Pow(2, $i - 1)) }
        }
    }
    return $false
}


# --- IP classification ------------------------------------------

function Test-IsPrivateOrLocalIp {
    <# True for RFC1918, loopback, link-local, and IPv6 ULA/link-local addresses. #>
    param([Parameter(Mandatory)] [string]$Ip)

    if ($Ip -eq '-' -or $Ip -eq '::1' -or $Ip -eq '127.0.0.1') { return $true }
    if ($Ip -match '^(fe80:|fc|fd)') { return $true }
    if ($Ip -match '^10\.')          { return $true }
    if ($Ip -match '^192\.168\.')    { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($Ip -match '^169\.254\.')    { return $true }
    return $false
}


# --- Allowlist --------------------------------------------------

function Get-LabAllowList {
    <# IPs that must never be banned. One per line; '#' starts a comment. Wrap calls in @(). #>
    param([string]$Path)
    if (-not $Path) { $Path = (Import-LabConfig).AllowListPath }
    if (-not (Test-Path $Path)) { return }

    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if ($t -and -not $t.StartsWith('#')) { $t }
    }
}


# --- Small JSON state helpers -----------------------------------

function Read-LabJson {
    <# Read a JSON state file; $null if missing, empty, or unreadable. #>
    param([Parameter(Mandatory)] [string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        $raw = Get-Content $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-LabLog "STATE_READ_ERROR: $Path : $($_.Exception.Message)"
        return $null
    }
}

function Write-LabJsonAtomic {
    <# Write text to a temp file, then move it into place, so readers never see half a file. #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Json
    )
    $tmp = "$Path.tmp"
    try {
        Set-Content -Path $tmp -Value $Json -Encoding UTF8
        Move-Item -Path $tmp -Destination $Path -Force
    } catch {
        Write-LabLog "STATE_WRITE_ERROR: $Path : $($_.Exception.Message)"
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}


# --- Banlist (persistent) ---------------------------------------

function Read-LabBanList {
    <# Active bans: objects with ip, user, count, firstSeen, lastSeen, expiresAt. Wrap calls in @(). #>
    param([string]$Path)
    if (-not $Path) { $Path = (Import-LabConfig).BanListPath }
    $data = Read-LabJson -Path $Path
    if ($null -eq $data) { return }
    foreach ($item in @($data)) {
        if ($item.PSObject.Properties['ip'] -and $item.PSObject.Properties['expiresAt']) { $item }
    }
}

function Save-LabBanList {
    <# Persist the banlist. Always writes a JSON array, even for 0 or 1 entries. #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [array]$List,
        [string]$Path
    )
    if (-not $Path) { $Path = (Import-LabConfig).BanListPath }
    $arr = @($List | Where-Object { $null -ne $_ })

    # ConvertTo-Json turns a 1-element array into a bare object in PS 5.1,
    # so build the array brackets explicitly.
    $items = @($arr | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress })
    Write-LabJsonAtomic -Path $Path -Json ('[' + ($items -join ',') + ']')
}


# --- Alert cooldown (Phase 05 monitor) --------------------------

function Test-LabAlertCooldown {
    <# True if an alert for this key (source IP) was sent within the cooldown. #>
    param([Parameter(Mandatory)] [string]$Key)
    $data = Read-LabJson -Path (Import-LabConfig).AlertCooldownPath
    if ($null -eq $data -or -not $data.PSObject.Properties[$Key]) { return $false }
    try { return ((Get-Date) -lt [datetime]$data.$Key) } catch { return $false }
}

function Set-LabAlertCooldown {
    <# Start (or restart) the cooldown for this key; prunes expired keys. #>
    param(
        [Parameter(Mandatory)] [string]$Key,
        [int]$Minutes
    )
    $cfg = Import-LabConfig
    if (-not $Minutes) { $Minutes = $cfg.AlertCooldownMinutes }

    $now = Get-Date
    $table = [ordered]@{}
    $data = Read-LabJson -Path $cfg.AlertCooldownPath
    if ($null -ne $data) {
        foreach ($p in $data.PSObject.Properties) {
            try { if ([datetime]$p.Value -gt $now) { $table[$p.Name] = $p.Value } } catch { }
        }
    }
    $table[$Key] = $now.AddMinutes($Minutes).ToString('s')
    Write-LabJsonAtomic -Path $cfg.AlertCooldownPath -Json ($table | ConvertTo-Json -Compress)
}


# --- Firewall enforcement ---------------------------------------

function Get-LabFirewallRuleName {
    param([Parameter(Mandatory)] [string]$Ip)
    return "$((Import-LabConfig).FirewallRulePrefix)-$Ip"
}

function Block-LabIp {
    <# Inbound block on TCP/3389 from one IP, all profiles. Idempotent. Returns $true on success. #>
    param([Parameter(Mandatory)] [string]$Ip)
    $name = Get-LabFirewallRuleName -Ip $Ip
    try {
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block `
            -Protocol TCP -LocalPort 3389 -RemoteAddress $Ip -Profile Any -Enabled True | Out-Null
        return $true
    } catch {
        Write-LabLog "FIREWALL_BLOCK_ERROR: Ip=$Ip Err=$($_.Exception.Message)"
        return $false
    }
}

function Unblock-LabIp {
    param([Parameter(Mandatory)] [string]$Ip)
    $name = Get-LabFirewallRuleName -Ip $Ip
    try {
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    } catch {
        Write-LabLog "FIREWALL_UNBLOCK_ERROR: Ip=$Ip Err=$($_.Exception.Message)"
    }
}

function Remove-AllLabFirewallRules {
    <# Delete every rule with the lab prefix. #>
    Get-NetFirewallRule -DisplayName "$((Import-LabConfig).FirewallRulePrefix)-*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Remove-ExpiredBans {
    <# Unblock expired bans; emit the bans still active. Wrap calls in @(). #>
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [array]$BanList)

    $now = Get-Date
    foreach ($b in @($BanList | Where-Object { $null -ne $_ })) {
        $expiresAt = $null
        try { $expiresAt = [datetime]$b.expiresAt } catch { }
        if ([string]::IsNullOrWhiteSpace($b.ip) -or $null -eq $expiresAt) { continue }

        if ($expiresAt -le $now) {
            $null = Unblock-LabIp -Ip $b.ip
            $null = Write-LabLog "UNBAN: SourceIP=$($b.ip) ExpiredAt=$($expiresAt.ToString('s'))"
        } else {
            $b
        }
    }
}


# --- Scheduled task (event trigger) -----------------------------

function Register-LabEventTask {
    <#
    .SYNOPSIS
        Register a task that runs a script as SYSTEM every time Security 4625 is written.

    .DESCRIPTION
        New-ScheduledTaskTrigger has no event-trigger option, so the trigger is
        built from the MSFT_TaskEventTrigger CIM class directly.

        MultipleInstances = Queue matters: an attack fires several 4625s within
        a second or two. With IgnoreNew, the run started by the first event could
        see fewer failures than the threshold, and every trigger during that run
        would be discarded, so the attack might never be acted on. Queue
        guarantees a run after the last event, which sees the whole burst.
        Runs are idempotent (already-banned IPs are skipped), so extra queued
        runs cost a few seconds of CPU and nothing else.

    .PARAMETER SweepMinutes
        If > 0, also run the script on a repeating timer. The responder needs
        this: expired bans are lifted only when the responder runs, and on a
        quiet box with no new 4625s it would otherwise never run.
    #>
    param(
        [Parameter(Mandatory)] [string]$TaskName,
        [Parameter(Mandatory)] [string]$ScriptPath,
        [string]$Description = 'RDP Detection & Response lab: runs on every Security 4625 event',
        [int]$SweepMinutes = 0
    )

    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""

    $cimClass = Get-CimClass -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ClassName 'MSFT_TaskEventTrigger'
    $trigger = New-CimInstance -CimClass $cimClass -ClientOnly
    $trigger.Enabled = $true
    $trigger.Subscription = $script:EventSubscriptionXml
    $triggers = @($trigger)

    if ($SweepMinutes -gt 0) {
        # No -RepetitionDuration: on Server 2016+ that means "repeat indefinitely".
        $triggers += New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $SweepMinutes)
    }

    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances Queue -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

    Register-ScheduledTask -TaskName $TaskName -Description $Description -Action $action `
        -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}


Export-ModuleMember -Function @(
    'Import-LabConfig', 'Assert-Administrator', 'Write-LabLog',
    'Get-RdpFailedLogons', 'Find-BruteForceBursts', 'Send-LabWebhook',
    'Test-IsPrivateOrLocalIp', 'Get-LabAllowList',
    'Read-LabBanList', 'Save-LabBanList',
    'Test-LabAlertCooldown', 'Set-LabAlertCooldown',
    'Get-LabFirewallRuleName', 'Block-LabIp', 'Unblock-LabIp',
    'Remove-AllLabFirewallRules', 'Remove-ExpiredBans',
    'Register-LabEventTask'
)
