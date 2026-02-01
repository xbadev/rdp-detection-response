# Detect and alert repeated failed network logons (Event ID 4625) over a short time window

# add configruable parameters (-MinutesBack, -Threshold)
param(
    [int]$MinutesBack = 2,
    [int]$Threshold   = 5,
    [switch]$TestWebhook
)

$LogPath       = "C:\homelab\logs\rdp_monitor.log"
# if log file don't exist
$LogDir = Split-Path $LogPath
if (-not (Test-Path $LogDir)) { 
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null 
}

function Write-LogLine {
    param([string]$Message)

    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogPath -Value $line
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

if ($TestWebhook) {
    Send-DiscordWebhook "TEST: Windows RDP monitor webhook is working."
    Write-Host "OK: Test alert sent to Discord."
    exit 0
}

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

    # LogonType 3 = network logon (common for failed RDP auth attempts)
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
    Write-LogLine "OK: No suspicious bursts (Threshold=$Threshold Window=${MinutesBack}m)"
    exit 0
}

# the details from the first 'hit' in the list
$FirstHit = $hits[0]
$Details  = $FirstHit.Name -split ',\s*'
$IP       = $Details[0]
$User     = $Details[1]
$Count    = $FirstHit.Count

Write-Host "SUSPECT: Possible RDP brute-force activity detected!" -ForegroundColor Red
Write-LogLine "SUSPECT: Threshold exceeded. SourceIP=$IP User=$User Failures=$Count Window=${MinutesBack}m"
Send-DiscordWebhook "SUSPECT: RDP brute-force detected from $IP (Target: $User) with $Count failures."

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
