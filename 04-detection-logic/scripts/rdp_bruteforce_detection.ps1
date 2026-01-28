# Detect repeated failed network logons (Event ID 4625) over a short time window
# Lab purpose: identify suspicious RDP authentication abuse patterns using native Windows logs

# $MinutesBack = 2
# $Threshold   = 5

# Add configruable parameters (-MinutesBack, -Threshold)
param(
    [int]$MinutesBack = 2,
    [int]$Threshold   = 5
)

$StartTime = (Get-Date).AddMinutes(-$MinutesBack)

# Must run elevated to read the Security log
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "ERROR: Run PowerShell as Administrator to read the Security log." -ForegroundColor Red
    exit 1
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
    Write-Host "OK: No suspicious bursts found (>= $Threshold failures within last $MinutesBack minutes). Checked since $StartTime"
    exit 0
}

Write-Host "SUSPECT: Possible RDP brute-force pattern detected (>= $Threshold failures within last $MinutesBack minutes):"
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
