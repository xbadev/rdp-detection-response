<#
.SYNOPSIS
    Install the RDP Detection & Response lab on the Windows endpoint.

.DESCRIPTION
    Equivalent of 'make install' from the SSH lab. Idempotent — safe to re-run.

    Steps performed:
      1. Verify Administrator privileges
      2. Create C:\HomeLab\rdp-dr\ tree (config, scripts, lib, logs, state, secrets)
      3. Copy lab.config.psd1, RdpDetection.psm1, and phase scripts into place
      4. Seed allowlist and empty banlist
      5. Lock down ACLs on secrets and state directories (SYSTEM + Administrators only)
      6. Prompt for Discord webhook URL (skipped if -NoWebhook or already set)
      7. Register the event-triggered scheduled task that runs the responder
      8. Run a smoke test (load config, query 4625 events, exit 0)

.PARAMETER NoWebhook
    Skip the webhook prompt. Useful for unattended installs; you can set the
    URL later with: 'Set-Content C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt "https://..."'

.PARAMETER NoTask
    Skip scheduled task registration. Useful when developing; lets you run
    the scripts manually without the event-triggered task firing too.

.EXAMPLE
    # First-time install with prompts
    PS> .\Install.ps1

.EXAMPLE
    # Reinstall scripts only, leave webhook + task alone
    PS> .\Install.ps1 -NoWebhook -NoTask
#>

[CmdletBinding()]
param(
    [switch]$NoWebhook,
    [switch]$NoTask
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = $PSScriptRoot
$InstallRoot = 'C:\HomeLab\rdp-dr'

# ---------- Privilege check ----------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Install.ps1 must be run from an elevated PowerShell." -ForegroundColor Red
    exit 1
}

Write-Host "==> RDP Detection & Response — installer" -ForegroundColor Cyan
Write-Host "    Repo: $RepoRoot"
Write-Host "    Dest: $InstallRoot"
Write-Host ""

# ---------- 1. Directory tree --------------------------------------
$dirs = @(
    "$InstallRoot",
    "$InstallRoot\config",
    "$InstallRoot\scripts",
    "$InstallRoot\lib",
    "$InstallRoot\logs",
    "$InstallRoot\state",
    "$InstallRoot\secrets"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host "    created  $d"
    } else {
        Write-Host "    exists   $d"
    }
}

# ---------- 2. Copy files ------------------------------------------
Write-Host "==> copying files"

Copy-Item -Path "$RepoRoot\lab.config.psd1"      -Destination "$InstallRoot\config\lab.config.psd1" -Force
Copy-Item -Path "$RepoRoot\Lib\RdpDetection.psm1" -Destination "$InstallRoot\lib\RdpDetection.psm1"  -Force

# Phase scripts.
$phaseScripts = @{
    "$RepoRoot\04-detection-logic\scripts\rdp_bruteforce_detection.ps1"          = "$InstallRoot\scripts\rdp_bruteforce_detection.ps1"
    "$RepoRoot\05-automated-monitoring-alerting\scripts\rdp_bruteforce_monitor.ps1" = "$InstallRoot\scripts\rdp_bruteforce_monitor.ps1"
    "$RepoRoot\06-automated-response\scripts\rdp_bruteforce_responder.ps1"      = "$InstallRoot\scripts\rdp_bruteforce_responder.ps1"
}
foreach ($src in $phaseScripts.Keys) {
    if (-not (Test-Path $src)) { continue }
    Copy-Item -Path $src -Destination $phaseScripts[$src] -Force
    Write-Host "    copied   $(Split-Path $src -Leaf)"
}

# ---------- 3. Seed allowlist + banlist ----------------------------
$allowlist = "$InstallRoot\config\rdp_allowlist.txt"
if (-not (Test-Path $allowlist)) {
    @(
        '# IP allowlist — one per line. Lines starting with # are comments.',
        '# Add management/admin IPs here so the responder never blocks them.',
        '127.0.0.1',
        '::1'
    ) | Set-Content -Path $allowlist -Encoding UTF8
    Write-Host "    seeded   $allowlist"
}

$banlist = "$InstallRoot\state\rdp_banlist.json"
if (-not (Test-Path $banlist)) {
    '[]' | Set-Content -Path $banlist -Encoding UTF8
    Write-Host "    seeded   $banlist"
}

# ---------- 4. Lock down ACLs --------------------------------------
# Secrets and state dirs: SYSTEM and Administrators only. No Users.
function Lock-Path {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return }

    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited ACEs

    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $rules = @(
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow'),
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
    )
    foreach ($r in $rules) { $acl.AddAccessRule($r) }
    Set-Acl -Path $Path -AclObject $acl
}

Write-Host "==> locking down ACLs on secrets + state"
Lock-Path "$InstallRoot\secrets"
Lock-Path "$InstallRoot\state"

# ---------- 5. Webhook URL -----------------------------------------
$webhookFile = "$InstallRoot\secrets\discord_webhook_url.txt"

if (-not $NoWebhook) {
    if ((Test-Path $webhookFile) -and ((Get-Content $webhookFile -Raw).Trim().Length -gt 0)) {
        Write-Host "==> webhook file already populated, leaving it alone"
    } else {
        Write-Host ""
        $url = Read-Host "Discord webhook URL (paste, or press Enter to skip)"
        if (-not [string]::IsNullOrWhiteSpace($url)) {
            $url.Trim() | Set-Content -Path $webhookFile -Encoding UTF8 -NoNewline
            Lock-Path $webhookFile
            Write-Host "    saved + locked $webhookFile"
        } else {
            Write-Host "    skipped (set later: 'Set-Content $webhookFile <url>')"
        }
    }
}

# ---------- 6. Set machine env var so scripts find config ----------
[Environment]::SetEnvironmentVariable('RDP_LAB_CONFIG', "$InstallRoot\config\lab.config.psd1", 'Machine')
Write-Host "==> set RDP_LAB_CONFIG (machine scope) so scripts auto-discover config"

# ---------- 7. Register event-triggered task -----------------------
if (-not $NoTask) {
    Write-Host "==> registering event-triggered scheduled task"

    # Load config to get the responder task name + paths.
    $cfg = Import-PowerShellDataFile -Path "$InstallRoot\config\lab.config.psd1"
    $taskName = $cfg.ResponderTaskName
    $script   = "$InstallRoot\scripts\rdp_bruteforce_responder.ps1"

    # Remove existing task if present — Register-ScheduledTask -Force handles this,
    # but being explicit is clearer in logs.
    Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    # Action: invoke the responder under PowerShell.
    $action = New-ScheduledTaskAction `
        -Execute 'PowerShell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""

    # Event trigger: fire on every Security/4625. Built via XML because
    # New-ScheduledTaskTrigger doesn't expose event triggers natively.
    $eventXml = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>
'@

    # Use CIM to build the EVENT trigger explicitly — New-ScheduledTaskTrigger
    # doesn't expose event triggers, so we instantiate the CIM class directly.
    $cimTrigger = Get-CimClass -Namespace 'Root\Microsoft\Windows\TaskScheduler' `
                               -ClassName 'MSFT_TaskEventTrigger'
    $trigger = New-CimInstance -CimClass $cimTrigger -ClientOnly
    $trigger.Enabled      = $true
    $trigger.Subscription = $eventXml

    # Run as SYSTEM with highest privileges.
    $principal = New-ScheduledTaskPrincipal `
        -UserId 'NT AUTHORITY\SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # Settings: don't stop when no user is logged in, allow on battery, queue back-to-back triggers.
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

    Register-ScheduledTask `
        -TaskName  $taskName `
        -Action    $action `
        -Trigger   $trigger `
        -Principal $principal `
        -Settings  $settings `
        -Force | Out-Null

    Write-Host "    registered task: $taskName"
    Write-Host "    trigger: every Security/4625 event"
}

# ---------- 8. Smoke test ------------------------------------------
Write-Host "==> smoke test"
Import-Module "$InstallRoot\lib\RdpDetection.psm1" -Force
$cfg = Import-LabConfig
Write-Host "    config OK   (target=$($cfg.TargetIp), threshold=$($cfg.Threshold), labMode=$($cfg.LabMode))"
$recent = Get-RdpFailedLogons -MinutesBack 5
Write-Host "    log query OK ($($recent.Count) events in last 5 min)"

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. From Kali, run an attack:  hydra -l Administrator -P pw.txt rdp://10.10.10.40"
Write-Host "  2. Watch the responder fire:  Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait"
Write-Host "  3. Verify ban created:        Get-NetFirewallRule -DisplayName 'HomeLab-RDPBan-*'"
Write-Host "  4. Reset between demos:       .\Reset.ps1"
