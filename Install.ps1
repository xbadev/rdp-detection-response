<#
.SYNOPSIS
    Install the RDP Detection & Response lab on the Windows Server target.

.DESCRIPTION
    Idempotent: safe to re-run after pulling changes. Steps:
      1. Check elevation
      2. Make sure failed-logon auditing is on (no 4625 events otherwise)
      3. Create C:\HomeLab\rdp-dr\{config,scripts,lib,logs,state,secrets}
      4. Copy the module and phase scripts (always) and the config (only if
         missing, so your edits survive a re-install; -ResetConfig to overwrite)
      5. Seed the allowlist and an empty banlist
      6. Restrict secrets\ and state\ to SYSTEM + Administrators
      7. Ask for the Discord webhook URL (hidden input; skipped if already set)
      8. Register the Phase 06 responder as an event-triggered task
      9. Smoke test: load config, query the Security log

.PARAMETER NoWebhook
    Don't prompt for the webhook URL.

.PARAMETER NoTask
    Don't register the scheduled task (run scripts by hand while developing).

.PARAMETER ResetConfig
    Overwrite the installed lab.config.psd1 with the repo copy.

.EXAMPLE
    .\Install.ps1
.EXAMPLE
    .\Install.ps1 -NoWebhook      # re-install after a git pull
#>

[CmdletBinding()]
param(
    [switch]$NoWebhook,
    [switch]$NoTask,
    [switch]$ResetConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot    = $PSScriptRoot
$InstallRoot = 'C:\HomeLab\rdp-dr'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run Install.ps1 from an elevated PowerShell." -ForegroundColor Red
    exit 1
}

Write-Host "==> RDP Detection & Response installer" -ForegroundColor Cyan
Write-Host "    from: $RepoRoot"
Write-Host "    to:   $InstallRoot"

# ---------- 1. Audit policy -------------------------------------------
# "Logon" subcategory by GUID (subcategory names are localized).
$logonGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
Write-Host "==> ensuring failed-logon auditing is enabled (Security 4625)"
& auditpol.exe /set /subcategory:$logonGuid /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "auditpol failed (exit $LASTEXITCODE)" }

# ---------- 2. Directories --------------------------------------------
foreach ($d in 'config', 'scripts', 'lib', 'logs', 'state', 'secrets') {
    New-Item -ItemType Directory -Path (Join-Path $InstallRoot $d) -Force | Out-Null
}
Write-Host "==> directories ready under $InstallRoot"

# ---------- 3. Files --------------------------------------------------
Copy-Item "$RepoRoot\Lib\RdpDetection.psm1" "$InstallRoot\lib\RdpDetection.psm1" -Force
@(
    "$RepoRoot\04-detection-logic\scripts\rdp_bruteforce_detection.ps1",
    "$RepoRoot\05-automated-monitoring-alerting\scripts\rdp_bruteforce_monitor.ps1",
    "$RepoRoot\06-automated-response\scripts\rdp_bruteforce_responder.ps1"
) | ForEach-Object { Copy-Item $_ "$InstallRoot\scripts\" -Force }
Write-Host "==> module and phase scripts copied"

$cfgDest = "$InstallRoot\config\lab.config.psd1"
if ($ResetConfig -or -not (Test-Path $cfgDest)) {
    Copy-Item "$RepoRoot\lab.config.psd1" $cfgDest -Force
    Write-Host "==> config written to $cfgDest"
} else {
    Write-Host "==> keeping existing $cfgDest (use -ResetConfig to overwrite)"
}

# ---------- 4. Allowlist + banlist ------------------------------------
$allow = "$InstallRoot\config\rdp_allowlist.txt"
if (-not (Test-Path $allow)) {
    @('# IPs the responder must never ban: one per line, # for comments.',
      '# Add the address you administer this server from.',
      '127.0.0.1',
      '::1') | Set-Content -Path $allow -Encoding UTF8
}
$ban = "$InstallRoot\state\rdp_banlist.json"
if (-not (Test-Path $ban)) { '[]' | Set-Content -Path $ban -Encoding UTF8 }

# ---------- 5. ACLs ---------------------------------------------------
function Set-AdminOnlyAcl {
    param([string]$Path)
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)                 # stop inheriting
    @($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
    foreach ($who in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}
Set-AdminOnlyAcl "$InstallRoot\secrets"
Set-AdminOnlyAcl "$InstallRoot\state"
Write-Host "==> secrets\ and state\ restricted to SYSTEM + Administrators"

# ---------- 6. Webhook ------------------------------------------------
$hook = "$InstallRoot\secrets\discord_webhook_url.txt"
$hasHook = (Test-Path $hook) -and ([string](Get-Content $hook -Raw)).Trim().Length -gt 0
if ($NoWebhook) {
    Write-Host "==> webhook prompt skipped (-NoWebhook)"
} elseif ($hasHook) {
    Write-Host "==> webhook already configured; leaving it"
} else {
    $secure = Read-Host "Discord webhook URL (input hidden; Enter to skip)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $url = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($url.Trim()) {
        Set-Content -Path $hook -Value $url.Trim() -Encoding ASCII -NoNewline
        Write-Host "==> webhook saved to $hook"
    } else {
        Write-Host "==> no webhook; alerts will only be logged. Add one later by re-running Install.ps1"
    }
}

# ---------- 7. Event-triggered task -----------------------------------
Import-Module "$InstallRoot\lib\RdpDetection.psm1" -Force
$cfg = Import-LabConfig -ConfigPath $cfgDest

if ($NoTask) {
    Write-Host "==> task registration skipped (-NoTask)"
} else {
    Register-LabEventTask -TaskName $cfg.ResponderTaskName `
        -ScriptPath "$InstallRoot\scripts\rdp_bruteforce_responder.ps1" `
        -Description 'RDP lab Phase 06: detect, block, alert; runs on every Security 4625'
    Write-Host "==> registered '$($cfg.ResponderTaskName)' (fires on every Security 4625)"
}

# ---------- 8. Smoke test ---------------------------------------------
$recent = @(Get-RdpFailedLogons -MinutesBack 60)
Write-Host "==> smoke test OK: config loaded (threshold $($cfg.Threshold), LabMode $($cfg.LabMode)); $($recent.Count) RDP failure(s) with a source IP in the last hour"

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host "  Test the webhook:  & '$InstallRoot\scripts\rdp_bruteforce_responder.ps1' -TestWebhook"
Write-Host "  Watch the log:     Get-Content '$($cfg.LogPath)' -Wait -Tail 20"
Write-Host "  Attack from Kali:  ./attacker/run-attack.sh"
Write-Host "  Reset for a demo:  .\Reset.ps1"
