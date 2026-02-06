<#
Task: rdp_responder_task.ps1 (Scheduled Task)

Purpose
- Runs the automated RDP brute-force response script on a fixed interval.
- This task is the execution layer that turns detection + response logic into
  continuous, hands-off enforcement on the Windows endpoint.

What this task does
- Executes the PowerShell responder script:
  C:\homelab\scripts\rdp_bruteforce_responder.ps1
- Passes runtime parameters that define:
  - How far back to inspect failed logons (MinutesBack)
  - How many failures trigger containment (Threshold)
  - How long offending IPs are blocked (BanMinutes)

Execution model
- Runs as NT AUTHORITY\SYSTEM with highest privileges:
  - Required for reading the Security event log
  - Required for creating/removing Windows Firewall rules
- Uses ExecutionPolicy Bypass so script execution is not blocked by local policy.
- Runs without a user session and continues operating even when no one is logged in.

Schedule behavior
- Starts once shortly after task creation.
- Repeats every 2 minutes indefinitely (configured for ~10 years).
- Ensures near real-time response to RDP brute-force activity.
#>

$TaskName = "RDP_BruteForce_Responder"

$Script   = "C:\homelab\scripts\rdp_bruteforce_responder.ps1"

# Action: run PowerShell and execute the responder script with defined thresholds
$Args = "-NoProfile -ExecutionPolicy Bypass -File `"$Script`" -MinutesBack 2 -Threshold 5 -BanMinutes 30"
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $Args


# Trigger: start shortly after creation, then repeat every 2 minutes long-term
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 2) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

# Run as SYSTEM with highest privileges (required for Security log + firewall access)
$Principal = New-ScheduledTaskPrincipal `
    -UserId "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Settings: allow execution regardless of power state
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

# Register (or overwrite) the scheduled task
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force
