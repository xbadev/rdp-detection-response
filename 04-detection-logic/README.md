# Phase 04 — RDP Authentication Failure Detection

Standalone PowerShell script that pulls recent Security log entries, filters for failed RDP authentication, and prints any source IPs that crossed the threshold. This is the **diagnostic** phase — no alerting, no firewall action. The same logic gets reused (via a shared module) by the Phase 05 monitor and Phase 06 responder.

**Script:** [`scripts/rdp_bruteforce_detection.ps1`](scripts/rdp_bruteforce_detection.ps1)
**Shared module:** [`Lib/RdpDetection.psm1`](../Lib/RdpDetection.psm1)

## Why these specific events

Windows doesn't have a "RDP attack" event. Authentication is logged uniformly for every method — local console, RDP, SMB, WMI, named-pipe — into the Security log. Two events matter:

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |

For brute-force detection, only 4625 matters. But 4625 also fires for failed local logons, mistyped service-account passwords, and background protocol auth. The discriminator is **LogonType**:

| LogonType | Source |
|---|---|
| 2 | Interactive (console) |
| 3 | **Network** (RDP, SMB, WMI) |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock (screensaver) |
| 10 | RemoteInteractive (also RDP) |

The detector keeps **LogonType 3 and 10** and drops the rest:

- **3 (Network):** with Network Level Authentication, which is on by default, a bad RDP password fails during CredSSP, before any desktop session exists, so Windows logs it as a network logon.
- **10 (RemoteInteractive):** with NLA turned off, the same failure is logged as type 10.

Keeping both means detection doesn't silently stop if someone disables NLA. Type 3 also covers failed SMB/WMI logons; on this lab box only RDP is exposed, so in practice those are RDP. Console (2) and unlock (7) failures are always dropped.

Each 4625 event carries:
- `IpAddress` — source of the attempt
- `TargetUserName` — account being attempted
- `WorkstationName` — attacker-supplied (often spoofed)
- `Status` / `SubStatus` — failure reason codes

These are the fields the script extracts.

## Known risk: a 4625 without a source IP

A ban needs `IpAddress`. Some Windows builds and configurations log RDP/NLA failures with `IpAddress` empty or `-`. When that happens, the module skips those events (it can't ban them) and writes a `NO_SOURCE_IP:` line to the lab log, so the problem is visible instead of silent.

**First thing to check on a new Windows Server VM:** run the attack once, then

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 3 |
    ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
        Where-Object Name -in 'IpAddress','LogonType','TargetUserName' |
        ForEach-Object { '{0} = {1}' -f $_.Name, $_.InnerText } ; '---' }
```

If `IpAddress` shows `10.10.10.30`, you're good. If it shows `-`, the fallback is Event ID 140 in `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`, which logs the client IP for failed NLA logons. That fallback isn't built yet, because it isn't needed unless this check fails.

## Detection logic

| Setting | Default | Reason |
|---|---|---|
| Threshold | 5 failures | A typo happens once or twice. Five rapid failures from one source against one user is a brute-force pattern. |
| Window | 2 minutes | Tight enough to be noisy on attacks, loose enough to survive short auth lulls. |
| Aggregation | by `(IpAddress, TargetUserName)` | An attacker hitting one user 20 times triggers; an attacker spreading 5 attempts across 5 users does not. (That broader pattern is "user enumeration" and would warrant a separate rule.) |

The script:

1. Asserts elevation (Security log requires it).
2. Calls `Get-RdpFailedLogons` from the shared module: pulls 4625 events since the later of `MinutesBack` ago or the last `Reset.ps1`, parses the event XML, keeps LogonType 3/10, drops events with no usable source IP.
3. Calls `Find-BruteForceBursts`: groups by (IP, user), returns groups at or over the threshold.
4. Prints the flagged groups with their 5 most recent events, or, if nothing crossed the threshold, the per-pair counts it did see (useful when tuning).

## Usage

After running `Install.ps1` from the repo root, in **elevated PowerShell**:

```powershell
# Default thresholds from lab.config.psd1
C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_detection.ps1

# Override per-run
C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_detection.ps1 -MinutesBack 10 -Threshold 3
```

Or directly from the repo (development mode):

```powershell
.\04-detection-logic\scripts\rdp_bruteforce_detection.ps1
```

## Validation

1. From Kali, generate six failed logons against the decoy account:

   ```bash
   ./attacker/run-attack.sh
   ```

   (If the Phase 06 responder task is installed, it will also block Kali partway through. That's expected and doesn't affect this check.)

2. On Windows, run the detection script:

   ```powershell
   C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_detection.ps1
   ```

   Expected output: `SUSPECT: ...` block listing source IP `10.10.10.30`, target user, count, and the 5 most recent records.

3. Re-run after the window has passed (or after `.\Reset.ps1`). Expected: `OK: no failed RDP/network logons with a source IP in the window.`

## Privilege requirement

The Security log is restricted to Administrators by default. Without elevation the script aborts with a clear error rather than failing silently inside `Get-WinEvent`.

Execution policy is bypassed at the launch line (`-ExecutionPolicy Bypass`) when the script is invoked by the scheduled task — it does not require the system-wide policy to be loosened.

## Next

Phase 05 wraps the same logic with webhook alerting for unattended monitoring. Phase 06 adds firewall containment. Both use this phase's module functions verbatim — no logic re-implemented.
