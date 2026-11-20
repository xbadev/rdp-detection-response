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

Filtering on `LogonType = 3` cleanly isolates RDP failures from console failures and screen-unlock noise. (LogonType 10 also exists for RDP; in practice 4625 from RDP brute-force lands as type 3 because Network Level Authentication fails before the RemoteInteractive logon is even attempted.)

Each 4625 event carries:
- `IpAddress` — source of the attempt
- `TargetUserName` — account being attempted
- `WorkstationName` — attacker-supplied (often spoofed)
- `Status` / `SubStatus` — failure reason codes

These are the fields the script extracts.

## Detection logic

| Setting | Default | Reason |
|---|---|---|
| Threshold | 5 failures | A typo happens once or twice. Five rapid failures from one source against one user is a brute-force pattern. |
| Window | 2 minutes | Tight enough to be noisy on attacks, loose enough to survive short auth lulls. |
| Aggregation | by `(IpAddress, TargetUserName)` | An attacker hitting one user 20 times triggers; an attacker spreading 5 attempts across 5 users does not. (That broader pattern is "user enumeration" and would warrant a separate rule.) |

The script:

1. Asserts elevation (Security log requires it).
2. Calls `Get-RdpFailedLogons` from the shared module — pulls 4625 events, parses XML, filters to LogonType 3, drops loopback addresses.
3. Calls `Find-BruteForceBursts` — groups by (IP, user), flags any group at/over threshold.
4. Prints results, including the most recent 5 events per flagged group.

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

1. From Kali, generate failed logons:

   ```bash
   hydra -l Administrator -P pw.txt -t 4 -V rdp://10.10.10.40
   ```

   (Where `pw.txt` is a list of wrong passwords. 5+ entries needed to cross the default threshold.)

2. On Windows, run the detection script:

   ```powershell
   C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_detection.ps1
   ```

   Expected output: `SUSPECT: ...` block listing source IP `10.10.10.30`, target user, count, and the 5 most recent records.

3. Re-run after 10 minutes (with no new attack). Expected: `OK: No failed RDP logons in the window.`

## Privilege requirement

The Security log is restricted to Administrators by default. Without elevation the script aborts with a clear error rather than failing silently inside `Get-WinEvent`.

Execution policy is bypassed at the launch line (`-ExecutionPolicy Bypass`) when the script is invoked by the scheduled task — it does not require the system-wide policy to be loosened.

## Next

Phase 05 wraps the same logic with webhook alerting for unattended monitoring. Phase 06 adds firewall containment. Both use this phase's module functions verbatim — no logic re-implemented.
