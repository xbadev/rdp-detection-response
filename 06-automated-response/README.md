# Phase 06 — Automated Response & Containment

The full pipeline. An event-triggered task fires on every Security/4625 entry. The responder evaluates the recent window, and on threshold crossing creates a Windows Firewall inbound block rule on TCP/3389 for the source IP, persists the ban with an expiration timestamp, posts to Discord, and self-prunes expired bans on each run.

| Script | Purpose |
|---|---|
| [`scripts/rdp_bruteforce_responder.ps1`](scripts/rdp_bruteforce_responder.ps1) | Detection + ban + alert |
| [`scripts/rdp_responder_task.ps1`](scripts/rdp_responder_task.ps1) | Registers the responder as an event-triggered task |

## State files

| Path | Purpose |
|---|---|
| `C:\HomeLab\rdp-dr\config\lab.config.psd1` | All configuration (threshold, paths, LabMode, IPs) |
| `C:\HomeLab\rdp-dr\config\rdp_allowlist.txt` | One IP per line. Always exempted from bans. |
| `C:\HomeLab\rdp-dr\state\rdp_banlist.json` | Active + historical bans with expiration timestamps |
| `C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt` | Webhook URL, ACL'd to SYSTEM + Admins |
| `C:\HomeLab\rdp-dr\logs\rdp_monitor.log` | Append-only operational log |

## Responder logic — one event-triggered run

1. Load config (`Import-LabConfig`).
2. Read banlist; remove expired entries; for each, `Remove-NetFirewallRule` for the matching `HomeLab-RDPBan-<ip>` rule.
3. Pull last `MinutesBack` minutes of 4625/LogonType-3 events.
4. Group by `(IpAddress, TargetUser)`, find any group with `Count >= Threshold`.
5. For each flagged group:
   - Skip if IP is in the allowlist.
   - Skip if `LabMode = $false` AND IP is private/loopback. (In `LabMode = $true`, private IPs are allowed to be banned — necessary because the lab attacker, Kali, is at `10.10.10.30`.)
   - Skip if IP is already banned (no ban extension; the original ban runs out and gets re-evaluated then).
   - Otherwise: `New-NetFirewallRule` blocking TCP/3389 from that IP, append to banlist with expiration, post Discord alert.
6. Save banlist atomically.

The whole sequence is idempotent. Multiple back-to-back firings of the task on the same attack do not produce duplicate rules or duplicate alerts (after the first ban, the IP is in the banlist, so subsequent runs hit step 5's "already banned" branch).

## The `LabMode` flag — important

Most "block private IPs" defaults exist in production responders to prevent self-lockout: you don't want your responder to ban `10.0.0.1` when that's your default gateway. In a homelab on `10.10.10.0/24`, every meaningful actor is on a private IP, so the same default makes the responder a no-op.

`lab.config.psd1` exposes `LabMode = $true` by default for that exact reason. The responder's behavior:

| LabMode | Private/local IPs |
|---|---|
| `$true` (default) | Eligible to be banned — Kali at `10.10.10.30` will be blocked |
| `$false` | Skipped with `SKIP_PRIVATE_OR_LOCAL` log line — production-style behavior |

The allowlist always wins regardless of `LabMode`. Use it to protect specific management/admin IPs you don't want banned even in lab mode.

## Setup

```powershell
# Install (repo root) — registers the responder task automatically
.\Install.ps1

# Re-register the task only (after editing the responder)
.\06-automated-response\scripts\rdp_responder_task.ps1
```

Verify the task is registered and event-triggered:

```powershell
Get-ScheduledTask -TaskName 'HomeLab-RDP-Responder'
$task = Get-ScheduledTask -TaskName 'HomeLab-RDP-Responder'
$task.Triggers     # should show a CIM trigger with Subscription containing EventID=4625
```

## Operator commands

```powershell
# Smoke-test the webhook without generating any events
C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_responder.ps1 -TestWebhook

# Wipe everything for a clean demo (also at repo root: .\Reset.ps1)
C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_responder.ps1 -ClearBans

# See active firewall bans
Get-NetFirewallRule -DisplayName 'HomeLab-RDPBan-*' | Format-Table DisplayName, Enabled, Action

# See the persistent banlist
Get-Content C:\HomeLab\rdp-dr\state\rdp_banlist.json | ConvertFrom-Json | Format-Table

# Tail the operational log
Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait -Tail 30
```

## End-to-end validation

1. Reset state:

   ```powershell
   .\Reset.ps1
   ```

2. From Kali, attack:

   ```bash
   hydra -l Administrator -P pw.txt -t 4 -V rdp://10.10.10.40
   ```

3. Within ~5 seconds:
   - `Get-NetFirewallRule -DisplayName 'HomeLab-RDPBan-10.10.10.30'` exists
   - `rdp_banlist.json` contains an entry for `10.10.10.30` with an expiration ~30 min in the future
   - Discord webhook delivered the `:no_entry: RDP attacker blocked` alert
   - From Kali, a follow-up `nmap -p 3389 10.10.10.40` shows `filtered` (or no response) — the rule blocks at the network layer

4. Wait for the ban window to expire (or `Reset.ps1` to fast-forward). The next responder run prunes the ban — firewall rule disappears, banlist entry removed.

## Sample alert

```
⛔ RDP attacker blocked
Host: 10.10.10.40
Banned IP: 10.10.10.30
Target user: Administrator
Failures: 5 in 2m
Block duration: 30m
Expires: 2026-05-04T03:44:22
```

## Account lockout interaction

Default Windows account lockout policy locks an account after ~10 failures. The responder's threshold (5) means the firewall ban almost always fires *before* the account locks — which is the desired ordering: stop the attack at the network layer, before the user-impacting lockout happens.

If you want to make this even cleaner for a demo, you can raise the lockout threshold so the firewall ban is the *only* visible response:

```powershell
net accounts /lockoutthreshold:0     # disable lockout entirely (lab only!)
```

Reset to the original value after the demo:

```powershell
net accounts /lockoutthreshold:10
```

This is a lab-only adjustment — disabling lockout in production removes a real defense-in-depth layer.

## Why this is the final phase

The pipeline is now closed-loop: detection → response → state tracking → alerting → cleanup. Identical structure to the SSH lab's Phase 04+05 split, with platform-specific implementation (Event Log + Task Scheduler + Windows Firewall instead of journald + systemd unit + UFW).

A real-world hardening continuation from here would be: GPO-distributed firewall ruleset, a SIEM forwarder for the Security log, and a SOAR playbook around the responder for tickets and analyst review. None of that lives in this repo — it's the explicit edge of "host-based" containment.
