# Phase 05 — Automated Monitoring & Alerting

Same detection logic as Phase 04, but runs unattended via an event-triggered scheduled task and posts to a Discord webhook on threshold crossing. **Alert-only mode** — no firewall changes. Use this phase to demonstrate detection-and-notification before adding containment in Phase 06.

| Script | Purpose |
|---|---|
| [`scripts/rdp_bruteforce_monitor.ps1`](scripts/rdp_bruteforce_monitor.ps1) | The monitor itself — checks recent 4625s, posts to webhook on threshold |
| [`scripts/rdp_monitor_task.ps1`](scripts/rdp_monitor_task.ps1) | Registers the monitor as an event-triggered task |

## Architecture — event-triggered, not polling

The original lab used a 2-minute interval task. That's a 2-minute worst-case latency from attack to alert. This refresh uses a **Task Scheduler event trigger** firing on every Security log entry of Event ID 4625:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>
```

When LSASS writes a 4625 event, Task Scheduler kicks off the monitor within ~2-5 seconds. The monitor then evaluates the last `MinutesBack` minutes of failures (not just the one that triggered it), so a single event doesn't fire an alert — only crossing the threshold does.

This trades polling latency for slightly higher CPU on heavy attacks (one PowerShell process per event), which is a fine trade for a lab. In production with millions of events you'd subscribe via WMI or ETW instead.

## Webhook delivery

Discord-compatible — any service accepting `POST {"content": "..."}` (Discord, Slack incoming webhooks, custom endpoints).

The webhook URL is stored at `C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt`, ACL'd to SYSTEM and Administrators only by `Install.ps1`. The shared module reads it on demand — never embedded in code, never logged.

## Sample alert

```
🚨 RDP brute-force detected
Host: 10.10.10.40
Source IP: 10.10.10.30
Target user: Administrator
Failures: 5 in 2m
Last seen: 2026-05-04T03:14:22
```

## Setup

After running `Install.ps1` from the repo root (which only registers the Phase 06 responder task by default), if you want **alert-only** mode without containment:

```powershell
# Disable the responder task
Get-ScheduledTask -TaskName 'HomeLab-RDP-Responder' | Disable-ScheduledTask

# Register the alert-only monitor task
.\05-automated-monitoring-alerting\scripts\rdp_monitor_task.ps1
```

To switch back to full response, re-enable the responder task and disable the monitor.

You can also leave both registered and enabled — the monitor will alert and the responder will block on the same event. Slight redundancy, but useful when demoing.

## Smoke test

Send a test webhook without generating any events:

```powershell
C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_monitor.ps1 -TestWebhook
```

Expected: green `Test alert sent.` line and a Discord message arriving in a few seconds.

## End-to-end validation

1. From Kali:

   ```bash
   hydra -l Administrator -P pw.txt -t 4 -V rdp://10.10.10.40
   ```

2. Watch on Windows:

   ```powershell
   Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait -Tail 20
   ```

   You should see `SUSPECT: SourceIP=10.10.10.30 ...` lines as the threshold is crossed, paired with the Discord alert arriving in real time.

## Account lockout — a known side effect

Repeated failed authentication will trigger Windows' built-in account lockout policy and lock the targeted account temporarily. The monitor doesn't cause this — Windows does — but the monitor will fire its alert *before* the lockout because the threshold (5) is below the default lockout threshold (often 10). That's intentional: you want the alert to land before the user-impacting lockout happens, so an admin has a chance to intervene.

To see / change the lockout policy:

```powershell
net accounts                  # current policy
secpol.msc                    # Local Security Policy GUI -> Account Policies
```

## Next

Phase 06 adds active response — the same detection now also drops a Windows Firewall block rule on the offender's IP, persisting the ban with expiration in JSON state.
