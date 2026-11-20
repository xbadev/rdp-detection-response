# Phase 05 — Automated Monitoring & Alerting

Same detection as Phase 04, run unattended by an event-triggered scheduled task, posting to a Discord webhook when a source IP crosses the threshold. **Alert-only mode:** no firewall changes. It shows detection plus notification on its own, before Phase 06 adds containment, and stays useful as the "an analyst decides what to block" variant.

| Script | Purpose |
|---|---|
| [`scripts/rdp_bruteforce_monitor.ps1`](scripts/rdp_bruteforce_monitor.ps1) | Checks recent 4625s; posts to the webhook on threshold, once per IP per cooldown |
| [`scripts/rdp_monitor_task.ps1`](scripts/rdp_monitor_task.ps1) | Registers the monitor as an event-triggered task |

## Event-triggered, not polling

The original version of this lab ran on a 2-minute interval, so an alert could land up to ~2 minutes after the attack. Now the task has an **event trigger** on every Security 4625:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>
```

When LSASS writes a 4625, Task Scheduler starts the monitor. Each run evaluates the whole `MinutesBack` window, not just the event that started it, so one stray failure doesn't alert; crossing the threshold does.

`New-ScheduledTaskTrigger` has no option for event triggers, so the shared module builds one from the `MSFT_TaskEventTrigger` CIM class (`Register-LabEventTask` in [`Lib/RdpDetection.psm1`](../Lib/RdpDetection.psm1)). The same function registers the Phase 06 task.

### Queued runs

An attack writes several 4625s within a second or two. The task queues runs (`-MultipleInstances Queue`) instead of ignoring triggers that arrive while a run is in progress. With `IgnoreNew`, the run started by the first failure could see fewer than `Threshold` events, every later trigger would be dropped, and the attack would never alert. With `Queue`, there is always a run after the last event that sees the full burst.

The trade-off is one short PowerShell process per failed logon. That's fine for a lab; at production volume you'd use a long-running subscriber (ETW, or a SIEM forwarder) instead.

## Alert cooldown

Because every 4625 starts a run, a 6-attempt attack produces up to six runs that all see the same burst. Without deduplication that's six identical alerts. The monitor records each alerted source IP in `C:\HomeLab\rdp-dr\state\alert_cooldowns.json` and stays quiet for that IP for `AlertCooldownMinutes` (default 10). The cooldown starts only after a successful post, so a webhook outage doesn't suppress the next attempt.

## Webhook delivery

Any endpoint that accepts `POST {"content": "..."}` works (Discord, Slack incoming webhooks). The URL lives in `C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt`, readable only by SYSTEM and Administrators (set by `Install.ps1`) and never logged. Delivery forces TLS 1.2 (Windows PowerShell 5.1 may not by default) and retries up to 3 times with backoff; failures are logged as `WEBHOOK_ERROR`.

## Sample alert

```
🚨 RDP brute-force detected
Host: 10.10.10.40
Source IP: 10.10.10.30
Target user: labuser
Failures: 5 in 2m
Last seen: 2026-11-20T03:14:22
```

## Setup (alert-only mode)

`Install.ps1` registers only the Phase 06 responder. For alert-only:

```powershell
Disable-ScheduledTask -TaskName 'HomeLab-RDP-Responder'
.\05-automated-monitoring-alerting\scripts\rdp_monitor_task.ps1
```

To go back: `Enable-ScheduledTask -TaskName 'HomeLab-RDP-Responder'` and `Disable-ScheduledTask -TaskName 'HomeLab-RDP-Monitor'`. Leaving both enabled also works: one alerts, the other blocks (and alerts).

## Smoke test

```powershell
& 'C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_monitor.ps1' -TestWebhook
```

Expected: `Test alert sent.` and a message in the channel within a few seconds. A red failure line points to the log.

## End-to-end check

1. On Windows: `.\Reset.ps1`, then `Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait -Tail 20`
2. On Kali: `./attacker/run-attack.sh`
3. Expect exactly one `SUSPECT: SourceIP=10.10.10.30 ...` line and one alert, not one per failure.

## Account lockout

Windows' account lockout policy counts failed logons independently of this pipeline. The threshold (5) sits below the usual lockout threshold (10) so the alert lands before the account is locked. The demo targets the decoy account `labuser`, so if repeated runs do lock something, it's an account nobody uses. Check the policy with `net accounts`.

## Next

Phase 06 adds active response: the same detection also blocks the source IP at the Windows Firewall, with an expiring banlist.
