# Phase 06 — Automated Response & Containment

The full loop. A scheduled task runs the responder on every Security 4625 (and every 5 minutes as a sweep). The responder evaluates the recent window; when a source IP crosses the threshold it adds a Windows Firewall inbound block on TCP/3389 for that IP, records the ban with an expiry, and posts to the webhook. Expired bans are lifted automatically.

| Script | Purpose |
|---|---|
| [`scripts/rdp_bruteforce_responder.ps1`](scripts/rdp_bruteforce_responder.ps1) | Detect, block, record, alert, expire |
| [`scripts/rdp_responder_task.ps1`](scripts/rdp_responder_task.ps1) | (Re-)registers the responder task; `Install.ps1` already does this |

## State and config

| Path | Purpose |
|---|---|
| `C:\HomeLab\rdp-dr\config\lab.config.psd1` | Threshold, window, ban length, LabMode, paths |
| `C:\HomeLab\rdp-dr\config\rdp_allowlist.txt` | IPs that are never banned, one per line |
| `C:\HomeLab\rdp-dr\state\rdp_banlist.json` | Active bans with expiry times (SYSTEM + Admins only) |
| `C:\HomeLab\rdp-dr\state\last_reset.txt` | Written by `Reset.ps1`; failures before it are ignored |
| `C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt` | Webhook URL (SYSTEM + Admins only) |
| `C:\HomeLab\rdp-dr\logs\rdp_monitor.log` | Operational log: `BAN`, `UNBAN`, `ALREADY_BANNED`, `SKIP_*`, `WEBHOOK_ERROR`, `NO_SOURCE_IP` |

## One responder run

1. Read the banlist, lift expired bans (remove their `HomeLab-RDPBan-<ip>` rules), save.
2. Read 4625 / LogonType 3+10 failures since the later of `MinutesBack` ago or the last reset.
3. Group by (source IP, account); keep groups with `Count >= Threshold`.
4. For each group, in order:
   - **Allowlisted** → log `SKIP_ALLOWLIST`, skip.
   - **Private IP and `LabMode = $false`** → log `SKIP_PRIVATE_OR_LOCAL`, skip.
   - **Already banned** → log `ALREADY_BANNED`, skip. Bans are not extended.
   - Otherwise: create the firewall rule. **Only if that succeeds**, record the ban, save, log `BAN ... SecondsAfterLastFailure=N`, post the alert.

### Why runs are queued, and why that's safe

An attack writes several 4625s within a second or two, and each one triggers the task. The task is registered with `-MultipleInstances Queue`, so those runs execute one after another, and the last one always sees the full burst. With `IgnoreNew`, the first run could see fewer failures than the threshold while every other trigger was discarded, and the attack would never be blocked.

The extra queued runs are harmless because the responder is idempotent: after the first ban, every later run hits the "already banned" branch. No duplicate rules, no duplicate alerts.

### Why there's also a 5-minute sweep

Expired bans are only lifted when the responder runs. With only the event trigger, a quiet server (no new failed logons) would never run it, and an "expired" block would stay in place indefinitely. The task therefore also has a repeating 5-minute trigger, so a ban is lifted at most 5 minutes after it expires.

## `LabMode`

Production responders usually refuse to ban private IPs, so a misfire can't block the network's own gateway or admins. In this lab every host is private (Kali is `10.10.10.30`), so that default would make the responder a silent no-op.

| `LabMode` | Private / loopback / link-local source IPs |
|---|---|
| `$true` (default) | Can be banned; Kali gets blocked |
| `$false` | Skipped with `SKIP_PRIVATE_OR_LOCAL` (production behavior) |

The allowlist overrides both. Put the IP you administer the server from in it, so a fat-fingered password from your own machine can't lock you out of RDP.

## Setup

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1     # registers this task
```

Check the task has both triggers:

```powershell
(Get-ScheduledTask -TaskName 'HomeLab-RDP-Responder').Triggers |
    Select-Object @{n='Type';e={$_.CimClass.CimClassName}}, Enabled, Subscription
```

Expect an `MSFT_TaskEventTrigger` whose `Subscription` mentions `EventID=4625`, and an `MSFT_TaskTimeTrigger` for the sweep.

## Operator commands

```powershell
$r = 'C:\HomeLab\rdp-dr\scripts\rdp_bruteforce_responder.ps1'
& $r -TestWebhook                    # check webhook plumbing without an attack
& $r -ClearBans                      # remove all lab rules + empty banlist
.\Reset.ps1                          # the above, plus clear log + cooldowns + mark reset time

Get-NetFirewallRule -DisplayName 'HomeLab-RDPBan-*' | Format-Table DisplayName, Enabled, Action
Get-Content C:\HomeLab\rdp-dr\state\rdp_banlist.json | ConvertFrom-Json | Format-Table
Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait -Tail 30
```

## End-to-end check

1. On Windows: `.\Reset.ps1`, then tail the log.
2. On Kali: `./attacker/run-attack.sh`
3. Expect:
   - one `BAN: SourceIP=10.10.10.30 ...` line, followed by `ALREADY_BANNED` lines from the queued runs
   - `Get-NetFirewallRule -DisplayName 'HomeLab-RDPBan-10.10.10.30'` exists
   - the `RDP attacker blocked` alert in the channel
   - the attack script's final check reports 3389 unreachable from Kali
4. Note the `SecondsAfterLastFailure` value on the `BAN` line. That's the measured detection-to-block latency for this setup.
5. Leave it for `BanMinutes` (+ up to 5 for the sweep): expect `UNBAN: SourceIP=10.10.10.30` and the rule gone.

## Sample alert

```
⛔ RDP attacker blocked
Host: 10.10.10.40
Banned IP: 10.10.10.30
Target user: labuser
Failures: 5 in 2m
Blocked for: 30m (until 2026-11-20T03:44:22)
```

## Account lockout

Windows' lockout policy counts failed logons independently of this pipeline. The threshold (5) sits below the usual lockout threshold (10), so the network block normally lands first. The demo deliberately attacks a decoy account (`labuser`) rather than Administrator, because repeated runs within the lockout window add up; locking a decoy is harmless, while locking the admin you RDP in with is not. Check the policy with `net accounts`.

## How this compares to the SSH lab

Both labs separate detection from response, but in different places. The SSH lab runs them as two daemons connected by a JSONL file. Here, detection lives in the shared module, and there are two consumers of it: Phase 05 (alert only) and Phase 06 (block + alert). The Windows building blocks are the Security log instead of journald, Task Scheduler event triggers instead of a systemd service, and Windows Firewall instead of UFW/Fail2Ban.

The natural next steps beyond host-based containment are a SIEM forwarder for the Security log, GPO-managed firewall policy, and a SOAR playbook that opens a ticket for an analyst. They are deliberately out of scope here.
