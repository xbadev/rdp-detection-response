# RDP Detection & Response — Home Lab

End-to-end RDP brute-force detection and response on Windows Server. A scheduled task with an **event trigger** runs on every Security log 4625 (failed logon); a shared PowerShell module groups the recent failures by source IP and account; when one crosses the threshold, the responder adds a Windows Firewall block on TCP/3389 for that IP, records the ban with an expiry, and posts to a webhook. No polling interval: the response starts from the failure itself.

The lab runs on Proxmox VE with two VMs on an isolated internal subnet: Windows Server as the target, Kali Linux as the attacker. Companion repo: [ssh-detection-response](https://github.com/xbadev/ssh-detection-response) (same pattern on Linux).

## Environment

| Component | Detail |
|-----------|--------|
| Hypervisor | Proxmox VE (see [proxmox-homelab](https://github.com/xbadev/proxmox-homelab)) |
| Target | Windows Server 2025, Desktop Experience (180-day evaluation) — `10.10.10.40` |
| Attacker | Kali Linux — `10.10.10.30` |
| Internal network | `10.10.10.0/24` on Proxmox bridge `vmbr1` (no uplink) |
| External network | Proxmox bridge `vmbr0` (DHCP; internet for updates, activation, webhook) |
| Attack surface | Remote Desktop (TCP/3389, Network Level Authentication on) |
| Telemetry | Security log, Event ID 4625, LogonType 3 (NLA) or 10 (no NLA) |
| Trigger | Task Scheduler event trigger on Security 4625 (`MSFT_TaskEventTrigger`) |
| Response | Windows Firewall block rule + expiring banlist + Discord webhook |
| Runtime | Windows PowerShell 5.1 (built in; nothing to install) |

## Quick demo

On the Windows Server target, in an **elevated** PowerShell:

```powershell
git clone https://github.com/xbadev/rdp-detection-response.git   # or download the ZIP
cd rdp-detection-response
powershell -ExecutionPolicy Bypass -File .\Install.ps1           # prompts for the webhook URL
net user labuser 'Choose-A-Long-Unique-Passw0rd!' /add           # optional decoy account
```

On Kali:

```bash
git clone https://github.com/xbadev/rdp-detection-response.git
cd rdp-detection-response
./attacker/run-attack.sh
```

The attack sends six wrong passwords to the decoy account `labuser`. Expected on the target:

1. Each failure writes a 4625; each 4625 queues a run of the responder.
2. The run that sees the 5th failure blocks `10.10.10.30` on 3389 and posts the alert.
3. The 6th attempt can't connect; the script's post-attack check reports 3389 unreachable from Kali.

Watch it live with `Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait -Tail 20`. Every `BAN:` line includes `SecondsAfterLastFailure`, the measured time from the last failed logon to the block. Run `.\Reset.ps1` between demos.

## Phases

| # | Phase | What it does |
|---|-------|---|
| 01 | [Baseline](./01-baseline/) | Default Windows Firewall posture: inbound denied, outbound allowed |
| 02 | [Controlled Exposure](./02-controlled-exposure/) | ICMP allowed from Kali only, proving source-scoped rules work before exposing a real service |
| 03 | [Remote Access Surface](./03-remote-access-surface/) | RDP enabled; 3389 confirmed open and authenticating |
| 04 | [Detection Logic](./04-detection-logic/) | On-demand detection: 4625 → LogonType filter → per-(IP, user) threshold |
| 05 | [Monitoring & Alerting](./05-automated-monitoring-alerting/) | Alert-only mode: event-triggered, webhook with per-IP cooldown, no blocking |
| 06 | [Automated Response](./06-automated-response/) | Full loop: event-triggered responder blocks, persists, alerts, expires bans |

## Architecture

```
┌──────────────┐  RDP brute-force   ┌───────────────────────────────────────────────┐
│ Kali         │ ─────────────────► │ Windows Server  10.10.10.40                   │
│ 10.10.10.30  │                    │                                               │
└──────────────┘                    │  LSASS / CredSSP ──writes──► Security log     │
       ▲                            │                                  │ 4625       │
       │                            │                    event trigger ▼            │
       │                            │                     Task Scheduler (queued)   │
       │                            │                                  │            │
       │                            │                                  ▼            │
       │   block TCP/3389           │                  rdp_bruteforce_responder.ps1 │
       └────────────────────────────┼── Windows Firewall ◄──────┤                   │
                                    │        rdp_banlist.json ◄──┤                   │
                                    │                            └──► webhook ──────┼──► Discord
                                    └───────────────────────────────────────────────┘
```

The same 4625 that triggers the task is evaluated by the run it starts, along with the rest of the last `MinutesBack` minutes. No poller, no tick interval.

## Configuration

`C:\HomeLab\rdp-dr\config\lab.config.psd1` (installed from [`lab.config.psd1`](./lab.config.psd1)). Edits apply on the next event; nothing to restart. Re-running `Install.ps1` keeps your edits.

| Setting | Default | Effect |
|---|---|---|
| `Threshold` | 5 | Failures from one IP against one account to act on; below the default lockout threshold (10) |
| `MinutesBack` | 2 | Window the threshold is counted in |
| `BanMinutes` | 30 | Firewall block duration |
| `AlertCooldownMinutes` | 10 | Phase 05 only: minimum gap between alerts for the same IP |
| `LabMode` | `$true` | `$true`: private IPs can be banned (Kali is private). `$false`: production behavior, private IPs skipped |

## Scripts

| Script | Purpose |
|---|---|
| `Install.ps1` | Enables failed-logon auditing, installs to `C:\HomeLab\rdp-dr`, locks down `secrets\` and `state\`, stores the webhook, registers the event-triggered task, smoke-tests |
| `Reset.ps1` | Clears bans, firewall rules, cooldowns, and the log; marks the reset time so older failures are ignored |
| `Uninstall.ps1` | Removes tasks, firewall rules, and the install tree |
| `attacker/run-attack.sh` | Kali side: six passwords via Hydra (default) or NetExec, then checks whether 3389 is still reachable |

## Tests and CI

[`tests/RdpDetection.Tests.ps1`](./tests/RdpDetection.Tests.ps1) holds Pester 5 unit tests for the module: IP classification, threshold grouping (including the empty and single-record cases), banlist round-trips, ban expiry, and alert cooldowns. The Security log and firewall are mocked.

[`ci.yml`](./.github/workflows/ci.yml) runs on every push, on GitHub's Windows runner: it parses every file with the real Windows PowerShell 5.1 parser, runs PSScriptAnalyzer and the Pester tests, and on Linux it runs shellcheck plus an ASCII-only check on all PowerShell files (5.1 misreads UTF-8 punctuation in BOM-less files).

## Design notes for reviewers

- **Why an event trigger, not a poller:** the original version ran every 2 minutes, so worst-case response was ~2 minutes after the attack. `MSFT_TaskEventTrigger` starts the responder from the failure itself; `New-ScheduledTaskTrigger` can't build event triggers, so the module instantiates the CIM class directly (`Register-LabEventTask`).
- **Why queued instances:** a brute-force burst writes several 4625s within a second or two. With `IgnoreNew`, the run started by the first event can see fewer failures than the threshold while every other trigger is discarded, so the attack is never acted on. `Queue` guarantees a run after the last event. Runs are idempotent, so the extra ones just log `ALREADY_BANNED`.
- **Why `LabMode`:** production responders usually refuse to ban private IPs so they can't lock out their own network. In a lab where the attacker is `10.10.10.30`, that default makes the responder a silent no-op. The flag makes the choice explicit.
- **PowerShell 5.1 pitfalls handled:** functions that return collections are always called inside `@()` (zero items become `$null`, one becomes a scalar, and `.Count` on either throws under strict mode); array parameters that can legitimately be empty carry `[AllowEmptyCollection()]`; event XML is read via `InnerText`; all scripts are ASCII.
- **Decoy target account:** the demo attacks `labuser`, not Administrator. Repeated runs add up toward account lockout; locking a decoy costs nothing.
