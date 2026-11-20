# RDP Detection & Response — Home Lab

End-to-end RDP brute-force detection and response pipeline on Windows. An event-triggered scheduled task fires on every Security log 4625 event, a shared PowerShell module groups failures by source IP and target user, and crossing the threshold drops a Windows Firewall block rule on TCP/3389 and posts to a webhook. Attacker-to-block latency: ~5 seconds.

The lab runs on a Proxmox VE hypervisor with two VMs on an isolated internal subnet — Windows 10 as the target, Kali Linux as the attacker. Companion to [ssh-detection-response](https://github.com/xbadev/ssh-detection-response), which does the same thing on Linux/SSH.

## Environment

| Component | Detail |
|-----------|--------|
| Hypervisor | Proxmox VE 9.x (see [proxmox-homelab](https://github.com/xbadev/proxmox-homelab)) |
| Target | Windows 10 — `10.10.10.40` |
| Attacker | Kali Linux — `10.10.10.30` |
| Internal network | `10.10.10.0/24` on Proxmox bridge `vmbr1` (no internet exposure) |
| External network | Proxmox bridge `vmbr0` (DHCP, internet egress only) |
| Attack surface | Remote Desktop Protocol (TCP/3389) |
| Telemetry | Windows Security event log, Event ID 4625, LogonType 3 |
| Detection | Event-triggered scheduled task fires on every 4625 |
| Response | Windows Firewall block rule + persistent banlist + Discord webhook |
| Latency | Attack to firewall block + webhook: ~5 seconds |

## Quick demo

On the Windows target, in elevated PowerShell:

```powershell
git clone https://github.com/xbadev/rdp-detection-response.git
cd rdp-detection-response
.\Install.ps1                       # prompts for webhook URL, registers task
```

On the Kali attacker:

```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -t 4 -V rdp://10.10.10.40
```

Within ~5 seconds, the attacker IP is firewall-blocked and a Discord alert lands. To watch the pipeline live on the target:

```powershell
Get-Content C:\HomeLab\rdp-dr\logs\rdp_monitor.log -Wait -Tail 20
```

## Phases

| # | Phase | What it does |
|---|-------|---|
| 01 | [Baseline](./01-baseline/) | Documented default Windows Firewall posture — inbound denied, outbound allowed |
| 02 | [Controlled Exposure](./02-controlled-exposure/) | Scoped ICMP rule allowing only the attacker IP — validates source-level firewall enforcement |
| 03 | [Remote Access Surface](./03-remote-access-surface/) | Enabled RDP, confirmed port 3389 listening and reachable |
| 04 | [Detection Logic](./04-detection-logic/) | Standalone detection script — Event ID 4625, LogonType 3, group-by-IP threshold |
| 05 | [Monitoring & Alerting](./05-automated-monitoring-alerting/) | Alert-only mode — webhook on threshold, no firewall action |
| 06 | [Automated Response](./06-automated-response/) | Full responder — event-triggered task fires the responder which bans, persists, and alerts |

## Architecture

```
┌──────────────┐   RDP brute-force    ┌────────────────────────────────────────┐
│ Kali         │ ───────────────────► │  Windows endpoint                       │
│ 10.10.10.30  │                      │  10.10.10.40                            │
└──────────────┘                      │                                         │
                                      │  ┌──────────────────┐                   │
                                      │  │ LSASS (RDP auth) │                   │
                                      │  └────────┬─────────┘                   │
                                      │           │ writes 4625                 │
                                      │           ▼                             │
                                      │  ┌──────────────────┐                   │
                                      │  │ Security log     │                   │
                                      │  └────────┬─────────┘                   │
                                      │           │ task event-trigger          │
                                      │           ▼                             │
                                      │  ┌──────────────────┐                   │
                                      │  │ rdp_responder.ps1│                   │
                                      │  └────────┬─────────┘                   │
                                      │           │                             │
                                      │           ├─► Windows Firewall (block)  │
                                      │           ├─► rdp_banlist.json (state)  │
                                      │           └─► Discord webhook ──────────┼──► Discord
                                      └─────────────────────────────────────────┘
```

The same Security log entry that triggers the task is the entry the responder reads back. No polling, no ticks — the OS notifies the task scheduler that a 4625 was written, the task fires, the responder evaluates the last `MinutesBack` minutes of failures.

## Configuration

All settings live in `C:\HomeLab\rdp-dr\config\lab.config.psd1`. See [`lab.config.psd1`](./lab.config.psd1) at the repo root for the reference copy. Edit, save, then any subsequent task firing picks up the new values. No restart needed.

Key values:

| Setting | Default | Effect |
|---|---|---|
| `Threshold` | 5 | Failures from one IP to trigger a ban |
| `MinutesBack` | 2 | Sliding window for the threshold |
| `BanMinutes` | 30 | Firewall block duration |
| `LabMode` | `$true` | When `$true`, private IPs (like Kali at 10.10.10.30) ARE banned. Set to `$false` for production behavior. |

## Top-level scripts

| Script | Purpose |
|---|---|
| `Install.ps1` | First-time install — creates dir tree, copies files, locks ACLs, prompts for webhook, registers event-triggered task |
| `Reset.ps1` | Wipes runtime state (banlist, logs, firewall rules) — leaves config and task in place |
| `Uninstall.ps1` | Full removal — task, firewall rules, install tree, env var |

## Notes for reviewers

- The detector and responder share `Lib/RdpDetection.psm1` — single source of truth for 4625 ingestion, XML parsing, threshold logic, webhook delivery, banlist, and firewall manipulation. Phase scripts are thin orchestration layers.
- Event-triggered scheduled tasks (`MSFT_TaskEventTrigger`) are the native Windows mechanism for "fire on a Security log entry." This replaces the original repo's 2-minute polling task, dropping latency by ~24x.
- The responder is idempotent — same IP triggering multiple times within the ban window does not create duplicate firewall rules or extend the ban.
- Banlist state lives in `C:\HomeLab\rdp-dr\state\rdp_banlist.json` with expiration timestamps. Each run prunes expired bans and removes their firewall rules — no manual cleanup ever needed.
- Allowlist at `C:\HomeLab\rdp-dr\config\rdp_allowlist.txt` always overrides ban logic. Add management/admin IPs there.
- `LabMode` is the toggle that lets the lab work — Kali is on a private subnet, and a production-correct responder would skip private IPs. The flag makes that explicit and reversible.

## Related

- [ssh-detection-response](https://github.com/xbadev/ssh-detection-response) — Linux/SSH equivalent. Same pattern, same conventions, journald instead of Event Log.
- [proxmox-homelab](https://github.com/xbadev/proxmox-homelab) — hypervisor and bridge configuration.
