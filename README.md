# RDP Detection & Response — Home Lab

Built an end-to-end host-based security pipeline on a Windows endpoint: from secure baseline to RDP exposure, brute-force detection, automated alerting, and firewall-level containment — using only native Windows logging, PowerShell, and host-based controls.

## Environment

| Component | Detail |
|-----------|--------|
| Endpoint | Windows VM |
| Attacker | Kali Linux VM |
| Network | VirtualBox Host-Only + NAT |
| Attack Surface | Remote Desktop Protocol (RDP) |
| Telemetry | Windows Security Event Log |
| Response | Windows Defender Firewall + Task Scheduler |

Network configuration and static IP addressing documented in [`network/`](./network/).

## Phases

| # | Phase | Description |
|---|-------|-------------|
| 01 | [Baseline Security Posture](./01-baseline/) | Documented default firewall behavior and confirmed all inbound traffic is blocked on a fresh Windows endpoint. |
| 02 | [Controlled Exposure](./02-controlled-exposure/) | Introduced scoped inbound ICMP access for a single source to validate firewall rule enforcement. |
| 03 | [Remote Access Attack Surface](./03-remote-access-surface/) | Enabled RDP and confirmed how exposing a single service changes the attack surface. |
| 04 | [Detection Logic](./04-detection-logic/) | Built PowerShell detection for RDP brute-force patterns using Event ID 4625 and LogonType filtering. |
| 05 | [Automated Monitoring & Alerting](./05-automated-monitoring-alerting/) | Automated detection into a continuous pipeline with Task Scheduler and real-time Discord webhook alerts. |
| 06 | [Automated Response](./06-automated-response/) | Implemented automated firewall blocking of attacker IPs with persistent ban tracking and alert notifications. |

Each phase has its own README with step-by-step documentation and inline evidence screenshots. Start at Phase 01 and progress sequentially.
