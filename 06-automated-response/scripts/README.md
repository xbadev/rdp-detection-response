# Automated RDP Brute-Force Response (Phase 06)

This phase represents the **final evolution** of the Windows endpoint lab:  
moving from **detection and alerting** to **automated containment**.

Phase 06 builds directly on Phase 05 and adds **real defensive action** while preserving safety, control, and repeatability.

---

## Scripts in This Folder

- **Responder logic:** [`rdp_bruteforce_responder.ps1`](rdp_bruteforce_responder.ps1)  
- **Scheduled task installer:** [`rdp_responder_task.ps1`](rdp_responder_task.ps1)

---

## What Changed From Phase 05 → Phase 06

### Phase 05 (Monitoring & Alerting)

In Phase 05, the system could:

- Detect repeated failed RDP authentication attempts (Event ID 4625)
- Log suspicious activity to disk
- Send Discord alerts when thresholds were exceeded
- Run automatically using a scheduled task

**Limitation:**  
Phase 05 was **observational only**.  
It notified the operator but required **manual intervention** to stop the attack.

---

### Phase 06 (Automated Response)

Phase 06 closes that gap by adding **automated response and state management**.

New capabilities include:

- **Automatic firewall containment**
  - Offending source IPs are blocked via Windows Defender Firewall (TCP/3389)
- **Time-based bans**
  - Each ban has a defined expiration (`-BanMinutes`)
- **Persistent state**
  - Active and historical bans are tracked in `rdp_banlist.json`
- **Idempotent execution**
  - The script safely runs every cycle without duplicating or extending bans
- **Automatic cleanup**
  - Expired bans are removed and firewall rules are deleted automatically
- **Operator control modes**
  - Test webhook delivery
  - Clear all bans and reset state safely

**Result:**  
The system now **detects, alerts, and responds automatically** with no human involvement.

---

## Why This Matters

Phase 06 transforms the lab from a **monitoring tool** into a **host-based defensive control**.

This mirrors real-world security operations where:

- Detection without response is incomplete
- Response must be automated, repeatable, and reversible
- State must persist across executions
- Safety mechanisms are required to avoid self-inflicted outages

This phase demonstrates how a Windows endpoint can enforce security **using only native telemetry and controls**, without external agents or SIEMs.

---

## Key Script Capabilities

- Detects failed RDP logons using Windows Security Event ID 4625
- Groups failures by source IP and target user
- Applies firewall blocks only when thresholds are exceeded
- Skips allowlisted, local, and private IP ranges
- Sends Discord alerts for each new containment action
- Maintains long-term state across runs
- Cleans up expired rules automatically

---

## Runtime Flexibility (Parameters)

The responder supports runtime tuning without code changes:

- `-MinutesBack` — log inspection window  
- `-Threshold` — failures required to trigger containment  
- `-BanMinutes` — duration of firewall block  
- `-TestWebhook` — validate alerting path  
- `-ClearBans` — reset firewall rules and ban state  

---

## Scheduled Task Role

The scheduled task enables:

- Execution every 2 minutes
- SYSTEM-level privileges for log access and firewall control
- Continuous protection even without an active user session

This task is the **enforcement layer** that turns logic into protection.

---

## Summary

Phase 06 completes the Windows endpoint lab by moving beyond detection and alerting into **automated defense**.  
The system continuously monitors RDP authentication failures, applies firewall-based containment when abuse thresholds are met, and safely reverses those actions when bans expire.

By combining native Windows event logs, persistent state tracking, scheduled execution, and controlled response logic, this phase demonstrates how a single endpoint can autonomously enforce security controls with no manual intervention.

This final stage reflects real-world endpoint protection principles: detect reliably, respond automatically, avoid self-lockout, and remain stable across repeated execution.
