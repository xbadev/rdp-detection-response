# RDP Brute-Force Monitoring and Alerting Scripts

This folder contains the monitoring and automation scripts introduced in **Phase 05**, which extend the Phase 04 detection logic into a continuously running monitoring and alerting pipeline.

The core detection logic remains unchanged. This phase focuses on **automation, persistence, and real-time alerting**.

---

## Scripts Overview

### `rdp_bruteforce_monitor.ps1`

This script continuously monitors Windows Security logs for suspicious RDP authentication failures and sends alerts when thresholds are exceeded.

#### What Changed from Phase 04

Compared to the Phase 04 detection script, this version adds:

- **Persistent execution** (designed to run repeatedly)
- **Local logging** to a dedicated log file
- **External alerting** via a Discord webhook
- **Silent behavior during normal conditions**
- **Optional webhook testing mode**

Detection thresholds and log parsing logic are intentionally reused to preserve consistency and accuracy.

#### How It Works

On each execution, the script:

1. Reads recent Event ID `4625` entries from the Security log
2. Filters for RDP-related failures (`LogonType = 3`)
3. Groups failures by source IP and target user
4. Evaluates activity against a configurable threshold
5. If suspicious behavior is detected:
   - Logs the event locally
   - Sends a real-time alert to Discord
6. If no suspicious activity is found:
   - Exits quietly after logging a single status line

The script is intentionally quiet during normal operation to avoid log and alert noise.

#### Key Features

- Configurable detection window and threshold
- Local execution logging (`rdp_monitor.log`)
- Secure webhook loading from a secrets file
- Explicit administrator privilege enforcement
- Test mode for validating webhook connectivity

---

### `rdp_monitor_task.ps1`

This script registers a Windows Scheduled Task that runs the monitoring script automatically.

#### Purpose

The scheduled task ensures the monitoring logic executes continuously without manual intervention.

#### Task Behavior

- Runs every **2 minutes**
- Executes under the **SYSTEM** account
- Runs with **highest privileges**
- Does not require a logged-in user session
- Automatically picks up script updates by path

This mirrors how background monitoring jobs are typically deployed in enterprise Windows environments.

---

## Execution Model

The two scripts work together as follows:

- `rdp_bruteforce_monitor.ps1`  
  → Performs detection, logging, and alerting

- `rdp_monitor_task.ps1`  
  → Ensures the monitor runs continuously and reliably

No manual execution is required once the task is registered.

---

## Summary

Phase 05 transitions the project from **manual detection** to **automated monitoring and alerting**.

These scripts establish:

- Continuous evaluation of RDP authentication activity
- Reliable alert delivery for high-risk behavior
- A stable foundation for automated response in Phase 06

The detection logic remains consistent, while automation and visibility are significantly expanded.
