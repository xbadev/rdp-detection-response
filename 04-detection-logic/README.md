# Phase 04 - RDP Authentication Failure Detection

## Objective

Establish reliable detection for suspicious Remote Desktop Protocol (RDP) authentication activity on the Windows endpoint by analyzing native Windows security logs.

This phase focuses on identifying failed RDP logon patterns consistent with brute-force or password-guessing behavior, using only built-in Windows telemetry and PowerShell.

The goal is visibility and signal quality rather than prevention, forming the foundation for automated alerting and response in later phases.

---

## Context and Threat Model

After Phase 03, the Windows endpoint exposes Remote Desktop Protocol (TCP 3389) to the internal network. While this mirrors common enterprise environments, it introduces a high-value authentication attack surface.

RDP abuse rarely involves immediate exploitation. Instead, it typically manifests as repeated authentication failures over a short time window. Effective detection therefore depends on correctly interpreting Windows authentication telemetry rather than relying on service-level alerts.

---

## Windows Authentication Telemetry Overview

Windows does not log “RDP attacks” directly.  
All authentication activity is recorded in the **Security** event log.

Two event types are critical:

- **Event ID 4624:** Successful logon  
- **Event ID 4625:** Failed logon  

Only failed logons are relevant for brute-force detection. However, these events must be filtered carefully to avoid noise from unrelated system activity.

---

## Identifying RDP-Relevant Failures

### Logon Type Analysis

Inspection of failed logon events (Event ID 4625) revealed that RDP authentication failures are recorded as:

- **LogonType = 3 (Network logon)**

This distinction is critical. Without filtering on LogonType, detection logic would incorrectly include:

- Local console login failures  
- Service account authentication  
- Background system activity  

- **[4625-logon-failure-details.png](evidence/4625-logon-failure-details.png)**  
  Detailed view of a failed authentication event (Event ID 4625), showing LogonType, source IP address, target username, and workstation name.

- **[failed-logon-workstation-and-ipaddress.png](evidence/failed-logon-workstation-and-ipaddress.png)**  
  Event data highlighting the originating workstation and source IP address used for correlation and grouping.

---

### Signal Reduction Using Advanced Filtering

To isolate RDP-related failures only, an advanced XML filter was applied in Event Viewer using the following constraints:

- **Event ID = 4625**  
- **LogonType = 3**

This filtering strategy removes:

- Local login failures  
- Non-interactive authentication attempts  
- Background system noise  

- **[XML-detection-filter.png](evidence/XML-detection-filter.png)**  
  Advanced XML filter applied in Event Viewer to isolate RDP-related authentication failures.

- **[XML-detection-filter-result.png](evidence/XML-detection-filter-result.png)**  
  Filtered Security log output demonstrating a reduced, high-signal dataset suitable for detection logic.

---

## Detection Logic Design

### Core Conditions

The detection logic is based on the following criteria:

- Failed authentication events (Event ID 4625)  
- Network logons only (LogonType 3)  
- Aggregation by:
  - Source IP address  
  - Target username  
  - Time window  

---

### Threshold Selection

A detection threshold of:

- **5 failed attempts within 2 minutes**

was selected based on the following reasoning:

- Human users may occasionally mistype credentials  
- Automated attacks generate rapid, repeated failures  
- This threshold balances sensitivity with false-positive reduction  

This mirrors common SOC heuristics used in enterprise detection environments.

---

## PowerShell Detection Implementation

### Script Purpose

A custom PowerShell script was developed to operationalize the detection logic by:

- Querying recent Security log events  
- Parsing event XML to extract relevant fields  
- Filtering for RDP-related failures only  
- Aggregating failures by source IP and target user  
- Flagging suspicious authentication bursts  
- Presenting results in a clear, readable format  

---

### Security Considerations

Access to the Windows Security log requires elevated privileges.

To prevent silent failures or misleading output:

- The script explicitly checks for Administrator permissions  
- Execution halts with a clear error if insufficient privileges are detected  

- **[run-script-not-elevated-error.png](evidence/run-script-not-elevated-error.png)**  
  Error output produced when the detection script is executed without elevated privileges.

- **[add-administrator-requirement-clarity.png](evidence/add-administrator-requirement-clarity.png)**  
  Script behavior demonstrating explicit enforcement of Administrator privileges.

Execution policy restrictions were handled to allow controlled script execution without weakening overall system security.

- **[executionpolicy.png](evidence/executionpolicy.png)**  
  Execution policy configuration allowing controlled PowerShell script execution.

---

## Detection Validation

The detection logic was validated through controlled testing:

- Normal system behavior produced no alerts  
- Multiple failed RDP login attempts were generated intentionally  

- **[run-script-as-administrator.png](evidence/run-script-as-administrator.png)**  
  Successful script execution with proper privileges.

- **[script-failed-logon-detection-result-cli.png](evidence/script-failed-logon-detection-result-cli.png)**  
  Command-line output showing detected suspicious RDP authentication activity, including source IP, target account, failure count, and timestamps.

This confirmed that the detection logic functions as intended under realistic conditions.

---

## Outcome

At the end of this phase, the Windows endpoint is capable of reliably detecting suspicious RDP authentication behavior using native logging and custom analysis.

The system now provides:

- High-signal visibility into RDP abuse patterns  
- Clear differentiation between benign user error and malicious activity  
- A solid analytical foundation for alerting and response automation  

---

## What This Phase Enables

With reliable RDP authentication failure detection in place, the Windows endpoint now produces actionable security signals.

This phase enables:

- Real-time identification of suspicious RDP login behavior  
- Confidence that authentication abuse is distinguishable from normal usage  
- Structured telemetry suitable for automation  
- A trustworthy trigger for alerting without excessive false positives  

Most importantly, this phase converts raw Windows event logs into meaningful security signals, making automated alerting and response both feasible and reliable.
