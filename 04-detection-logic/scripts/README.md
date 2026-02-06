# RDP Authentication Failure Detection Script

This script detects suspicious Remote Desktop Protocol (RDP) authentication behavior on a Windows endpoint by analyzing native Windows Security logs.

It is designed to identify short bursts of repeated failed network logons that are consistent with brute-force or password-guessing attempts.

This script is the foundation for all later monitoring and response phases.

---

## Script Purpose

The script scans recent Windows authentication events and flags potential RDP brute-force activity based on:

- Repeated failed logons
- Network-based authentication attempts
- A configurable time window and threshold

It relies entirely on built-in Windows telemetry and PowerShell.

---

## Detection Logic Overview

The script performs the following steps:

1. Queries the Windows **Security** event log for failed authentication events  
   - Event ID: **4625**
2. Filters events to include **network logons only**  
   - `LogonType = 3`
3. Extracts key fields from each event:
   - Source IP address
   - Target username
   - Timestamp
   - Status and sub-status codes
   - Originating workstation
4. Groups failures by:
   - Source IP
   - Target username
5. Flags suspicious activity when failures exceed a defined threshold within a short time window

---

## Configurable Parameters

The script supports the following parameters:

- `-MinutesBack`  
  Defines how far back in time to analyze events  
  Default: `2` minutes

- `-Threshold`  
  Minimum number of failed attempts required to trigger detection  
  Default: `5` failures

**Example:**

`powershell`
.\rdp_failed_logon_detection.ps1 -MinutesBack 3 -Threshold 6 

---

## Privilege Requirements

Reading the Windows Security log requires **Administrator privileges**.

The script explicitly checks for elevation and exits with a clear error message if run without sufficient permissions. This prevents silent failures or misleading output.

---

## Output Behavior

- If no failed logons are found, the script exits cleanly  
- If failed logons exist but do not exceed the threshold, the script reports normal behavior  
- If suspicious bursts are detected, the script prints:
  - Source IP address  
  - Target username  
  - Number of failed attempts  
  - Recent authentication timestamps and context  

The output is intentionally human-readable to support manual validation and tuning.

---

## Role in the Lab

This script provides **visibility only**.

It does **not**:
- Block traffic  
- Modify firewall rules  
- Send alerts  
- Persist state  

Later phases build directly on this logic to introduce continuous monitoring, alerting, and automated response **without modifying this original detection script**.

---

## Summary

This script establishes reliable, high-signal detection of RDP authentication abuse using native Windows logs. It serves as the analytical baseline for all subsequent automation in the Windows endpoint lab.
