# Phase 01 - Baseline Security Posture

## Objective

Establish and validate the default network security posture of a Windows endpoint before introducing any controlled exposure. This phase confirms how the system behaves with no custom firewall rules or services enabled.

The goal is to understand what traffic is permitted or denied by default and to create a clean reference point for all subsequent security changes.

---

## Environment Context

- **Attacker System:** Kali Linux VM  
- **Target System:** Windows endpoint VM  
- **Network:** VirtualBox Host-Only network (internal lab segment)

Both systems reside on the same internal subnet and are able to reach each other at the network layer.

---

## Actions Performed

To validate baseline behavior, the following checks were performed.

### 1. Neighbor Discovery and Address Confirmation

The Kali system enumerated local network neighbors to identify the Windows endpoint and confirm Layer 2 adjacency.

### 2. Outbound Connectivity Validation (Windows → Kali)

The Windows endpoint initiated ICMP echo requests to the Kali system. Responses were successfully received, confirming:

- Network connectivity exists
- Outbound traffic from Windows is permitted by default

### 3. Inbound Connectivity Test (Kali → Windows)

The Kali system attempted ICMP echo requests to the Windows endpoint. All requests failed, indicating inbound traffic was blocked.

### 4. Firewall Configuration Verification

Windows Defender Firewall with Advanced Security was inspected to validate the observed behavior. The firewall was confirmed to be enabled, with inbound connections blocked unless explicitly allowed.

### 5. ICMP Rule Inspection

Inbound rules related to ICMP (Echo Request - ICMPv4-In) were reviewed and found to be disabled by default under the **File and Printer Sharing** rule group.

---

## Security Findings

The baseline assessment confirmed the following:

- Windows Defender Firewall is enabled and enforcing policy
- Inbound traffic is denied by default unless explicitly allowed
- ICMP echo requests to the Windows endpoint are blocked
- Outbound traffic from the Windows endpoint is permitted
- The system is not externally discoverable via basic ICMP probing

This behavior represents a secure default posture for a standalone Windows endpoint on an internal network.

---

## Outcome

This phase establishes a verified baseline showing that the Windows endpoint is not exposed to unsolicited inbound traffic. Any future change in reachability can now be directly attributed to deliberate configuration decisions rather than default behavior.

---

## What This Phase Enables

With the baseline confirmed, subsequent phases can safely introduce controlled exposure to specific protocols and sources while measuring the exact impact of each change against this known-good starting point.
