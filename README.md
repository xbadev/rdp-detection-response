# Windows Endpoint Security Lab

This lab documents the design, exposure, monitoring, detection, and automated response of a Windows endpoint in a controlled homelab environment.

The project demonstrates how a Windows system transitions from a secure default posture to an actively defended endpoint capable of detecting and automatically responding to real-world authentication abuse.

The lab is structured as a series of incremental phases, each building on the previous one to form a complete host-based security pipeline.

---

## Lab Objectives

The primary goals of this lab are to:

- Establish a secure baseline for a Windows endpoint
- Introduce controlled network and service exposure
- Analyze Windows authentication telemetry
- Detect suspicious RDP authentication behavior
- Automate alerting and containment actions
- Mirror enterprise-style detection and response workflows

All detection and response logic relies on **native Windows logging**, **PowerShell**, and **host-based controls**.

---

## Environment Overview

- **Endpoint:** Windows VM
- **Attacker Systems:** Kali Linux VM, host system
- **Network:** VirtualBox Host-Only + NAT
- **Attack Surface:** Remote Desktop Protocol (RDP)
- **Telemetry Source:** Windows Security Event Log
- **Response Mechanism:** Windows Defender Firewall + scheduled tasks

---

## Lab Structure

Each phase is isolated into its own directory with a dedicated README and supporting evidence.

### Phase Breakdown

#### Phase 01 – Baseline Security Posture
Establishes the default firewall behavior and inbound traffic restrictions of a fresh Windows endpoint.

📁 **[`01-baseline/`](./01-baseline/)**

---

#### Phase 02 – Controlled Exposure
Introduces narrowly scoped inbound ICMP access to validate firewall rule scoping and least-privilege exposure.

📁 **[`02-controlled-exposure/`](./02-controlled-exposure/)**

---

#### Phase 03 – Remote Access Attack Surface
Enables Remote Desktop Protocol (RDP) and confirms how exposing a single service changes the attack surface.

📁 **[`03-remote-access-surface/`](./03-remote-access-surface/)**

---

#### Phase 04 – Detection Logic
Builds reliable detection for suspicious RDP authentication failures using Windows Security logs and PowerShell.

📁 **[`04-detection-logic/`](./04-detection-logic/)**

---

#### Phase 05 – Automated Monitoring and Alerting
Transitions from manual detection to continuous monitoring with automated alert generation.

📁 **[`05-automated-monitoring-alerting/`](./05-automated-monitoring-alerting/)**

---

#### Phase 06 – Automated Response and Containment
Implements a fully automated responder that blocks attacker IPs, tracks bans persistently, and issues real-time alerts.

📁 **[`06-automated-response/`](./06-automated-response/)**

---

## Network Configuration

The Windows endpoint uses a dual-adapter design to separate internal lab traffic from external connectivity.

- **Host-Only Adapter:** Internal lab communication
- **NAT Adapter:** Outbound internet access

Static IP addressing and interface separation are documented here:

📁 **[`network/`](./network/)**

---

## Key Capabilities Demonstrated

Across all phases, this lab demonstrates:

- Secure default Windows firewall behavior
- Controlled service exposure
- Precise authentication telemetry analysis
- High-signal brute-force detection
- Automated alerting pipelines
- Host-based containment via firewall enforcement
- Persistent state tracking for automated responses
- SOC-style separation of detection, monitoring, and response duties

---

## Design Philosophy

This lab was built with the following principles:

- **Incremental exposure:** Nothing is enabled without validation
- **Separation of duties:** Detection, monitoring, and response are isolated
- **Native tooling first:** No third-party agents required
- **Reproducibility:** Every phase is documented with evidence
- **Enterprise realism:** Mirrors real-world endpoint security workflows

---

## Outcome

At the conclusion of this lab, the Windows endpoint operates as an actively defended system with:

- Continuous authentication monitoring
- Automated detection of RDP abuse
- Immediate host-level containment
- Persistent ban management with expiration
- Real-time alerting for operator visibility

This completes an end-to-end host-based detection and response pipeline on Windows.

---

## Navigation Tip

Each phase README contains:

- Clear objectives
- Step-by-step actions
- Security findings
- Outcome summaries
- Inline, clickable evidence screenshots

Start at Phase 01 and progress sequentially to see the full evolution of the endpoint.

---

