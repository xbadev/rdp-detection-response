# Phase 06 – Automated RDP Response and Containment

## Objective

Move from passive security monitoring to **active, automated containment** of malicious behavior on a Windows endpoint.

This phase implements a host-based response mechanism that automatically reacts to repeated RDP authentication failures by enforcing temporary firewall bans against attacking source IPs and issuing real-time alerts.

The goal is to demonstrate how endpoint telemetry can drive **immediate defensive action without human intervention**, closely mirroring real-world enterprise response workflows.

---

## Context and Threat Model

By the end of Phase 05, the Windows endpoint continuously monitored RDP authentication activity and generated alerts when brute-force behavior was detected.

However, **alerting alone does not stop an attack**.

In production environments, sustained authentication abuse must be contained quickly to prevent account lockouts, service degradation, or lateral movement attempts. This phase introduces an automated responder that actively reduces the attack surface as soon as malicious behavior is identified.

---

## Design Philosophy and Separation of Duties

A key design decision in this phase was to preserve the integrity of earlier phases.

Rather than modifying existing detection or monitoring scripts:

- The finalized monitoring logic was **copied into a new responder script**
- Original detection and monitoring scripts remain unchanged
- Each script has a single, clearly defined responsibility

This creates a clean separation:

- **Detection:** Identify suspicious activity  
- **Monitoring:** Evaluate activity continuously and alert  
- **Response:** Enforce containment actions  

This mirrors real SOC pipelines, where response tooling builds on validated detection logic without altering upstream components.

---

## Automated Responder Architecture

### Stateless Execution with Persistent Memory

The responder script is designed to run repeatedly on a fixed schedule. Each execution:

- Evaluates recent failed RDP authentication events
- Determines whether thresholds are exceeded
- Takes action only when necessary

To avoid losing context between executions, the responder maintains a **persistent state file** stored locally on the endpoint.

- **[banlist-json-file-tracking-banned-ips-shows-kali-and-windows-host-banned-ips.png](evidence/banlist-json-file-tracking-banned-ips-shows-kali-and-windows-host-banned-ips.png)**  
  Persistent banlist state file tracking attacker IPs, failure counts, timestamps, and ban expiration values.

This state file tracks:

- Attacker source IP address
- Targeted username
- Failure count
- First and last observed timestamps
- Ban expiration time

By loading and updating this state on every run, the responder avoids duplicate enforcement and automatically expires bans without manual cleanup.

---

## Response Logic and Containment Strategy

When repeated RDP failures exceed the configured threshold within a short time window, the responder performs three actions atomically:

1. Creates a Windows Defender Firewall rule blocking inbound traffic from the attacker IP
2. Records the ban in the persistent state file with an expiration timestamp
3. Emits an alert describing the incident and the action taken

- **[logging-the-ban-successfully.png](evidence/logging-the-ban-successfully.png)**  
  Local responder logs showing successful firewall enforcement and ban registration.

The firewall rule operates at the host level, immediately cutting off access to the RDP service regardless of authentication outcomes.

This ensures the response **stops the attack path itself**, not just the login attempts.

---

## Scheduling and Autonomous Execution

### Task Scheduler Integration

To ensure continuous protection, the responder runs automatically using Windows Task Scheduler.

As part of this phase:

- The previous monitoring-only scheduled task was explicitly removed  
- A new responder task was registered to execute on a recurring interval  

- **[Unregister-previous-scheduled-task-command.png](evidence/Unregister-previous-scheduled-task-command.png)**  
  Removal of the prior monitoring-only scheduled task.

- **[register-new-responder-task.png](evidence/register-new-responder-task.png)**  
  Registration of the automated responder task with elevated privileges.

The task:

- Runs with highest privileges  
- Does not require an active user session  
- Executes the responder script by file path  

- **[directories-files-created-by-the-script-auto-run.png](evidence/directories-files-created-by-the-script-auto-run.png)**  
  Automatic creation of responder directories and files during scheduled execution.

This design allows script updates to be picked up automatically without reconfiguring the task.

---

## Handling Windows Account Lockout Interference

During testing, Windows’ built-in account lockout policy could prematurely stop brute-force attempts before the responder acted.

To ensure the responder was responsible for containment:

- The account lockout threshold was temporarily increased  

- **[increase-account-lockout-threshold.png](evidence/increase-account-lockout-threshold.png)**  
  Temporary adjustment of account lockout policy to allow responder-driven containment.

This ensured the firewall ban was applied **before** the OS account lockout mechanism triggered.

---

## Validation Through Controlled Attacks

### Multi-Source Attack Simulation

The responder was validated using controlled RDP brute-force attempts from multiple sources:

- Kali Linux attacker VM using Hydra
- Repeated failed logons via MSTSC

- **[kali-not-showing-rdp-open-port-and-failing-hydra-after-ban.png](evidence/kali-not-showing-rdp-open-port-and-failing-hydra-after-ban.png)**  
  Kali scan and Hydra attempts failing after firewall ban enforcement.

- **[rdp-from-windows-host-banned.png](evidence/rdp-from-windows-host-banned.png)**  
  RDP connection attempts from a banned Windows host blocked at the network layer.

Once the responder triggered:

- Firewall rules immediately blocked the attacker IP
- RDP connectivity failed at the network layer
- Port scans no longer showed RDP as reachable
- Subsequent brute-force attempts could not establish connections

---

## Alerting and Operator Visibility

Each enforcement action generated a real-time alert containing:

- Attacker IP address
- Targeted username
- Failure count
- Evaluation time window
- Ban duration

- **[discord-ban-alert-details.png](evidence/discord-ban-alert-details.png)**  
  Real-time Discord alert showing ban enforcement details and attacker context.

Private and local IP addresses were explicitly excluded from bans:

- **[log-info-successfully-skipped-private-local-ip-ban.png](evidence/log-info-successfully-skipped-private-local-ip-ban-.png)**  
  Responder logic confirming private and local addresses are skipped safely.
  > **Note:**  
> The exclusion of private and local IP address ranges is configurable and environment-dependent.  
> For the purposes of this lab, the exclusion logic was temporarily commented during testing to allow the responder to act on attacks originating from Kali and the Windows host, both of which reside on private/local networks.  
>  
> In a production environment, these exclusions would typically remain enforced to prevent accidental self-blocking or disruption of internal infrastructure.

---

## Observations and Security Implications

This phase highlights an important operational insight:

Authentication abuse can escalate into **availability impact** even without credential compromise.

By enforcing containment early and automatically, the responder:

- Prevents cascading account lockouts
- Reduces attack noise across the environment
- Limits exposure windows without analyst intervention

This reflects how endpoint-based controls are used in practice to stop attacks in progress.

---

## Outcome

At the end of this phase, the Windows endpoint operates with:

- Continuous authentication monitoring
- Automated evaluation of suspicious behavior
- Host-level containment via firewall enforcement
- Persistent ban tracking with expiration
- Real-time alerting for responder visibility

The system now actively defends itself against RDP brute-force attacks.

---

## What This Phase Enables

With automated containment in place, the Windows endpoint now supports:

- End-to-end detection, alerting, and response workflows
- Safe experimentation with response tuning and thresholds
- Extension into more advanced response logic
- Integration with centralized logging or SIEM pipelines

---

## Foundation for the Windows Endpoint Lab

This phase represents the final functional layer of the Windows endpoint security pipeline.

Together, the completed phases demonstrate:

- Controlled exposure of services
- Precise authentication telemetry analysis
- Continuous monitoring and alerting
- Automated defensive enforcement

The Windows endpoint lab is now **complete and enterprise-representative**.
