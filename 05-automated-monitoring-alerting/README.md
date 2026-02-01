# Phase 05 - Automated RDP Monitoring and Alerting

## Objective

Transition from manual inspection and on-demand detection to continuous, automated monitoring and alerting for suspicious RDP authentication behavior on a Windows endpoint.

This phase operationalizes the detection logic developed in Phase 04 by running it on a recurring schedule, logging only high-risk activity, and delivering real-time alerts to an external notification channel.

The goal is to simulate how enterprise systems continuously monitor authentication telemetry and surface actionable security events without human intervention.

---

## Context and Threat Model

At this stage of the lab, the Windows endpoint exposes RDP internally and already has validated detection logic for failed authentication bursts.

In real environments, detection logic is only valuable if it runs automatically and produces timely alerts. Analysts do not manually inspect Event Viewer to discover attacks. Monitoring systems continuously evaluate recent activity and notify responders when thresholds are exceeded.

This phase bridges that gap by transforming detection into an always-on monitoring capability.

---

## Separation of Detection and Monitoring Responsibilities

To preserve clarity, reusability, and auditability, the finalized detection logic from Phase 04 was reused without modification.

A new monitoring script was introduced with the following responsibilities:

- Reusing the same detection logic and thresholds  
- Executing repeatedly on a time-based schedule  
- Evaluating only recent authentication activity  
- Determining whether alert conditions are met  

This separation mirrors real enterprise practice, where detection logic is reused across multiple pipelines while monitoring and alerting layers evolve independently.

---

## Monitoring Output and Local Logging

The monitoring script was intentionally designed to remain quiet during normal operation.

Its behavior is limited to:

- Writing only suspicious activity or execution failures to a local log file  
- Remaining silent when no alert conditions are met  

This minimizes noise while ensuring a persistent audit trail of meaningful security events and script health.

---

## External Alerting via Webhook Integration

### Alert Channel Design

To simulate enterprise SOC workflows, alerts are delivered to a dedicated external channel using a webhook integration.

This mirrors real-world alert pipelines that forward security events to platforms such as Slack, Microsoft Teams, or incident management systems.

- **[testing-discord-webhook-connectivity-command.png](evidence/testing-discord-webhook-connectivity-command.png)**  
  Command-line test validating outbound webhook connectivity before enabling full monitoring.

- **[discord-testing-alert-result.png](evidence/discord-testing-alert-result.png)**  
  Successful test alert delivered to the external Discord channel.

---

### Secret Management and File Security

To avoid embedding sensitive information directly in code:

- The webhook URL is stored in a dedicated secrets file  
- Inherited permissions were explicitly removed  
- Access was restricted to SYSTEM and Administrators only  

This ensures the webhook cannot be read or abused by standard users while remaining accessible to scheduled tasks running with elevated privileges.

- **[webhook-url-default-file-permissions.png](evidence/webhook-url-default-file-permissions.png)**  
  Default permissions on the webhook secrets file prior to hardening.

- **[webhook-url-remove-inheritance-file-permission.png](evidence/webhook-url-remove-inheritance-file-permission.png)**  
  Removal of inherited permissions to prevent unauthorized access.

- **[webhook-url-set-permissions-command-and-display-permissions.png](evidence/webhook-url-set-permissions-command-and-display-permissions.png)**  
  Explicit permission configuration restricting access to SYSTEM and Administrators only.

---

## Automation with Windows Task Scheduler

### Continuous Execution Model

The monitoring script was automated using Windows Task Scheduler and configured to:

- Run on a recurring interval  
- Execute with highest privileges  
- Operate independently of user logon state  

This approach parallels cron jobs and systemd timers commonly used on Linux systems, adapted to native Windows tooling.

- **[the_task_in_task_scheduler.png](evidence/the_task_in_task_scheduler.png)**  
  Scheduled task configuration showing automatic execution with highest privileges.

- **[running_the_task_once.png](evidence/running_the_task_once.png)**  
  Manual task execution to validate correct script behavior and alerting.

---

### Privilege and Reliability Considerations

The scheduled task runs under a privileged context to ensure:

- Consistent access to the Windows Security event log  
- Reliable execution regardless of user session state  
- No dependence on interactive logins  

Successful task registration and execution confirmed that the monitoring pipeline operates continuously.

---

## End-to-End Pipeline Validation

### Controlled Attack Simulation

To validate the full monitoring and alerting pipeline, a controlled brute-force simulation was performed from a Kali Linux attacker VM.

The attack sequence included:

- Verifying RDP exposure through network scanning  
- Generating repeated failed authentication attempts using Hydra  
- Targeting a known account with a small password list  

- **[kali-nmap-and-hydra-controlled-attack.png](evidence/kali-nmap-and-hydra-controlled-attack.png)**  
  Controlled attack simulation generating repeated RDP authentication failures.

As expected, the Windows endpoint generated multiple failed authentication events in rapid succession.

---

### Alert Delivery and System Response

The monitoring script detected the authentication failure burst and successfully:

- Identified the source IP address  
- Identified the targeted account  
- Counted failed authentication attempts  
- Delivered a real-time alert to the external notification channel  

- **[discord-rdp-bruteforce-alert_shows_IP_target_failuresCount.png](evidence/discord-rdp-bruteforce-alert_shows_IP_target_failuresCount.png)**  
  Real-time alert showing source IP, target account, and failure count.

Shortly after, the targeted account entered a locked state due to the default Windows account lockout policy.

- **[windows-account-lockout-policy-locked-account.png](evidence/windows-account-lockout-policy-locked-account.png)**  
  Account lockout triggered automatically after repeated authentication failures.

- **[successful-rdp_suspect_logging-in-machine.png](evidence/successful-rdp_suspect_logging-in-machine.png)**  
  Successful RDP login after account recovery, confirming system stability post-lockout.

---

## Observations and Security Implications

This phase highlights a critical real-world behavior:

Repeated authentication failures can cause account-level denial of service even without successful compromise.

Although no custom response logic was implemented yet, built-in Windows protections were automatically triggered, temporarily denying access to the affected account.

This reinforces the importance of early detection and alerting before availability and user access are impacted.

---

## Outcome

At the end of this phase, the Windows endpoint operates with:

- Continuous RDP authentication monitoring  
- Automated evaluation of high-risk behavior  
- Secure external alert delivery  
- No dependency on manual inspection  

The system now behaves like a simplified enterprise authentication monitoring pipeline.

---

## What This Phase Enables

With automated monitoring and alerting in place, the environment is prepared for active response.

This phase enables:

- Immediate awareness of RDP abuse as it occurs  
- Reliable triggers for automated containment actions  
- Safe experimentation with response logic without blind spots  
- A transition from detection to mitigation  

The account lockout observed during testing provides a natural pivot into controlled response handling in the next phase.
