# Phase 03 - Remote Access Attack Surface (RDP)

## Objective

Introduce a high-risk remote access service to the Windows endpoint and observe how enabling the service changes the system’s external attack surface. This phase establishes a realistic authentication entry point that will later be used for attack simulation, detection, and alerting.

Remote Desktop Protocol (RDP) was selected due to its widespread use in enterprise environments and its frequent targeting in real-world attacks.

---

## Environment Context

- **Attacker System:** Kali Linux VM  
- **Target System:** Windows endpoint VM  
- **Network:** VirtualBox Host-Only internal network

At the end of Phase 02, the Windows endpoint allowed only narrowly scoped ICMP traffic and had no exposed TCP services.

---

## Actions Performed

The following steps were taken to intentionally introduce a remote access attack surface.

### 1. Pre-Exposure Port Scan

A network scan was performed from the Kali system against the Windows endpoint.  
The scan showed no listening TCP services, confirming that no remote access services were exposed.

### 2. Remote Desktop Enabled

Remote Desktop was enabled through the Windows system settings.  
This action allowed inbound RDP connections to the endpoint.

### 3. Post-Exposure Port Scan

The same network scan was repeated from the Kali system.  
Port **3389/tcp** was now visible and identified as an active RDP service.

### 4. Legitimate Remote Access Validation (mstsc)

A Remote Desktop connection was initiated using the Windows Remote Desktop client.  
Authentication succeeded, and a full interactive session was established.

### 5. Command-Line Remote Access Validation (xfreerdp)

A Remote Desktop connection was initiated from Kali using the `xfreerdp` client.  
Authentication succeeded, confirming that the service was reachable and functional from an attacker-controlled system.

---

## Security Findings

This phase confirmed the following security behaviors:

- Enabling RDP immediately expands the system’s attack surface
- Port exposure is observable through standard reconnaissance tools
- The RDP service is reachable from internal network peers
- Authentication-based access control becomes the primary security boundary
- Both GUI-based and CLI-based access methods function once RDP is enabled

The system transitioned from a non-exposed state to one that accepts remote authentication attempts.

---

## Outcome

A real, high-risk remote access service was intentionally exposed and validated. The change in attack surface was confirmed through network scanning, and legitimate access was established using multiple client methods.

This phase establishes a realistic entry point for adversary simulation and mirrors common enterprise remote management scenarios.

---

## What This Phase Enables

With RDP exposed and validated, the environment is now prepared for:

- Simulating malicious authentication attempts
- Observing Windows authentication and security event logs
- Implementing detection logic for brute-force and unauthorized access attempts
- Building alerting and response mechanisms

This phase serves as the foundation for all detection and alerting work that follows.

---

## Evidence and Screenshots

The following artifacts document the introduction and validation of the RDP attack surface.

- **`kali-win-nmap-scan-before-rdp-enable.png`**  
  Pre-exposure network scan from Kali showing no listening TCP services on the Windows endpoint.

- **`win-enable-RemoteDesktop.png`**  
  Windows system configuration showing Remote Desktop enabled on the endpoint.

- **`kali-win-nmap-scan-after-rdp-enable.png`**  
  Post-exposure network scan from Kali identifying port **3389/tcp** as open and associated with the RDP service.

- **`rdp-thru-mstsc.png`**  
  Successful Remote Desktop connection initiated using the Windows Remote Desktop client.

- **`remote-desktop-connection-successful.png`**  
  Authenticated interactive RDP session established with the Windows endpoint.

- **`xfreerdp3-version-and-command.png`**  
  Command-line RDP access from Kali using the `xfreerdp` client, confirming service reachability from an attacker-controlled system.

These screenshots provide verifiable evidence of how enabling RDP immediately exposes a new remote authentication attack surface.

