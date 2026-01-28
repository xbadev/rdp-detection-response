# Phase 02 - Controlled Exposure (ICMP)

## Objective

Introduce a deliberately scoped inbound network exposure to the Windows endpoint while maintaining the principle of least privilege. This phase demonstrates how a service can be selectively enabled for a specific source without broadly exposing the system to the network.

The purpose is to validate firewall rule scoping and confirm that access controls behave exactly as configured.

---

## Environment Context

- **Attacker System:** Kali Linux VM  
- **Target System:** Windows endpoint VM  
- **Additional System:** Host machine (used to validate scoping enforcement)  
- **Network:** VirtualBox Host-Only internal network

At the end of Phase 01, the Windows endpoint was confirmed to block all inbound ICMP traffic by default.

---

## Actions Performed

The following controlled changes were made to the Windows Defender Firewall configuration.

### 1. ICMPv4 Inbound Rule Enabled

The existing **Echo Request - ICMPv4-In** rule under the **File and Printer Sharing** rule group was enabled.

### 2. Source IP Scoping Applied

The rule scope was restricted to allow ICMP echo requests **only** from the Kali Linux VM’s IP address.

- No IP ranges were permitted  
- No subnets were permitted  
- Access was limited to a single trusted source

### 3. Authorized Source Validation (Kali → Windows)

The Kali system initiated ICMP echo requests to the Windows endpoint.  
All requests were successfully received, confirming that the scoped rule functioned as intended.

### 4. Unauthorized Source Validation (Host → Windows)

The host machine attempted to ping the Windows endpoint.  
All requests failed, demonstrating that access was correctly denied to non-authorized sources.

---

## Security Findings

This phase confirmed the following security behaviors:

- Firewall rules can be enabled without introducing broad exposure
- Source IP scoping is enforced correctly by Windows Defender Firewall
- Authorized systems gain access only when explicitly permitted
- Unauthorized systems remain blocked even when the service is enabled
- Exposure can be validated empirically through controlled testing

The Windows endpoint remained protected while allowing narrowly defined access for testing purposes.

---

## Outcome

A controlled inbound exposure was successfully introduced without weakening the overall security posture of the system. Access was limited to a single trusted source, and all other inbound ICMP traffic remained blocked.

This confirms that the firewall configuration supports precise, least-privilege access control and that future exposure decisions can be made safely and deliberately.

---

## What This Phase Enables

With controlled exposure validated, the lab can now safely introduce higher-risk services while maintaining confidence in firewall enforcement. This phase establishes the foundation for exposing and analyzing real attack surfaces in subsequent phases.

---

## Evidence and Screenshots

The following artifacts document the controlled ICMP exposure and source IP scoping behavior.

- **[scoping-win-icmp-for-kali-only.png](evidence/scoping-win-icmp-for-kali-only.png)**  
  Windows Defender Firewall configuration showing the ICMPv4 inbound rule scoped exclusively to the Kali Linux VM’s IP address.

- **[kali-win-icmp-ping-successful.png](evidence/kali-win-icmp-ping-successful.png)**  
  Successful ICMP echo requests from the authorized Kali system, confirming the scoped rule is functioning as intended.

- **[host-win-ping-failure-prove-scoping.png](evidence/host-win-ping-failure-prove-scoping.png)**  
  Failed ICMP echo requests from the host machine, proving that non-authorized sources remain blocked despite the rule being enabled.

These screenshots provide verifiable proof that controlled exposure was introduced without weakening the overall security posture of the Windows endpoint.

