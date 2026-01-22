# ICMP Controlled Exposure (Windows Endpoint)

## Objective
Allow inbound ICMP Echo Requests only from a trusted internal attacker (Kali Linux) while maintaining a default-deny posture for all other sources.

## Configuration Change
- Enabled: File and Printer Sharing (Echo Request - ICMPv4-In)
- Action: Allow
- Scope: Restricted to Kali IP (192.168.56.30)
- Profiles: Private / Domain
- All other sources remain blocked

## Validation Results
- Kali → Windows ICMP: Success
- Host → Windows ICMP: Blocked
- Windows outbound ICMP: Allowed

## Evidence
- Kali successful ping to Windows
- Host failed ping to Windows
- Firewall rule scoped to Kali IP only

## Security Impact
This change demonstrates controlled exposure:
- No subnet-wide trust
- No blanket ICMP allowance
- Principle of least privilege enforced
