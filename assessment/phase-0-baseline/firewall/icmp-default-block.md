# Default ICMP Firewall Behavior (Windows Endpoint)

## Observation
Inbound ICMP Echo Requests (ping) to the Windows endpoint are blocked by default.

## Evidence
- Kali to Windows ICMP failed (100% packet loss)
- Windows to Kali ICMP succeeded
- Windows Defender Firewall is enabled for all profiles
- Default inbound policy is set to block

## Firewall Rule Details
The following inbound rules exist but are disabled by default:

- File and Printer Sharing (Echo Request - ICMPv4-In)
- Profile: Domain / Private
- Action: Allow
- Enabled: No

Because these rules are disabled, inbound ICMP traffic is dropped by the firewall.

## Conclusion
The Windows endpoint enforces a default-deny inbound firewall posture.
ICMP Echo Requests must be explicitly enabled to allow inbound ping traffic.
