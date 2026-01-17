# IP Addressing Plan – Windows Endpoint

This document records the network configuration of the Windows endpoint VM
used in the homelab.

## Host-Only Network (Internal)

Subnet: `192.168.56.0/24`  
Purpose: Internal communication between virtual machines.

| Device        | Interface | IP Address        |
|---------------|-----------|-------------------|
| Windows VM    | Ethernet  | 192.168.56.40     |

Notes:
- IP assigned via VirtualBox host-only DHCP
- No default gateway on this interface
- Used for internal lab communication with Kali, Ubuntu, and the host

## NAT Network (External)

Purpose: Internet access for system updates.

Notes:
- IP and default gateway assigned dynamically via VirtualBox NAT (DHCP)
- Provides outbound internet access only
