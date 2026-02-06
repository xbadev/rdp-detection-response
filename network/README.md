# IP Addressing Plan – Windows Endpoint

This document records the network configuration of the Windows endpoint VM
used in the homelab.

The Windows endpoint is configured with **two network adapters** to separate
internal lab traffic from external internet access.

---

## Network Interface Overview

| Adapter    | Network Type | Purpose |
|-----------|--------------|--------|
| Ethernet  | Host-Only    | Internal lab communication |
| Ethernet 2 | NAT          | Outbound internet access |

---

## Host-Only Network (Internal)

**Subnet:** `192.168.56.0/24`  
**Purpose:** Internal communication between lab virtual machines.

| Device     | Interface | IP Address |
|-----------|----------|-----------|
| Windows VM | Ethernet | 192.168.56.40 |

### Configuration Summary

- Static IP address manually assigned
- No default gateway configured
- Used for communication with Kali Linux, Ubuntu server, and host system
- Not exposed to the internet

Verification of interface separation and IP assignment:

- **[win-ipconfig.png](screenshots/win-ipconfig.png)**

---

## Manual Static IP Configuration (Host-Only Adapter)

Because the Windows VM uses **two adapters**, the Host-Only interface was
manually configured to ensure predictable addressing and avoid conflicts
with the NAT adapter.

The following steps apply **only to the Host-Only adapter**.

---

### Step 1 – Open Network Adapter Settings

From Windows Settings:

- Go to **Network & Internet**
- Select **Ethernet**
- Click **Change adapter options**

- **[change-adapter-options-link.png](screenshots/change-adapter-options-link.png)**

---

### Step 2 – Select the Host-Only Adapter

In **Network Connections**:

- Right-click **Ethernet** (Host-Only)
- Select **Properties**

The NAT adapter remains unchanged.

- **[right-click-ethernet-then-properties.png](screenshots/right-click-ethernet-then-properties.png)**

---

### Step 3 – Configure IPv4 Manually

Within Ethernet Properties:

- Select **Internet Protocol Version 4 (TCP/IPv4)**
- Click **Properties**
- Choose **Use the following IP address**

Configured values:

- IP address: `192.168.56.40`
- Subnet mask: `255.255.255.0`
- Default gateway: *(none)*

This ensures internal reachability without external routing.

- **[IPv4-then-manually-choose-IP.png](screenshots/IPv4-then-manually-choose-IP.png)**

---

## NAT Network (External)

**Purpose:** Internet access for updates and package downloads.

### Configuration Summary

- IP address assigned dynamically via VirtualBox NAT (DHCP)
- Default gateway provided automatically
- Outbound access only
- Not used for internal lab communication or attack simulation

---

## Outcome

The Windows endpoint now operates with:

- A stable, static IP on the Host-Only interface
- A separate NAT interface for external connectivity
