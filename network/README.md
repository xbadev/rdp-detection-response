# Network Configuration — Windows Endpoint

The Windows VM has two virtual NICs in Proxmox, one bridged to each Proxmox bridge:

| Adapter | Bridge | Purpose | Address |
|---|---|---|---|
| Ethernet | `vmbr1` | Internal lab — attack traffic | Static `10.10.10.40/24` |
| Ethernet 2 | `vmbr0` | Internet — updates, downloads | DHCP |

`vmbr1` has no uplink. Internal lab traffic is fully isolated from the home network.

## IP plan (vmbr1)

| Host | Address | Role |
|---|---|---|
| Ubuntu Server | `10.10.10.20` | SSH lab target |
| Kali Linux | `10.10.10.30` | Attacker (used by both labs) |
| Windows | `10.10.10.40` | RDP lab target (this VM) |

## Configuring the static IP on Windows

The internal NIC is configured manually so the address is predictable and survives reboots without DHCP races on a network that has no DHCP server.

**Network & Internet → Change adapter options →** right-click the internal Ethernet adapter → **Properties** → **Internet Protocol Version 4 (TCP/IPv4)** → **Properties** → **Use the following IP address**.

| Field | Value |
|---|---|
| IP address | `10.10.10.40` |
| Subnet mask | `255.255.255.0` |
| Default gateway | *(none)* |
| Preferred DNS | *(none)* |

The internet adapter (Ethernet 2, on `vmbr0`) keeps DHCP — its default route is what gets used for `Invoke-RestMethod` calls to the Discord webhook.

## Identifying which adapter is which

In Proxmox, NICs appear in the order you added them in the VM hardware tab. Inside Windows, they show up with kernel-assigned names that don't always match the order. The reliable way to tell them apart:

```powershell
Get-NetAdapter | Format-Table Name, MacAddress, InterfaceDescription, Status -Auto
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress, PrefixLength -Auto
```

Cross-reference the MAC addresses with what Proxmox shows on each NIC in the VM hardware tab. Rename them via **Network Connections → right-click → Rename** so the labels stick (e.g. `LabInternal`, `LabExternal`) — clearer in screenshots and easier when running PowerShell against a specific adapter.

## Verification

```powershell
ipconfig /all                                  # both adapters with correct addresses
Test-NetConnection 10.10.10.30 -CommonTCPPort RDP  # reach Kali (will likely fail since Kali isn't listening on 3389, but the route works)
Test-Connection -ComputerName 10.10.10.30 -Count 2  # ICMP reachability
```

After Phase 02 (controlled ICMP exposure), the second command should succeed in the Kali → Windows direction; before then it will fail (default firewall blocks inbound).

## Reverting to DHCP

If the static config breaks something:

```powershell
$adapter = Get-NetAdapter -Name 'Ethernet'      # or whatever you named the internal NIC
$adapter | Set-NetIPInterface -Dhcp Enabled
$adapter | Remove-NetIPAddress -Confirm:$false
$adapter | Remove-NetRoute -Confirm:$false
```

Useful as a panic button during initial setup.
