# Network Configuration — Windows Server Target

The Windows Server VM has two virtual NICs in Proxmox, one on each bridge:

| Adapter | Bridge | Purpose | Address |
|---|---|---|---|
| Lab NIC | `vmbr1` | Internal lab: attack traffic | Static `10.10.10.40/24`, no gateway |
| Internet NIC | `vmbr0` | Updates, evaluation activation, webhook delivery | DHCP |

`vmbr1` has no uplink, so lab traffic never touches the home network. The `vmbr0` NIC is not optional for this VM: the Windows Server evaluation must be activated online within its first 10 days or it starts shutting down automatically, and the responder posts alerts over the internet.

## IP plan (vmbr1)

| Host | Address | Role |
|---|---|---|
| Ubuntu Server | `10.10.10.20` | SSH lab target |
| Kali Linux | `10.10.10.30` | Attacker (both labs) |
| Windows Server 2025 | `10.10.10.40` | RDP lab target (this VM) |

## Building the VM on Proxmox (short version)

- ISO: Windows Server 2025 evaluation from the Microsoft Evaluation Center (free registration, 180 days). Pick **Desktop Experience** at install: the GUI makes the demo and screenshots easier to follow than Server Core.
- Disk/NIC: VirtIO for performance. Attach the `virtio-win` driver ISO as a second CD-ROM and load the storage driver during setup ("Load driver"), then install the rest of the guest tools after first boot. Same process as the Windows 10 VM in [proxmox-homelab](https://github.com/xbadev/proxmox-homelab).
- Two network devices: one on `vmbr0`, one on `vmbr1`. Note both MAC addresses from the Hardware tab.
- After first boot: rename the computer (e.g. `RDP-TARGET`), run Windows Update, confirm activation with `slmgr /dli`.

## Static IP on the lab NIC

Identify the adapters by MAC first (Windows names them in no guaranteed order):

```powershell
Get-NetAdapter | Format-Table Name, MacAddress, Status -AutoSize
```

Match the MACs to the Proxmox Hardware tab, rename the adapters so the labels are obvious, then set the lab NIC:

```powershell
Rename-NetAdapter -Name 'Ethernet'   -NewName 'LabInternal'   # adjust to what Get-NetAdapter showed
Rename-NetAdapter -Name 'Ethernet 2' -NewName 'LabExternal'
New-NetIPAddress -InterfaceAlias 'LabInternal' -IPAddress 10.10.10.40 -PrefixLength 24
```

No gateway and no DNS on `LabInternal`: the default route stays on `LabExternal`, which is the path `Invoke-RestMethod` uses to reach the webhook.

## Verification

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize
Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Format-Table InterfaceAlias, NextHop   # default route on LabExternal only
Test-Connection -ComputerName 10.10.10.30 -Count 2                                 # Windows -> Kali works by default
```

Kali → Windows ping fails until Phase 02 enables the scoped ICMP rule. That's expected, not a network problem.

## Panic button: back to DHCP

```powershell
Remove-NetIPAddress -InterfaceAlias 'LabInternal' -Confirm:$false
Set-NetIPInterface -InterfaceAlias 'LabInternal' -Dhcp Enabled
```
