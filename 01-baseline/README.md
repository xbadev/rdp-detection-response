# Phase 01 — Baseline Security Posture

Documented the default network security posture of a fresh Windows Server before introducing any exposure. The point is to anchor every later change ("we enabled RDP, here's exactly what changed") against a known starting state, not against assumptions.

## Environment

| System | Role | IP |
|---|---|---|
| Kali | Attacker | `10.10.10.30` |
| Windows Server 2025 (Desktop Experience) | Target | `10.10.10.40` |

Both on Proxmox bridge `vmbr1` (`10.10.10.0/24`), no internet uplink on this bridge.

## Baseline checks

### 1. Layer-2 reachability

From Kali, confirm the Windows VM is on the same broadcast domain — the ARP entry should appear after a brief probe:

```bash
ip neighbor flush all
ping -c 1 10.10.10.40 || true   # will likely fail at IP layer
ip neighbor show 10.10.10.40
```

Expected: an `lladdr` entry. If absent, the VMs are not on the same bridge.

### 2. Outbound (Windows → Kali)

From the Windows endpoint:

```powershell
Test-Connection -ComputerName 10.10.10.30 -Count 2
```

Expected: replies received. Outbound is permitted by default.

### 3. Inbound (Kali → Windows)

From Kali:

```bash
ping -c 3 10.10.10.40
```

Expected: 100% packet loss. Inbound ICMP is blocked by default Windows Firewall behavior.

### 4. Firewall verification

On Windows:

```powershell
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -Auto
```

Expected:
- `Enabled` = `True` for Domain, Private, and Public profiles
- `DefaultInboundAction` = `Block`
- `DefaultOutboundAction` = `Allow`

### 5. ICMP rule inspection

```powershell
Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' |
    Where-Object DisplayName -like '*Echo Request*' |
    Format-Table DisplayName, Enabled, Direction, Action -Auto
```

The `ICMPv4-In` rule exists but is disabled. That's why Kali's ping was dropped: not because there's no rule, but because the rule isn't enabled.

### 6. What IS allowed in by default

"Default inbound = Block" doesn't mean nothing gets in. List the built-in allow rules that are already on:

```powershell
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    Sort-Object DisplayGroup | Format-Table DisplayName, Profile -AutoSize
```

On Windows Server, expect **Windows Remote Management (HTTP-In)**: WinRM on TCP/5985 is enabled by default so the server can be managed remotely, and its Public-profile rule allows the local subnet. Confirm from Kali with `nmap -Pn -p 5985 10.10.10.40`. This lab leaves it alone (it's out of scope), but it belongs in the baseline: it's an authenticated remote-management service listening before anything else was configured.

### 7. Which firewall profile the lab NIC is in

```powershell
Get-NetConnectionProfile | Format-Table InterfaceAlias, Name, NetworkCategory -AutoSize
```

The `vmbr1` NIC has no gateway, so Windows usually labels it an unidentified network and puts it in the **Public** profile. Rules created later in this lab use `-Profile Any`, so they apply regardless.

## Findings

| Check | Result |
|---|---|
| Windows Firewall | Enabled on all profiles |
| Inbound default | `Block` |
| Outbound default | `Allow` |
| ICMP inbound | Rule exists, disabled |
| Pre-enabled inbound services | WinRM (TCP/5985) from the local subnet |
| RDP | Disabled |

The baseline is mostly closed, with one remote-management service on by default. Every later gain in attack surface (Phase 02 ICMP, Phase 03 RDP) is attributable to a specific, deliberate change.

## Next

Phase 02 introduces controlled exposure — enabling inbound ICMP **only** for the Kali IP — to validate that Windows Firewall enforces source-scoping correctly before we expose anything more interesting.
