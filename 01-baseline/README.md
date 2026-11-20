# Phase 01 — Baseline Security Posture

Documented the default network security posture of the Windows endpoint before introducing any exposure. The point is to anchor every later change ("we enabled RDP, here's exactly what changed") against a known starting state, not against assumptions.

## Environment

| System | Role | IP |
|---|---|---|
| Kali | Attacker | `10.10.10.30` |
| Windows | Target | `10.10.10.40` |

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

The `ICMPv4-In` rule exists but is disabled. That's why Kali's ping was dropped — not because there's no rule, but because the rule isn't enabled.

## Findings

| Check | Result |
|---|---|
| Windows Firewall | Enabled, enforcing |
| Inbound default | `Block` |
| Outbound default | `Allow` |
| ICMP inbound | Rule exists, disabled |
| External discoverability via ICMP | None |

The endpoint has a secure default posture. Any future reachability must be the result of deliberate configuration change — not default behavior. That makes Phase 02 (scoped ICMP) and Phase 03 (RDP exposure) attributable: we can point at a specific firewall change for every gain in attack surface.

## Next

Phase 02 introduces controlled exposure — enabling inbound ICMP **only** for the Kali IP — to validate that Windows Firewall enforces source-scoping correctly before we expose anything more interesting.
