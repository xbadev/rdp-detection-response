# Phase 03 — Remote Access Attack Surface (RDP)

Enabled Remote Desktop on the Windows Server target. RDP is the most-attacked authentication-bound service on internet-facing Windows servers, which makes it the realistic surface for the detection and response phases that follow.

## Environment

| System | Role | IP |
|---|---|---|
| Kali | Attacker | `10.10.10.30` |
| Windows Server 2025 | Target | `10.10.10.40` |

Starting state: Phase 02 validated source-scoped firewall rules with ICMP. No TCP services exposed yet.

## Steps

### 1. Pre-exposure scan

From Kali:

```bash
nmap -Pn -p- --min-rate 1000 10.10.10.40
```

Expected: no RDP. On Windows Server you will likely see **5985/tcp (WinRM)** open: Server enables PowerShell remoting by default and allows it from the local subnet. That's a real finding in its own right (see the Phase 01 baseline). It isn't part of this lab's attack surface, but don't call the box "nothing open" if it isn't.

### 2. Enable Remote Desktop

In an elevated PowerShell on the server:

```powershell
# Enable RDP.
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 0

# Open the firewall rule group for RDP.
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
```

GUI equivalents: **Server Manager → Local Server → Remote Desktop**, or option 7 in `sconfig`. Network Level Authentication stays on (the default); the detection phases account for how NLA changes the logged LogonType.

### 3. Post-exposure scan

Repeat the nmap scan. Expected: TCP/3389 open and identified as `ms-wbt-server` (plus 5985 if WinRM is still on).

### 4. Confirm reachability

#### From a Windows client

Use `mstsc` (built-in Remote Desktop Connection client). Authenticate with a valid local account. Expected: full interactive session.

#### From Kali

```bash
xfreerdp3 /v:10.10.10.40 /u:<your-admin-account> /cert:ignore   # older Kali: xfreerdp
```

Expected: prompt for password, then desktop session.

### 5. Create the decoy account the demo attacks

```powershell
net user labuser 'Choose-A-Long-Unique-Passw0rd!' /add
```

A standard user, not an admin, never logged into. The attack script targets it so lockouts from repeated demo runs never hit a real account. (Optional: failures against a nonexistent username are logged as 4625 too.)

## Findings

| Check | Pre-RDP | Post-RDP |
|---|---|---|
| nmap full TCP scan | No 3389 (5985 WinRM on Server) | 3389 open |
| Authenticated session from Windows client | n/a | ✅ |
| Authenticated session from Kali (`xfreerdp`) | n/a | ✅ |

Enabling RDP took the endpoint from zero exposed services to one authentication-bound service reachable from any host on `10.10.10.0/24`. Authentication is now the only barrier between an attacker on the lab subnet and an interactive session.

## Why scope wasn't applied here

Phase 02 demonstrated that you *can* scope a rule to a single source. RDP was deliberately left open to the whole subnet so the detection and response phases have something interesting to defend. In production you would scope this to a jump host or VPN range — the lab keeps it open precisely because the next phases are about catching the attack, not preventing it.

## Next

Phase 04 builds the detection script that watches the Security event log for failed authentication patterns from the now-exposed RDP service.
