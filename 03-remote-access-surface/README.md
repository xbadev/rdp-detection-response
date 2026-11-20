# Phase 03 — Remote Access Attack Surface (RDP)

Enabled Remote Desktop on the Windows endpoint. RDP was chosen because it's the most-targeted authentication-bound service on Windows in the wild — making it the most realistic surface for the detection and response work in later phases.

## Environment

| System | Role | IP |
|---|---|---|
| Kali | Attacker | `10.10.10.30` |
| Windows | Target | `10.10.10.40` |

Starting state: Phase 02 validated source-scoped firewall rules with ICMP. No TCP services exposed yet.

## Steps

### 1. Pre-exposure scan

From Kali:

```bash
nmap -Pn -p- --min-rate 1000 10.10.10.40
```

Expected: no open TCP ports (or only what's incidentally listening, e.g. nothing on a hardened baseline).

### 2. Enable Remote Desktop

In PowerShell on the Windows endpoint:

```powershell
# Enable RDP.
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 0

# Open the firewall rule group for RDP.
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
```

Equivalent via the GUI: **Settings → System → Remote Desktop → Enable**.

### 3. Post-exposure scan

Repeat the nmap scan. Expected: TCP/3389 open and identified as `ms-wbt-server`.

### 4. Confirm reachability

#### From a Windows client

Use `mstsc` (built-in Remote Desktop Connection client). Authenticate with a valid local account. Expected: full interactive session.

#### From Kali

```bash
xfreerdp /v:10.10.10.40 /u:bader /cert:ignore
```

Expected: prompt for password, then desktop session.

## Findings

| Check | Pre-RDP | Post-RDP |
|---|---|---|
| nmap full TCP scan | Nothing open | 3389 open |
| Authenticated session from Windows client | n/a | ✅ |
| Authenticated session from Kali (`xfreerdp`) | n/a | ✅ |

Enabling RDP took the endpoint from zero exposed services to one authentication-bound service reachable from any host on `10.10.10.0/24`. Authentication is now the only barrier between an attacker on the lab subnet and an interactive session.

## Why scope wasn't applied here

Phase 02 demonstrated that you *can* scope a rule to a single source. RDP was deliberately left open to the whole subnet so the detection and response phases have something interesting to defend. In production you would scope this to a jump host or VPN range — the lab keeps it open precisely because the next phases are about catching the attack, not preventing it.

## Next

Phase 04 builds the detection script that watches the Security event log for failed authentication patterns from the now-exposed RDP service.
