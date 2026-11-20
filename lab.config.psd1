@{
    # ============================================================
    # RDP Detection & Response — Lab Configuration
    # ============================================================
    # Real version path: C:\HomeLab\rdp-dr\config\lab.config.psd1
    # Permissions:       SYSTEM + Administrators only (set by Install.ps1)
    # Loaded by:         every script and the event-triggered task
    # ============================================================

    # --- Network ----------------------------------------------------
    # Proxmox vmbr1 internal lab subnet.
    InternalSubnet = '10.10.10.0/24'

    # Static IPs on vmbr1.
    TargetIp   = '10.10.10.40'   # Windows endpoint (this host)
    AttackerIp = '10.10.10.30'   # Kali

    # --- Detection tuning ------------------------------------------
    # Trigger response when this many failed RDP logons (Event ID 4625,
    # LogonType 3) come from a single source IP within MinutesBack.
    Threshold    = 5
    MinutesBack  = 2

    # How long a banned IP is firewalled out for (minutes).
    BanMinutes   = 30

    # --- Mode ------------------------------------------------------
    # LabMode = $true   -> private/local IPs ARE banned (Kali at 10.10.10.30 is private!)
    # LabMode = $false  -> private/local IPs SKIPPED (production behavior)
    # Default is $true so a fresh demo actually bans the lab attacker.
    LabMode = $true

    # --- Paths -----------------------------------------------------
    # Install.ps1 creates these and locks them down.
    InstallRoot   = 'C:\HomeLab\rdp-dr'
    LogPath       = 'C:\HomeLab\rdp-dr\logs\rdp_monitor.log'
    StateDir      = 'C:\HomeLab\rdp-dr\state'
    BanListPath   = 'C:\HomeLab\rdp-dr\state\rdp_banlist.json'
    AllowListPath = 'C:\HomeLab\rdp-dr\config\rdp_allowlist.txt'
    SecretsDir    = 'C:\HomeLab\rdp-dr\secrets'
    WebhookFile   = 'C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt'

    # --- Firewall --------------------------------------------------
    # Prefix for firewall rules created by the responder. Easy to enumerate / clear.
    FirewallRulePrefix = 'HomeLab-RDPBan'

    # --- Scheduled task --------------------------------------------
    # Names of the event-triggered tasks. Install.ps1 registers these.
    DetectorTaskName  = 'HomeLab-RDP-Detector'
    ResponderTaskName = 'HomeLab-RDP-Responder'
}
