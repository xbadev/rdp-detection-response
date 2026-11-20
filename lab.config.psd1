@{
    # ============================================================
    # RDP Detection & Response - Lab Configuration
    # ============================================================
    # Installed to:  C:\HomeLab\rdp-dr\config\lab.config.psd1  (by Install.ps1)
    # Read by:       every script, via Import-LabConfig in Lib\RdpDetection.psm1
    # Edit the INSTALLED copy to change behavior; changes apply on the next
    # event, no restart needed. Values must be literals (psd1 rule).
    # ============================================================

    # --- Identity --------------------------------------------------
    # This host's lab IP (vmbr1). Shown in alerts.
    TargetIp = '10.10.10.40'

    # --- Detection -------------------------------------------------
    # Act when this many failed RDP logons (Security 4625, LogonType 3/10)
    # from one source IP against one account land within MinutesBack.
    # 5 sits below the default account-lockout threshold (10), so the
    # attacker is cut off at the network before the account gets locked.
    Threshold   = 5
    MinutesBack = 2

    # --- Response --------------------------------------------------
    # Firewall block duration for a banned IP (minutes).
    BanMinutes = 30

    # Phase 05 (alert-only monitor): minimum minutes between alerts for the
    # same source IP. Without it, every 4625 during an attack re-alerts.
    AlertCooldownMinutes = 10

    # LabMode = $true  -> private/local source IPs CAN be banned.
    #                     Needed in the lab: Kali (10.10.10.30) is a private IP.
    # LabMode = $false -> private/local IPs are skipped, the usual production
    #                     default that stops a responder banning its own network.
    LabMode = $true

    # --- Paths (created and locked down by Install.ps1) ------------
    InstallRoot       = 'C:\HomeLab\rdp-dr'
    LogPath           = 'C:\HomeLab\rdp-dr\logs\rdp_monitor.log'
    StateDir          = 'C:\HomeLab\rdp-dr\state'
    BanListPath       = 'C:\HomeLab\rdp-dr\state\rdp_banlist.json'
    AlertCooldownPath = 'C:\HomeLab\rdp-dr\state\alert_cooldowns.json'
    AllowListPath     = 'C:\HomeLab\rdp-dr\config\rdp_allowlist.txt'
    SecretsDir        = 'C:\HomeLab\rdp-dr\secrets'
    WebhookFile       = 'C:\HomeLab\rdp-dr\secrets\discord_webhook_url.txt'

    # --- Names -----------------------------------------------------
    # Prefix of every firewall rule the responder creates (easy to list/clear).
    FirewallRulePrefix = 'HomeLab-RDPBan'

    # Event-triggered scheduled tasks.
    ResponderTaskName = 'HomeLab-RDP-Responder'   # Phase 06, registered by Install.ps1
    MonitorTaskName   = 'HomeLab-RDP-Monitor'     # Phase 05, optional alert-only mode
}
