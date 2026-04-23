"""
Shared alert pattern definitions for LogHawk tools.

Each entry: (regex_string, severity, description, category)

Categories group related patterns for filtering and reporting.
Source comments indicate which log file each pattern targets.
"""

ALERT_PATTERNS = [
    # ── auth.log / secure ────────────────────────────────────────────

    # SSH brute force / credential stuffing
    (r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)",
     "HIGH", "SSH failed login", "brute_force"),

    # Successful logins — not bad by itself, but worth logging
    (r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)",
     "INFO", "SSH successful login", "auth_success"),

    # Root login (should almost never happen)
    (r"Accepted .+ for root from ([\d.]+)",
     "CRITICAL", "Root SSH login", "root_login"),

    # Sudo usage
    (r"sudo:\s+(\S+) : .* COMMAND=(.*)",
     "MEDIUM", "Sudo command executed", "privilege_escalation"),

    # Failed sudo
    (r"sudo:\s+(\S+) : .* command not allowed",
     "HIGH", "Sudo denied — unauthorized escalation attempt", "privilege_escalation"),

    # New user/group created
    (r"useradd\[.*\]: new user: name=(\S+)",
     "HIGH", "New user account created", "account_change"),
    (r"groupadd\[.*\]: new group: name=(\S+)",
     "MEDIUM", "New group created", "account_change"),

    # User deleted
    (r"userdel\[.*\]: delete user '(\S+)'",
     "HIGH", "User account deleted", "account_change"),

    # Password changed
    (r"passwd\[.*\]: password changed for (\S+)",
     "MEDIUM", "Password changed", "account_change"),

    # SSH config changed (via common editors — rough heuristic)
    (r"COMMAND=.*(?:sshd_config|authorized_keys|sudoers)",
     "HIGH", "SSH or sudo config file touched via sudo", "config_change"),

    # Repeated auth failures = lockout or brute force in progress
    (r"pam_unix\(sshd:auth\): authentication failure",
     "HIGH", "PAM auth failure", "brute_force"),

    # Session opened for root
    (r"pam_unix\(sudo:session\): session opened for user root",
     "MEDIUM", "Root session opened via sudo", "privilege_escalation"),

    # Cron job added or modified (appears in auth.log)
    (r"CRON\[.*\]: \((\S+)\) CMD \((.*)\)",
     "LOW", "Cron job executed", "cron"),

    # Invalid user login attempt
    (r"Invalid user (\S+) from ([\d.]+)",
     "MEDIUM", "Login attempt for nonexistent user", "brute_force"),

    # ── kern.log ─────────────────────────────────────────────────────

    (r"Out of memory: Killed process (\d+) \((\S+)\)",
     "CRITICAL", "OOM killer activated", "kernel"),

    (r"segfault at",
     "HIGH", "Process segfault", "kernel"),

    (r"Kernel panic",
     "CRITICAL", "Kernel panic", "kernel"),

    (r"EXT4-fs error",
     "CRITICAL", "Filesystem error", "kernel"),

    (r"I/O error, dev (\S+)",
     "CRITICAL", "Disk I/O error", "kernel"),

    (r"Hardware Error",
     "CRITICAL", "Hardware error (MCE)", "kernel"),

    (r"usb \d+-[\d.]+: new .* speed .* USB device",
     "LOW", "USB device connected", "kernel"),

    (r"(?:iptables|nftables|kernel:.*\bDPT=).*(?:BLOCK|DROP|REJECT)",
     "MEDIUM", "Firewall packet dropped", "kernel"),

    (r"ACPI Error",
     "HIGH", "ACPI hardware error", "kernel"),

    (r"link (?:is not ready|down)",
     "HIGH", "Network link down", "kernel"),

    # ── cron.log ─────────────────────────────────────────────────────

    (r"crontab\[.*\]: \((\S+)\) (?:REPLACE|BEGIN EDIT|END EDIT)",
     "HIGH", "Crontab modified", "cron"),

    (r"crontab\[.*\]: \(root\) (?:REPLACE|END EDIT)",
     "CRITICAL", "Root crontab modified", "cron"),

    (r"CRON\[.*\]: \(root\) CMD \((.*)\)",
     "LOW", "Root cron job executed", "cron"),

    (r"anacron\[.*\]: Job .* started",
     "LOW", "Anacron job started", "cron"),

    # ── audit.log (auditd format via imfile) ─────────────────────────

    (r"type=USER_AUTH msg=.*res=failed",
     "HIGH", "Auditd: authentication failure", "audit"),

    (r"type=ANOM_",
     "CRITICAL", "Auditd: anomaly event", "audit"),

    (r'type=EXECVE msg=.*a0="(/usr/s?bin/(?:chmod|chown|chattr|setfacl))',
     "MEDIUM", "Auditd: permission change command", "audit"),

    (r"type=MAC_POLICY_LOAD",
     "HIGH", "Auditd: SELinux/AppArmor policy loaded", "audit"),

    (r"type=AVC msg=.*denied",
     "HIGH", "Auditd: SELinux denial", "audit"),

    (r"type=USER_MGMT msg=.*op=(?:adding|deleting)",
     "HIGH", "Auditd: user management operation", "audit"),

    (r"type=CRYPTO_KEY_USER",
     "MEDIUM", "Auditd: crypto key operation", "audit"),

    (r"type=SYSTEM_SHUTDOWN",
     "HIGH", "Auditd: system shutdown", "audit"),

    (r"type=SYSTEM_BOOT",
     "MEDIUM", "Auditd: system boot", "audit"),

    # ── syslog.log (daemon + catchall) ───────────────────────────────

    (r"systemd\[.*\]: (\S+)\.service: Failed with result",
     "HIGH", "Service failed", "service"),

    (r"systemd\[.*\]: (\S+)\.service: Entered failed state",
     "HIGH", "Service entered failed state", "service"),

    (r"systemd\[.*\]: Started (\S+)\.",
     "LOW", "Service started", "service"),

    (r"No space left on device",
     "CRITICAL", "Disk full", "system"),

    (r"(?:rsyslogd|rsyslog).*error",
     "HIGH", "Rsyslog error", "system"),

    (r"systemd-resolved\[.*\]:.*(?:SERVFAIL|NXDOMAIN).*for (\S+)",
     "MEDIUM", "DNS resolution failure", "system"),

    (r"(?:oom-kill|lowmem)",
     "CRITICAL", "Memory pressure event", "system"),

    (r"(?:temperature|overheat|thermal)",
     "HIGH", "Thermal warning", "system"),
]
