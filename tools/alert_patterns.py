"""
Shared alert pattern definitions for LogHawk tools.

Each entry: (regex_string, severity, description, category)
"""

ALERT_PATTERNS = [
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

    # Cron job added or modified
    (r"CRON\[.*\]: \((\S+)\) CMD \((.*)\)",
     "LOW", "Cron job executed", "cron"),

    # Invalid user login attempt
    (r"Invalid user (\S+) from ([\d.]+)",
     "MEDIUM", "Login attempt for nonexistent user", "brute_force"),
]
