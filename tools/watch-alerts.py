#!/usr/bin/env python3
"""
watch-alerts.py
Real-time log watcher. Tails auth logs and prints alerts when suspicious
patterns appear. No external dependencies — stdlib only.

Usage:
    # Watch local auth log (Ubuntu/Debian):
    sudo python3 watch-alerts.py

    # Watch a specific file:
    sudo python3 watch-alerts.py --file /var/log/auth.log
    # or on RHEL/CentOS/Rocky:
    sudo python3 watch-alerts.py --file /var/log/secure

    # Watch all remote logs on the central server:
    sudo python3 watch-alerts.py --file /var/log/remote/*/auth.log

    # Write JSON alerts to a file (for LLM analysis later):
    sudo python3 watch-alerts.py --json-out /var/log/security-alerts.jsonl

    # Email CRITICAL/HIGH alerts via local MTA (no credentials needed):
    sudo python3 watch-alerts.py --email admin@example.com
"""

import argparse
import glob
import json
import logging
import os
import re
import signal
import smtplib
import socket
import sys
import threading
import time
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from email.message import EmailMessage

# ── Logging setup ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Alert patterns ────────────────────────────────────────────────────
# Each pattern: (regex, severity, description, category)
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

# Compile all patterns once at startup for speed
COMPILED_PATTERNS = [
    (re.compile(pattern), severity, description, category)
    for pattern, severity, description, category in ALERT_PATTERNS
]

# ── Brute force tracker ───────────────────────────────────────────────
# Track failures per IP to detect brute force bursts
FAILURE_WINDOW_SECONDS = 60
BRUTE_FORCE_THRESHOLD = 3  # failures from same IP within window = alert

class BruteForceTracker:
    """Counts failures per IP in a rolling time window."""

    def __init__(self, window_seconds: int, threshold: int):
        self.window = window_seconds
        self.threshold = threshold
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_failure(self, ip: str) -> bool:
        """
        Record a failure from an IP.
        Returns True if this failure pushed the IP over the threshold.
        """
        now = time.time()
        cutoff = now - self.window

        with self._lock:
            # Purge old entries
            self._failures[ip] = [t for t in self._failures[ip] if t > cutoff]
            self._failures[ip].append(now)
            count = len(self._failures[ip])

        # Alert only exactly at threshold to avoid duplicate alerts
        return count == self.threshold


brute_tracker = BruteForceTracker(FAILURE_WINDOW_SECONDS, BRUTE_FORCE_THRESHOLD)

# ── Alert output ──────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": "\033[1;31m",  # bold red
    "HIGH":     "\033[0;31m",  # red
    "MEDIUM":   "\033[0;33m",  # yellow
    "LOW":      "\033[0;36m",  # cyan
    "INFO":     "\033[0;32m",  # green
}
RESET = "\033[0m"

# Severities that trigger email. MEDIUM/LOW/INFO are print-only.
EMAIL_SEVERITIES = {"CRITICAL", "HIGH"}


def send_alert_email(recipient: str, severity: str, description: str, raw_line: str, source_file: str):
    """Send alert email via local MTA. No credentials required."""
    hostname = socket.getfqdn()
    subject = f"[{severity}] Security alert on {hostname}: {description}"
    body = (
        f"Severity:    {severity}\n"
        f"Description: {description}\n"
        f"Host:        {hostname}\n"
        f"Log file:    {source_file}\n"
        f"Log line:    {raw_line.strip()}\n"
    )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"security-alerts@{hostname}"
    msg["To"] = recipient
    msg.set_content(body)

    try:
        with smtplib.SMTP("localhost") as smtp:
            smtp.send_message(msg)
    except OSError as err:
        log.error("Email send failed: %s", err)


def emit_alert(
    severity: str,
    description: str,
    category: str,
    raw_line: str,
    source_file: str,
    json_out_handle,
    email_recipient: str | None,
):
    """Print a colored alert to stdout, optionally write JSON, optionally email."""
    timestamp = datetime.now(timezone.utc).isoformat()
    color = SEVERITY_COLOR.get(severity, "")

    print(
        f"{color}[{severity:8s}] {timestamp}  {description}{RESET}\n"
        f"           File: {source_file}\n"
        f"           Log:  {raw_line.strip()}\n"
    )

    if json_out_handle:
        record = {
            "timestamp": timestamp,
            "severity": severity,
            "description": description,
            "category": category,
            "source_file": source_file,
            "raw_line": raw_line.strip(),
        }
        json_out_handle.write(json.dumps(record) + "\n")
        json_out_handle.flush()

    if email_recipient and severity in EMAIL_SEVERITIES:
        send_alert_email(email_recipient, severity, description, raw_line, source_file)


# ── Log tailer ────────────────────────────────────────────────────────

def tail_file(filepath: str, json_out_handle, email_recipient: str | None):
    """
    Open a log file, seek to end, then yield new lines as they arrive.
    Handles log rotation by detecting if the file was truncated or replaced.
    """
    log.info("Watching: %s", filepath)

    try:
        file_handle = open(filepath, "r", errors="replace")
        file_handle.seek(0, 2)  # seek to end — don't replay old lines
        inode = os.fstat(file_handle.fileno()).st_ino
    except OSError as err:
        log.error("Cannot open %s: %s", filepath, err)
        return

    while True:
        line = file_handle.readline()

        if line:
            process_line(line, filepath, json_out_handle, email_recipient)
        else:
            time.sleep(0.2)

            # Check for log rotation: file replaced or truncated
            with suppress(OSError):
                new_stat = Path(filepath).stat()
                if new_stat.st_ino != inode or new_stat.st_size < file_handle.tell():
                    log.info("Log rotated: %s — reopening.", filepath)
                    file_handle.close()
                    file_handle = open(filepath, "r", errors="replace")
                    inode = os.fstat(file_handle.fileno()).st_ino


def process_line(line: str, source_file: str, json_out_handle, email_recipient: str | None):
    """Run all alert patterns against a single log line."""
    for compiled_pattern, severity, description, category in COMPILED_PATTERNS:
        match = compiled_pattern.search(line)
        if not match:
            continue

        # Extra check: count brute force from same IP
        if category == "brute_force" and len(match.groups()) >= 2:
            ip = match.group(2) if len(match.groups()) >= 2 else ""
            if ip and not brute_tracker.record_failure(ip):
                # Don't alert on every single failure — wait for threshold
                # Exception: still alert on CRITICAL/HIGH for visibility
                if severity not in ("CRITICAL", "HIGH"):
                    continue

        emit_alert(severity, description, category, line, source_file, json_out_handle, email_recipient)
        break  # One alert per line is enough


# ── Main ──────────────────────────────────────────────────────────────

def resolve_log_files(file_patterns: list[str]) -> list[str]:
    """Expand glob patterns and return matching file paths."""
    paths = []
    for pattern in file_patterns:
        matched = glob.glob(pattern)
        if matched:
            paths.extend(matched)
        elif Path(pattern).exists():
            paths.append(pattern)

    if not paths:
        candidates = [
            "/var/log/auth.log",   # Ubuntu/Debian
            "/var/log/secure",     # RHEL/CentOS/Rocky
            "/var/log/messages",   # RHEL fallback
        ]
        for candidate in candidates:
            if Path(candidate).exists():
                paths.append(candidate)

    if not paths:
        log.error("No log files found at: %s", file_patterns)
        sys.exit(1)

    return paths


def main():
    parser = argparse.ArgumentParser(
        description="Real-time security log watcher. Alerts on suspicious patterns."
    )
    parser.add_argument(
        "--file",
        nargs="+",
        default=["/var/log/auth.log"],
        help=(
            "Log file(s) to watch. Supports globs (quote to prevent shell expansion): "
            "'/var/log/remote/*/auth.log'. Also accepts shell-expanded paths. "
            "Defaults to /var/log/auth.log (Ubuntu/Debian) or /var/log/secure (RHEL)."
        ),
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Write JSON alert records to this file (one JSON object per line).",
    )
    parser.add_argument(
        "--email",
        default=None,
        metavar="ADDRESS",
        help="Email address to notify on CRITICAL/HIGH alerts via local MTA.",
    )
    args = parser.parse_args()

    log_files = resolve_log_files(args.file)  # args.file is already a list via nargs='+'

    json_out_handle = None
    if args.json_out:
        try:
            json_out_handle = open(args.json_out, "a", buffering=1)
            log.info("JSON alerts writing to: %s", args.json_out)
        except OSError as err:
            log.error("Cannot open JSON output file: %s", err)
            sys.exit(1)

    if args.email:
        log.info("Email alerts (CRITICAL/HIGH) → %s", args.email)

    print(f"\nWatching {len(log_files)} file(s). Press Ctrl+C to stop.\n")

    # Handle Ctrl+C cleanly
    def handle_shutdown(signum, frame):
        print("\nShutting down.")
        if json_out_handle:
            json_out_handle.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Start one thread per log file
    threads = []
    for filepath in log_files:
        thread = threading.Thread(
            target=tail_file,
            args=(filepath, json_out_handle, args.email),
            daemon=True,
            name=f"tailer-{os.path.basename(filepath)}",
        )
        thread.start()
        threads.append(thread)

    # Keep main thread alive
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
