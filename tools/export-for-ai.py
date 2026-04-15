#!/usr/bin/env python3
"""
export-for-ai.py
Extracts suspicious log events into clean JSON for LLM analysis.
Outputs a structured summary you can paste directly into ChatGPT, Claude, etc.

Usage:
    # Export last 2 hours of suspicious activity:
    sudo python3 export-for-ai.py

    # Export from a specific host's logs:
    sudo python3 export-for-ai.py --host web-server-01

    # Export last 24 hours:
    sudo python3 export-for-ai.py --hours 24

    # Save to file:
    sudo python3 export-for-ai.py --out /tmp/incident-2026-04-15.json

    # Print a ready-to-paste LLM prompt:
    sudo python3 export-for-ai.py --llm-prompt
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Alert patterns (same as watch-alerts.py) ─────────────────────────
ALERT_PATTERNS = [
    (r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)",
     "HIGH", "SSH failed login", "brute_force"),
    (r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)",
     "INFO", "SSH successful login", "auth_success"),
    (r"Accepted .+ for root from ([\d.]+)",
     "CRITICAL", "Root SSH login", "root_login"),
    (r"sudo:\s+(\S+) : .* COMMAND=(.*)",
     "MEDIUM", "Sudo command executed", "privilege_escalation"),
    (r"sudo:\s+(\S+) : .* command not allowed",
     "HIGH", "Sudo denied", "privilege_escalation"),
    (r"useradd\[.*\]: new user: name=(\S+)",
     "HIGH", "New user created", "account_change"),
    (r"userdel\[.*\]: delete user '(\S+)'",
     "HIGH", "User deleted", "account_change"),
    (r"passwd\[.*\]: password changed for (\S+)",
     "MEDIUM", "Password changed", "account_change"),
    (r"Invalid user (\S+) from ([\d.]+)",
     "MEDIUM", "Login attempt for nonexistent user", "brute_force"),
    (r"groupadd\[.*\]: new group: name=(\S+)",
     "MEDIUM", "New group created", "account_change"),
    (r"COMMAND=.*(?:sshd_config|authorized_keys|sudoers)",
     "HIGH", "SSH or sudo config touched", "config_change"),
]

COMPILED_PATTERNS = [
    (re.compile(pattern), severity, description, category)
    for pattern, severity, description, category in ALERT_PATTERNS
]

# ── Timestamp parsing ─────────────────────────────────────────────────
# syslog format: "Apr 15 14:23:01"
SYSLOG_TS_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
CURRENT_YEAR = datetime.now().year


def parse_syslog_timestamp(line: str) -> datetime | None:
    """Parse syslog-format timestamp from a log line. Returns UTC datetime or None."""
    match = SYSLOG_TS_PATTERN.match(line)
    if not match:
        return None
    try:
        # syslog omits the year — assume current year
        raw = f"{match.group(1)} {CURRENT_YEAR}"
        dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ── Log extraction ────────────────────────────────────────────────────

def extract_events(log_file: str, since: datetime) -> list[dict]:
    """Read a log file and return suspicious events newer than `since`."""
    events = []

    try:
        with open(log_file, "r", errors="replace") as fh:
            for line in fh:
                ts = parse_syslog_timestamp(line)
                if ts and ts < since:
                    continue  # too old

                for compiled_pattern, severity, description, category in COMPILED_PATTERNS:
                    if compiled_pattern.search(line):
                        events.append({
                            "timestamp": ts.isoformat() if ts else None,
                            "source_file": log_file,
                            "severity": severity,
                            "description": description,
                            "category": category,
                            "raw_line": line.strip(),
                        })
                        break  # one match per line

    except OSError as err:
        print(f"WARNING: Cannot read {log_file}: {err}", file=sys.stderr)

    return events


def find_log_files(log_base: str, hostname_filter: str | None) -> list[str]:
    """Return list of auth log files to scan."""
    files = []

    if hostname_filter:
        pattern = os.path.join(log_base, hostname_filter, "auth.log")
        files.extend(glob.glob(pattern))
    else:
        files.extend(glob.glob(os.path.join(log_base, "*/auth.log")))

    # Always include local auth log
    for candidate in ["/var/log/auth.log", "/var/log/secure"]:
        if os.path.exists(candidate):
            files.append(candidate)

    return files


# ── Summary builder ───────────────────────────────────────────────────

def build_summary(events: list[dict]) -> dict:
    """Aggregate stats for the LLM prompt."""
    from collections import Counter

    ip_failures: Counter = Counter()
    ip_successes: Counter = Counter()
    users_touched: set = set()
    categories: Counter = Counter()

    for event in events:
        raw = event.get("raw_line", "")
        categories[event["category"]] += 1

        # Extract IP from raw line if present
        ip_match = re.search(r"from ([\d.]+)", raw)
        if ip_match:
            ip = ip_match.group(1)
            if event["category"] == "brute_force":
                ip_failures[ip] += 1
            elif event["category"] == "auth_success":
                ip_successes[ip] += 1

        # Extract usernames
        user_match = re.search(r"for (?:invalid user )?(\S+) from", raw)
        if user_match:
            users_touched.add(user_match.group(1))

    return {
        "total_events": len(events),
        "by_category": dict(categories),
        "top_attacking_ips": ip_failures.most_common(10),
        "successful_login_ips": ip_successes.most_common(10),
        "usernames_seen": sorted(users_touched),
        "critical_events": [e for e in events if e["severity"] == "CRITICAL"],
        "high_events": [e for e in events if e["severity"] == "HIGH"],
    }


def build_llm_prompt(events: list[dict], summary: dict, hours: int) -> str:
    """Format a prompt ready to paste into an LLM."""
    prompt = f"""You are a security analyst. Analyze the following security log events from the last {hours} hour(s) and identify:
1. Any active attacks or intrusion attempts
2. Suspicious patterns or anomalies
3. Accounts or IPs that need immediate investigation
4. Recommended immediate actions

## Summary Statistics
- Total suspicious events: {summary['total_events']}
- Events by category: {json.dumps(summary['by_category'], indent=2)}
- Top attacking IPs: {json.dumps(summary['top_attacking_ips'], indent=2)}
- Successful login IPs: {json.dumps(summary['successful_login_ips'], indent=2)}
- Usernames seen in events: {summary['usernames_seen']}

## Critical Events
{json.dumps(summary['critical_events'], indent=2)}

## High Severity Events (first 50)
{json.dumps(summary['high_events'][:50], indent=2)}

## All Events (first 200)
{json.dumps(events[:200], indent=2)}

Please provide a concise threat assessment and prioritized action items.
"""
    return prompt


# ── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Export security log events as JSON for LLM analysis."
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Hostname to filter (matches subdir under LOG_BASE).",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=2,
        help="How many hours back to look (default: 2).",
    )
    parser.add_argument(
        "--log-base",
        default="/var/log/remote",
        help="Base directory for remote logs (default: /var/log/remote).",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Write JSON output to this file instead of stdout.",
    )
    parser.add_argument(
        "--llm-prompt",
        action="store_true",
        help="Output a formatted prompt ready to paste into an LLM.",
    )
    args = parser.parse_args()

    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    log_files = find_log_files(args.log_base, args.host)

    if not log_files:
        print(f"ERROR: No log files found under {args.log_base}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {len(log_files)} log file(s) for last {args.hours} hour(s)...",
          file=sys.stderr)

    all_events: list[dict] = []
    for log_file in log_files:
        events = extract_events(log_file, since)
        all_events.extend(events)
        print(f"  {log_file}: {len(events)} events", file=sys.stderr)

    all_events.sort(key=lambda e: e.get("timestamp") or "")

    summary = build_summary(all_events)

    if args.llm_prompt:
        output = build_llm_prompt(all_events, summary, args.hours)
        if args.out:
            Path(args.out).write_text(output)
            print(f"LLM prompt written to: {args.out}", file=sys.stderr)
        else:
            print(output)
        return

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hours_scanned": args.hours,
        "log_files_scanned": log_files,
        "summary": summary,
        "events": all_events,
    }

    output = json.dumps(result, indent=2)

    if args.out:
        Path(args.out).write_text(output)
        print(f"Written to: {args.out}", file=sys.stderr)
        print(f"Total events: {len(all_events)}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
