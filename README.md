# Security Observability Stack

Watch your servers for sketchy activity. Get alerted in real time. Search logs fast. Export everything to an AI for analysis.

No giant enterprise setup. No paid tools. Just rsyslog + two Python scripts + two shell scripts.

## What This Does

```
[ each server ]  →  forwards logs  →  [ log server ]  →  watch-alerts.py screams at you
                                                       →  search-logs.sh lets you dig
                                                       →  export-for-ai.py feeds an LLM
```

Every server you care about sends a copy of its auth logs to one central place.
You watch that central place for anything suspicious.

## What's in This Folder

```
security-stack/
├── agent/
│   ├── install-agent.sh        ← run this on EACH server you want to monitor
│   └── rsyslog-agent.conf      ← (used automatically by install-agent.sh)
│
├── central/
│   ├── install-central.sh      ← run this ONCE on your log server
│   └── rsyslog-central.conf    ← (used automatically by install-central.sh)
│
├── tools/
│   ├── watch-alerts.py         ← real-time watcher — prints alerts as they happen
│   ├── search-logs.sh          ← grep shortcuts for common questions
│   └── export-for-ai.py        ← pull recent events into JSON or an LLM prompt
│
└── docs/
    └── spot-weirdness.md       ← read this — explains how to find threats fast
```

## Step-by-Step Setup

### Step 1 — Pick a log server

This is the machine that receives logs from everyone else. It can be any server.
It just needs to be reachable on **TCP port 514** from your other servers.

### Step 2 — Set up the log server

SSH into your log server and run:

```bash
sudo ./central/install-central.sh
```

That's it. It installs rsyslog, opens port 514, sets up log rotation, and starts receiving.

Logs will land in `/var/log/remote/<hostname>/auth.log`.

### Step 3 — Set up each server you want to monitor

SSH into each server and run:

```bash
sudo ./agent/install-agent.sh <log-server-ip>
```

Replace `<log-server-ip>` with the IP of the server from Step 2.

Example:
```bash
sudo ./agent/install-agent.sh 10.0.0.10
```

Repeat this on every server you care about.

### Step 4 — Start watching for alerts

On your **log server**, run:

```bash
sudo python3 tools/watch-alerts.py --file '/var/log/remote/*/auth.log'
```

Leave it running. It tails all the logs and prints colored alerts when something suspicious happens.

Want to save alerts to a file for later AI analysis? Add `--json-out`:

```bash
sudo python3 tools/watch-alerts.py \
  --file '/var/log/remote/*/auth.log' \
  --json-out /var/log/security-alerts.jsonl
```

Email:

```sh
sudo python3 tools/watch-alerts.py --email admin@example.com --file '/var/log/remote/*/auth.log' --json-out /var/log/security-alerts.jsonl
```

## Searching Logs

Run these on the **log server**:

```bash
# See all SSH failures across all servers
sudo ./tools/search-logs.sh ssh-fails

# See SSH failures on one specific server
sudo ./tools/search-logs.sh ssh-fails web-server-01

# See everything from a suspicious IP
sudo ./tools/search-logs.sh from-ip 185.220.101.5

# See all sudo commands run
sudo ./tools/search-logs.sh sudo-commands

# See new user accounts created
sudo ./tools/search-logs.sh new-accounts

# See recent successful logins
sudo ./tools/search-logs.sh last-logins

# See all available commands
sudo ./tools/search-logs.sh help
```

## Getting an AI to Analyze Your Logs

Export the last few hours of suspicious events and ask an AI what's going on:

```bash
# Generate a ready-to-paste prompt covering the last 4 hours:
sudo python3 tools/export-for-ai.py --hours 4 --llm-prompt --out /tmp/ask-ai.txt

# Read it:
cat /tmp/ask-ai.txt
```

Paste the output into Claude, ChatGPT, or any LLM. Ask: *"What's going on here? What should I do?"*

## What Counts as Suspicious

The watcher alerts on:

| Alert | Severity |
|-------|----------|
| Root SSH login | CRITICAL |
| SSH brute force (5+ failures from same IP) | HIGH |
| New user account created | HIGH |
| Sudo denied (unauthorized escalation) | HIGH |
| SSH/sudo config file touched | HIGH |
| User account deleted | HIGH |
| Login for nonexistent username | MEDIUM |
| Sudo command executed | MEDIUM |
| Password changed | MEDIUM |
| Successful SSH login | INFO |

## Requirements

- Ubuntu or RHEL-based Linux (works on both)
- Python 3.9+
- `rsyslog` (installed automatically if missing)
- Run install scripts as root (`sudo`)
- No external Python packages needed — stdlib only

## Something Went Wrong?

**Logs aren't showing up on the central server:**
1. Check that port 514 is open: `telnet <log-server-ip> 514`
2. Check rsyslog is running: `systemctl status rsyslog`
3. Check the agent config was written: `cat /etc/rsyslog.d/99-security-forward.conf`

**watch-alerts.py says no log files found:**
Give it a path that actually exists:
```bash
sudo python3 tools/watch-alerts.py --file /var/log/auth.log
```

**Permission denied reading logs:**
Run with `sudo`. Auth logs are root-readable only.

## Read This Next

`docs/spot-weirdness.md` — explains the most common attack patterns, what to look for, a daily 5-minute checklist, and what to do when you find something bad.

<br>
