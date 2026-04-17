![LogHawk Banner Design](LogHawk-Banner-Design.png)

Centralized security log collection, real-time alerting, and AI-ready incident export for Linux server fleets.

## When your servers are blind spots

SSH brute-force attacks, unauthorized sudo escalations, and rogue account creation all leave traces — but only if you're watching. On a fleet of servers, those traces are scattered across dozens of individual `/var/log/auth.log` files with no way to correlate them, no alerting, and no audit trail. By the time you notice something went wrong, the window to respond has already closed.

## What LogHawk does

LogHawk wires your servers into a single, tamper-resistant log pipeline. Each monitored host ships its auth logs to a central collector over mutual TLS so logs can't be spoofed or intercepted in transit. On the collector, a real-time watcher fires color-coded alerts the moment suspicious patterns appear — SSH brute force bursts, root logins, privilege escalation attempts, account changes. For deeper investigation, a set of forensic search shortcuts lets you pivot instantly from "something happened" to "here's every action that IP ever took." When an incident needs human or AI analysis, a single command exports structured JSON plus a ready-to-paste LLM prompt.

Everything runs on standard rsyslog. No agents to maintain, no cloud dependency, no external Python packages.

## Example: catching a brute-force campaign in real time

```
$ sudo python3 tools/watch-alerts.py --file /var/log/remote/*/auth.log \
    --json-out /var/log/security-alerts.jsonl \
    --email security@example.com

[HIGH    ] 2026-04-17T14:22:01+00:00  SSH failed login
           File: /var/log/remote/web-01/auth.log
           Log:  Apr 17 14:22:01 web-01 sshd[9823]: Failed password for root from 203.0.113.45

[CRITICAL] 2026-04-17T14:22:03+00:00  Root SSH login
           File: /var/log/remote/web-01/auth.log
           Log:  Apr 17 14:22:03 web-01 sshd[9831]: Accepted password for root from 203.0.113.45
```

Then pivot to the attacker's full history:

```
$ ./tools/search-logs.sh from-ip 203.0.113.45
```

Then export everything for AI triage:

```
$ sudo python3 tools/export-for-ai.py --hours 2 --llm-prompt | pbcopy
# Paste directly into Claude or ChatGPT
```

## Usage

### 1. Generate mTLS certificates

Run once on any machine with `openssl`. Generates a private CA plus server and per-agent client certificates.

```bash
./central/generate-certs.sh \
    --server-name log-server.example.com \
    --server-address 10.0.0.10 \
    --client-name web-01 \
    --client-name db-01
```

Copy the CA cert and the appropriate client cert/key pair to each agent host before installing.

### 2. Set up the central collector

Run on the server that will receive logs from all other hosts.

```bash
sudo ./central/install-central.sh \
    --allow-from 10.0.0.0/24 \
    --retention-days 90
```

Installs rsyslog, configures TLS reception on port 6514, sets up log rotation, and opens the firewall.

### 3. Install the forwarding agent

Run on each server you want to monitor.

```bash
sudo ./agent/install-agent.sh log-server.example.com \
    --server-name log-server.example.com
```

Installs rsyslog, drops the forwarding config, and verifies the TCP connection to the collector.

### 4. Watch for alerts in real time

```bash
# Local auth log
sudo python3 tools/watch-alerts.py

# All remote hosts on the central server
sudo python3 tools/watch-alerts.py --file /var/log/remote/*/auth.log

# With email alerts for CRITICAL/HIGH events
sudo python3 tools/watch-alerts.py --email security@example.com
```

### 5. Search logs during an investigation

```bash
# All SSH failures across the fleet
./tools/search-logs.sh ssh-fails

# SSH failures on one specific host
./tools/search-logs.sh ssh-fails web-01

# Everything logged from a suspicious IP
./tools/search-logs.sh from-ip 203.0.113.45

# Sudo command history
./tools/search-logs.sh sudo-commands

# User or group creation/deletion events
./tools/search-logs.sh new-accounts
```

### 6. Check pipeline health

Identify hosts that have stopped sending logs.

```bash
./tools/check-log-pipeline.sh --minutes 15
```

### 7. Export for AI-assisted analysis

```bash
# Last 2 hours, LLM-ready prompt to stdout
sudo python3 tools/export-for-ai.py --llm-prompt

# Last 24 hours for a specific host, saved to file
sudo python3 tools/export-for-ai.py --hours 24 --host web-01 --out incident.json
```

## Requirements

- Linux: Ubuntu/Debian or RHEL/CentOS/Rocky
- Python 3.9+ (stdlib only — no pip installs needed)
- `openssl` for certificate generation
- `rsyslog` (installed automatically by the setup scripts)
- Local MTA (e.g. postfix) if using email alerting

## License

[MIT](LICENSE)

<br>
