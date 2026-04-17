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

### 3. Set up the log server as a forwarding agent

The log server itself also runs the forwarding agent. After deploying
`agent/rsyslog-agent.conf` to `/etc/rsyslog.d/99-security-forward.conf` on the
log server, two edits are required to avoid conflicts with the central config:

1. **Remove the `global()` block** (lines starting with `global(` through the
   closing `)`) — the central config already sets these TLS globals.
2. **Remove the two module lines** that load `imuxsock` and `imklog` — they are
   already loaded by the default `rsyslog.conf`.

Also set correct ownership and permissions on the certs directory so rsyslog
can read them:

```bash
sudo chown root:syslog /etc/rsyslog.d/certs/*.pem
sudo chmod 640 /etc/rsyslog.d/certs/*.pem
```

Then restart: `sudo systemctl restart rsyslog`

### 4. Install the forwarding agent

Run on each server you want to monitor.

```bash
sudo ./agent/install-agent.sh log-server.example.com \
    --server-name log-server.example.com
```

Installs rsyslog, drops the forwarding config, and verifies the TCP connection to the collector.

### 5. Watch for alerts in real time

```bash
# Local auth log
sudo python3 tools/watch-alerts.py

# All remote hosts on the central server
sudo python3 tools/watch-alerts.py --file /var/log/remote/*/auth.log

# With email alerts for CRITICAL/HIGH events
sudo python3 tools/watch-alerts.py --email security@example.com
```

### 6. Search logs during an investigation

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

### 7. Check pipeline health

Identify hosts that have stopped sending logs.

```bash
./tools/check-log-pipeline.sh --minutes 15
```

### 8. Export for AI-assisted analysis

```bash
# Last 2 hours, LLM-ready prompt to stdout
sudo python3 tools/export-for-ai.py --llm-prompt

# Last 24 hours for a specific host, saved to file
sudo python3 tools/export-for-ai.py --hours 24 --host web-01 --out incident.json
```

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

```sh
$ ./tools/search-logs.sh from-ip 203.0.113.45
```

Then export everything for AI triage:

```sh
$ sudo python3 tools/export-for-ai.py --hours 2 --llm-prompt | pbcopy
# Paste directly into Claude or ChatGPT
```

## Requirements

- Linux: Ubuntu/Debian or RHEL/CentOS/Rocky
- Python 3.9+ (stdlib only — no pip installs needed)
- `openssl` for certificate generation
- `rsyslog` (installed automatically by the setup scripts)
- Local MTA (e.g. postfix) if using email alerting

<BR>
