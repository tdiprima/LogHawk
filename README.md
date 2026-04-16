# Security Observability Stack

Centralize Linux security logs, keep them off the host, and watch them from one place.

This stack is still intentionally small, but it now defaults to production-safe basics:

- TLS-encrypted rsyslog forwarding on TCP `6514`
- mutual certificate validation
- optional source-subnet firewall allowlisting
- central retention with configurable rotation
- forwarding of `auditd` in addition to auth/kernel/cron/syslog
- a simple pipeline-health check for stale senders

## What This Does

```text
[ each server ]  --TLS syslog-->  [ central collector ]
                                   |-> watch-alerts.py
                                   |-> search-logs.sh
                                   |-> export-for-ai.py
                                   |-> check-log-pipeline.sh
```

Logs land under `/var/log/remote/<hostname>/` with separate files such as:

- `auth.log`
- `audit.log`
- `kern.log`
- `cron.log`
- `syslog.log`

## Repo Layout

```text
logging-stack/
├── agent/
│   ├── install-agent.sh
│   └── rsyslog-agent.conf
├── central/
│   ├── generate-certs.sh
│   ├── install-central.sh
│   └── rsyslog-central.conf
├── docs/
├── tools/
│   ├── check-log-pipeline.sh
│   ├── export-for-ai.py
│   ├── search-logs.sh
│   └── watch-alerts.py
└── README.md
```

## Recommended Setup

### 1. Keep clocks in sync

Centralized logs are much less useful if timestamps drift.

Install and enable one of:

```bash
sudo systemctl enable --now chronyd
```

or

```bash
sudo systemctl enable --now systemd-timesyncd
```

### 2. Generate a private CA and certificates

On the machine where you are preparing the rollout:

```bash
chmod +x central/generate-certs.sh
./central/generate-certs.sh \
  --server-name log-server.example.com \
  --server-address 10.0.0.10 \
  --client-name web-01 \
  --client-name db-01
```

This creates:

- `central/certs/ca/ca-cert.pem`
- `central/certs/server/server-cert.pem`
- `central/certs/server/server-key.pem`
- `central/certs/clients/<hostname>/client-cert.pem`
- `central/certs/clients/<hostname>/client-key.pem`

Copy:

- the CA certificate to every machine
- the server cert/key to the collector
- one client cert/key pair to each agent

Suggested destination on each host:

```text
/etc/rsyslog.d/certs/
```

### 3. Install the central collector

On the log server:

```bash
sudo ./central/install-central.sh \
  --port 6514 \
  --allow-from 10.0.0.0/24 \
  --tls-ca /etc/rsyslog.d/certs/logging-ca.pem \
  --tls-cert /etc/rsyslog.d/certs/server-cert.pem \
  --tls-key /etc/rsyslog.d/certs/server-key.pem \
  --retention-days 90
```

Notes:

- `--allow-from` is strongly recommended.
- If you omit `--allow-from`, the script opens the TLS port to any source.
- Retention is configurable; default is `90` days.

### 4. Install each agent

On every monitored host:

```bash
sudo ./agent/install-agent.sh 10.0.0.10 \
  --server-name log-server.example.com \
  --port 6514 \
  --tls-ca /etc/rsyslog.d/certs/logging-ca.pem \
  --tls-cert /etc/rsyslog.d/certs/agent-cert.pem \
  --tls-key /etc/rsyslog.d/certs/agent-key.pem
```

The positional argument is where the agent connects.

`--server-name` must match the collector certificate name or SAN used in TLS validation.

## Daily Operations

Watch all remote auth logs:

```bash
sudo python3 tools/watch-alerts.py --file '/var/log/remote/*/auth.log'
```

Persist alert records:

```bash
sudo python3 tools/watch-alerts.py \
  --file '/var/log/remote/*/auth.log' \
  --json-out /var/log/security-alerts.jsonl
```

Search centrally:

```bash
sudo ./tools/search-logs.sh ssh-fails
sudo ./tools/search-logs.sh ssh-fails web-server-01
sudo ./tools/search-logs.sh from-ip 185.220.101.5
sudo ./tools/search-logs.sh sudo-commands
sudo ./tools/search-logs.sh new-accounts
sudo ./tools/search-logs.sh last-logins
```

Check for stale senders:

```bash
sudo ./tools/check-log-pipeline.sh --minutes 15
```

Export recent suspicious events for triage:

```bash
sudo python3 tools/export-for-ai.py --hours 4 --llm-prompt --out /tmp/ask-ai.txt
```

## What Is Collected

Agents forward:

- `auth` / `authpriv`
- `kern`
- `cron`
- `daemon`
- `syslog`
- `auditd` via `/var/log/audit/audit.log`

This is still host-log focused. It does not automatically ingest app logs, cloud control-plane logs, or identity-provider logs.

## Current Security Posture

This repo now covers the main centralized-logging baseline:

- off-host copies of security-relevant Linux logs
- encrypted transport
- certificate-based authentication
- local queueing on agents during collector outages
- source-restricted firewalling when configured
- configurable retention
- basic stale-sender monitoring

Still missing if you want a fuller production program:

- immutable/offsite archive
- structured application logging and trace correlation
- ingestion/drop-rate dashboards
- alerting on collector resource pressure
- richer detections beyond regexes over auth/audit/syslog

## Troubleshooting

Collector not receiving logs:

1. Check rsyslog status: `systemctl status rsyslog`
2. Check the listener config: `cat /etc/rsyslog.d/10-security-central.conf`
3. Check the TLS files exist and are readable by rsyslog
4. Check the agent can reach TCP `6514`
5. Check the agent certificate chains to the same CA as the collector

Agent not forwarding:

1. Check the generated config: `cat /etc/rsyslog.d/99-security-forward.conf`
2. Check `journalctl -u rsyslog --no-pager -n 50`
3. Confirm `--server-name` matches the collector certificate identity
4. Confirm `/var/log/audit/audit.log` exists if you expect auditd forwarding

No logs found by the watcher:

```bash
sudo python3 tools/watch-alerts.py --file /var/log/auth.log
```

## Next

Read [docs/spot-weirdness.md](/Users/tdiprima/Documents/trabajo/logging-stack/docs/spot-weirdness.md) for investigation patterns and response ideas.
