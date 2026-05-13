# LogHawk 🦅

LogHawk is a lightweight Linux security observability toolkit for collecting, searching, and alerting on system logs across a small fleet.

It uses `rsyslog` with mutual TLS to forward logs from monitored servers to a central collector, then provides practical tools for real-time alerts, incident investigation, pipeline health checks, and AI-ready event exports.

## Why It Exists

LogHawk is built for environments where full SIEM platforms are too heavy, but raw SSH access and scattered `/var/log` files are not enough.

It demonstrates:

- Secure centralized log collection with rsyslog over TLS
- Linux operations across Ubuntu/Debian and RHEL-style systems
- Security-focused detection for auth, sudo, kernel, cron, auditd, and service events
- Small, dependency-light Python and Bash tooling
- Operational polish: installers, systemd service files, config loading, log rotation, and health checks

## Features

- 🔐 mTLS log forwarding from agents to a central collector
- Per-host remote log storage under `/var/log/remote/<hostname>/`
- Real-time alerting with severity levels and duplicate suppression
- Optional email alerts through the local mail transfer agent
- JSONL alert output for downstream tools
- Search shortcuts for common investigations
- Pipeline freshness checks for missing or stale logs
- AI export tool that turns suspicious log activity into structured JSON or a ready-to-paste LLM prompt

## Repository Layout

```text
central/   Collector setup, rsyslog receiver config, and certificate helpers
agent/     Agent installer and rsyslog forwarding config
tools/     Alerting, search, export, config, daemon, and pipeline utilities
```

## Requirements

- Linux host with `systemd`
- `rsyslog`
- `openssl` for certificate generation
- Python 3.9+
- `apt`, `dnf`, or `yum` on target hosts

Python tooling uses the standard library only.

## Quick Start

Generate a private CA, server certificate, and client certificates:

```bash
./central/generate-certs.sh \
  --server-name log-server.example.com \
  --server-address 10.0.0.10 \
  --client-name web-01 \
  --client-name db-01
```

Copy certificates to the collector and agents:

```bash
./central/copy-certs.sh log-server.example.com --role collector
./central/copy-certs.sh web-01 --role agent --client-name web-01
```

Install the central collector:

```bash
sudo ./central/install-central.sh --allow-from 10.0.0.0/24
```

Install an agent on each monitored server:

```bash
sudo ./agent/install-agent.sh log-server.example.com
```

Install the alert daemon on the collector:

```bash
sudo ./tools/install-alerts-daemon.sh \
  --email security@example.com \
  --file '/var/log/remote/*/*.log' \
  --min-severity HIGH \
  --json-out /var/log/loghawk-alerts.jsonl
```

## Common Commands

Watch logs interactively:

```bash
sudo python3 tools/watch-alerts.py --file '/var/log/remote/*/*.log'
```

Search for SSH failures:

```bash
sudo ./tools/search-logs.sh ssh-fails
```

Search for activity from an IP:

```bash
sudo ./tools/search-logs.sh from-ip 192.168.1.50
```

Check whether remote logs are stale:

```bash
sudo ./tools/check-log-pipeline.sh --minutes 15
```

Export suspicious events as JSON:

```bash
sudo python3 tools/export-for-ai.py --hours 24 --out /tmp/loghawk-events.json
```

Generate an LLM-ready incident prompt:

```bash
sudo python3 tools/export-for-ai.py --hours 2 --llm-prompt
```

## Configuration

Most tools read `/etc/loghawk/loghawk.conf` when present. A sample config is available at:

```text
tools/loghawk.conf.example
```

You can override the config path with:

```bash
LOGHAWK_CONFIG=/path/to/loghawk.conf
```

Python tools also support:

```bash
--config /path/to/loghawk.conf
```

## Alert Coverage

LogHawk includes detection patterns for:

- SSH failed logins, invalid users, successful logins, and root logins
- Sudo activity and denied privilege escalation attempts
- User, group, password, SSH, and sudo configuration changes
- Kernel panics, disk errors, OOM kills, segfaults, and hardware errors
- Cron changes and root cron execution
- auditd authentication, anomaly, policy, and user management events
- systemd service failures, DNS issues, firewall drops, and disk-full events

## Project Status

This is a practical security engineering project. Review detection patterns, retention, firewall rules, certificate handling, and alert routing before using it in production. Read the [docs](./docs).

## License

MIT License. See [LICENSE](LICENSE).

<br>
