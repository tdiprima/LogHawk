# Log Reports Have Stopped — Troubleshooting Guide

Work through these layers in order. Each section isolates one part of the pipeline.

---

## 1. Is the daemon running?

```bash
systemctl status loghawk-alerts
```

If it's stopped or failed, restart it and check the reason:

```bash
sudo systemctl restart loghawk-alerts
journalctl -u loghawk-alerts -n 50
```

---

## 2. Are the log files being updated?

Check whether the source logs themselves have recent activity:

```bash
ls -lt /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null | head
```

If timestamps are stale, the problem is upstream — rsyslog isn't writing, not LogHawk.

---

## 3. Is rsyslog running?

```bash
systemctl status rsyslog
```

If stopped:

```bash
sudo systemctl restart rsyslog
```

> **Known gotcha:** After logrotate runs, rsyslog may keep writing to the rotated file.
> Always HUP rsyslog after rotation so it reopens the current log file:
> ```bash
> sudo kill -HUP $(cat /var/run/rsyslog.pid)
> ```
> See [project_logrotate-rsyslog-gotcha.md](../memory/project_logrotate-rsyslog-gotcha.md).

---

## 4. Are remote logs arriving at the central server?

Run the pipeline health check:

```bash
sudo bash tools/check-log-pipeline.sh
```

- `STALE` → the host's logs haven't updated in the last 15 minutes (default threshold).
- `MISS` → an expected log file is absent entirely.
- `EMPTY` → no log files found at all for that host.

If hosts are stale, check agent-side rsyslog and TLS certs (see step 6).

---

## 5. Are alerts actually being generated?

Run the watcher manually against the log files in question:

```bash
sudo python3 tools/watch-alerts.py --min-severity INFO
```

If patterns match but you see nothing, your `--min-severity` setting in
`/etc/loghawk/alerts.conf` may be filtering them out.

---

## 6. Are agent hosts forwarding logs? (central server setup only)

On the **agent host**:

```bash
systemctl status rsyslog
# Check for TLS errors in rsyslog's output:
journalctl -u rsyslog -n 30
```

Common causes of silent forwarding failure:

| Symptom | Fix |
|---|---|
| `certificate verify failed` | Regenerate or re-copy certs — see `central/generate-client-cert.sh` |
| Queue files growing in `/var/spool/rsyslog/` | Central server unreachable — check port 6514 is open |
| Rsyslog running but no logs sent | Re-run `agent/install-agent.sh` to re-apply the forwarding config |

---

## 7. Is email delivery working?

If alerts appear on the console but emails aren't arriving:

```bash
# Test the local MTA directly:
echo "test" | mail -s "loghawk test" your@email.com

# Check mail queue:
mailq

# Check postfix/sendmail status:
systemctl status postfix
```

If no local MTA is running, install one:

```bash
sudo apt install postfix   # Ubuntu/Debian
sudo dnf install postfix   # RHEL/Rocky
sudo systemctl enable --now postfix
```

---

## 8. Check the config

```bash
cat /etc/loghawk/loghawk.conf
cat /etc/loghawk/alerts.conf
```

Things to verify:

- `log_base` points to the right directory.
- `email_severities` includes the levels you expect (default: `CRITICAL,HIGH`).
- `dedup_window_seconds` isn't set so high that alerts are being suppressed.

After any config change:

```bash
sudo systemctl restart loghawk-alerts
```

---

## Quick summary

```
No reports
├── Daemon stopped?          → systemctl restart loghawk-alerts
├── Log files stale?         → rsyslog stopped or logrotate HUP missed
├── Remote logs stale?       → check-log-pipeline.sh → agent rsyslog / certs
├── Patterns not matching?   → run watch-alerts.py manually, lower --min-severity
├── Emails not arriving?     → local MTA down or misconfigured
└── Config changed?          → restart daemon after any edit to loghawk.conf
```
