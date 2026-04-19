# LogHawk Testing Guide

End-to-end verification after installing the central collector and each agent.

---

## What's Covered 👇

1. **Certs** — fingerprint match, mTLS handshake, perms locked in
2. **Central** — port check, service up, self-inject doing its thing
3. **Agent** — placeholder check, TCP connect, inject + verify on central per host
4. **Self-forward** — log server pulling double duty, rsyslog config passes vibe check
5. **Pipeline health** — check-log-pipeline.sh + stale log simulation
6. **watch-alerts.py** — inject per severity, brute-force thresholds, JSON output, log rotation handled
7. **search-logs.sh** — all commands tested + error paths hit
8. **export-for-ai.py** — JSON export, host filter, file output, LLM-ready prompt, missing-path error handled
9. **Full E2E scenario** — copy-paste code, whole flow validated
10. **Negative/security tests** — wrong cert, no cert, raw TCP, bad paths (all the cursed cases)
11. **Quick checklist** — post-install sanity check so nothing's silently broken

---

## 1. Certificate and TLS Setup

**Verify cert files exist and have correct permissions on central:**

```bash
ls -la /etc/rsyslog.d/certs/
# Expected: logging-ca.pem, server-cert.pem, server-key.pem
# Owner: root:syslog, mode: 640
```

**Verify server cert CN matches what agents will use as permitted peer:**

```bash
openssl x509 -in /etc/rsyslog.d/certs/server-cert.pem -noout -subject
# Returns: subject=CN=log-server.example.com
```

**Verify CA cert on agent matches CA cert on central (hashes must match):**

```bash
# Run on both central and agent, compare output
openssl x509 -in /etc/rsyslog.d/certs/logging-ca.pem -noout -fingerprint -sha256
```

**Verify mTLS handshake from an agent host:**

```bash
openssl s_client \
  -connect log-server.example.com:6514 \
  -CAfile /etc/rsyslog.d/certs/logging-ca.pem \
  -cert /etc/rsyslog.d/certs/client-cert.pem \
  -key /etc/rsyslog.d/certs/client-key.pem
# Look for: Verify return code: 0 (ok)
```

## 2. Central Collector

**Port open and listening:**

```bash
ss -tlnp | grep 6514
# or: netstat -tlnp | grep 6514
# Must show rsyslogd listening
```

**rsyslog service running without errors:**

```bash
sudo systemctl status rsyslog
sudo journalctl -u rsyslog --since "5 minutes ago" --no-pager
# No "error" or "permission denied" lines
```

**Remote log directory created:**

```bash
ls /var/log/remote/
# Empty initially — subdirs appear per hostname when logs arrive
```

**Manual inject via logger to confirm central writes locally:**

```bash
logger -p auth.info "LogHawk central self-test $(date)"
grep "LogHawk central self-test" /var/log/auth.log
```

## 3. Agent Forwarding

**Verify placeholders substituted in agent config (no literal `CENTRAL_LOG_SERVER`):**

```bash
grep -E "CENTRAL_LOG_SERVER|CENTRAL_PERMITTED_PEER" /etc/rsyslog.d/99-security-forward.conf
# Must return nothing
```

**Verify TCP connection from agent to central:**

```bash
nc -zv log-server.example.com 6514
# or: telnet log-server.example.com 6514
```

**Inject a test log line on the agent and confirm it appears on central:**

```bash
# On agent:
logger -p auth.info "LogHawk agent-test from $(hostname) at $(date)"

# On central (within ~5 seconds):
grep "LogHawk agent-test" /var/log/remote/$(hostname-of-agent)/auth.log
```

**Repeat for each monitored host.** Confirm a subdirectory exists under `/var/log/remote/` for each.

## 4. Log Server Self-Forwarding

The log server runs both the central config and the agent config. Extra verification:

**Confirm no duplicate `global()` block error:**

```bash
sudo rsyslogd -N1 2>&1 | grep -i error
# Must be empty
```

**Cert file ownership (rsyslog needs group-read access):**

```bash
stat /etc/rsyslog.d/certs/*.pem | grep -E "File:|Uid:|Gid:"
# Owner root, group syslog, mode 640
```

**Self-forwarded logs appear in remote dir (log server's own hostname):**

```bash
logger -p auth.info "LogHawk self-forward test"
grep "LogHawk self-forward test" /var/log/remote/$(hostname)/auth.log
```

## 5. Pipeline Health Check

```bash
./tools/check-log-pipeline.sh --minutes 15
# All active agents: OK
# Exit code 0 = all fresh, exit code 1 = at least one STALE
```

Simulate a stale host by stopping rsyslog on an agent, waiting 20 minutes, then re-running. Should show `STALE` for that host.

## 6. watch-alerts.py

**Smoke test — inject a line matching each severity level:**

```bash
# On central server, write directly to a remote auth.log to avoid waiting for network:
echo "Apr 18 12:00:01 web-01 sshd[9999]: Failed password for root from 10.0.0.99 port 22 ssh2" \
  | sudo tee -a /var/log/remote/web-01/auth.log

# In another terminal, already running:
sudo python3 watch-alerts.py --file /var/log/remote/*/auth.log
# OR
sudo python3 watch-alerts.py --file '/var/log/remote/*/auth.log'
```

Expected output for the injected line:

- `[HIGH    ]` for `Failed password for root` (SSH failed login)
- If you inject `Accepted password for root from ...` → `[CRITICAL]`

**Brute force threshold test** — inject 5 failures from same IP within 60 seconds:

```bash
for i in $(seq 1 6); do
  echo "Apr 18 12:00:0${i} web-01 sshd[100${i}]: Failed password for invalid user admin from 198.51.100.1 port 22 ssh2" \
    | sudo tee -a /var/log/remote/web-01/auth.log
done
# Alert fires on exactly the 5th injection, not before
```

**JSON output test:**

```bash
sudo python3 tools/watch-alerts.py \
  --file /var/log/remote/web-01/auth.log \
  --json-out /tmp/test-alerts.jsonl &

# Inject a test line...
echo "Apr 19 15:22:01 db-01 sudo[4821]: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1002 euid=0 tty=/dev/pts/1 ruser=deploy rhost= user=deploy" | sudo tee -a /var/log/remote/web-01/auth.log

# Then:
jq . /tmp/test-alerts.jsonl
# OR without jq:
while IFS= read -r line; do echo "$line" | python3 -m json.tool; echo; done < /tmp/test-alerts.jsonl

# Verify: timestamp, severity, description, category, raw_line all present
```

**Log rotation test:**

```bash
# While watch-alerts.py is running, rotate the file:
sudo mv /var/log/remote/web-01/auth.log /var/log/remote/web-01/auth.log.1
sudo touch /var/log/remote/web-01/auth.log
# Then inject a line into the new file — alert must still fire
echo "Apr 18 12:05:01 web-01 sshd[2000]: Accepted password for root from 10.0.0.1 port 22 ssh2" \
  | sudo tee -a /var/log/remote/web-01/auth.log
```

## 7. search-logs.sh

**Verify each search command returns results or "None found" without error:**

```bash
./tools/search-logs.sh ssh-fails
./tools/search-logs.sh ssh-fails web-01
./tools/search-logs.sh from-ip 10.0.0.99
./tools/search-logs.sh root-logins
./tools/search-logs.sh sudo-commands
./tools/search-logs.sh new-accounts
./tools/search-logs.sh last-logins
./tools/search-logs.sh help
```

**Test host filter with a nonexistent host — must exit with error:**

```bash
./tools/search-logs.sh ssh-fails no-such-host-xyz
# Expected: "ERROR: No log found for host: no-such-host-xyz"
# Exit code: 1
```

**Test unknown command:**

```bash
./tools/search-logs.sh bogus-command
# Expected: "ERROR: Unknown command 'bogus-command'"
# Exit code: 1
```

## 8. export-for-ai.py

**Baseline export (JSON to stdout):**

```bash
sudo python3 tools/export-for-ai.py --hours 1 | python3 -m json.tool
# Verify: generated_at, hours_scanned, summary, events keys present
```

**Host filter:**

```bash
sudo python3 tools/export-for-ai.py --hours 1 --host web-01 | python3 -m json.tool
# Only events from web-01 log
```

**File output:**

```bash
sudo python3 tools/export-for-ai.py --hours 2 --out /tmp/test-export.json
ls -lh /tmp/test-export.json
python3 -m json.tool /tmp/test-export.json > /dev/null && echo "Valid JSON"
```

**LLM prompt output:**

```bash
sudo python3 tools/export-for-ai.py --hours 1 --llm-prompt | head -20
# Must start with "You are a security analyst..."
```

**No log files found — must exit non-zero with error message:**

```bash
sudo python3 tools/export-for-ai.py --log-base /tmp/nonexistent --hours 1
# Expected: "ERROR: No log files found under /tmp/nonexistent"
# Exit code: 1
```

## 9. Full End-to-End Scenario

Run this on a fresh install to confirm the entire pipeline works:

```sh
# 1. Inject known-bad lines on each agent
logger -p auth.info "Failed password for invalid user testuser from 192.0.2.1 port 22 ssh2"
logger -p auth.info "sudo: testuser : TTY=pts/0 ; COMMAND=/usr/bin/cat /etc/shadow"

# 2. Wait 10 seconds, then check central received them
sleep 10
grep "testuser" /var/log/remote/$(hostname)/auth.log

# 3. Confirm pipeline is fresh
./tools/check-log-pipeline.sh --minutes 5

# 4. Confirm search works
./tools/search-logs.sh ssh-fails

# 5. Export and verify event count > 0
sudo python3 tools/export-for-ai.py --hours 1 | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print('Events:', d['summary']['total_events'])"
```

## 10. Negative / Security Tests

| Test | Command | Expected |
|------|---------|----------|
| Agent with wrong CA cert | Replace CA on agent with a self-signed cert, restart rsyslog | Central rejects connection; agent rsyslog logs TLS error |
| Agent with no cert | Remove cert/key from agent config, restart rsyslog | Connection refused or TLS handshake failure |
| Direct TCP without TLS | `nc log-server.example.com 6514` then send raw syslog | Central ignores or rejects (StreamDriver.Mode=1 requires TLS) |
| Log base missing | `LOG_BASE=/nonexistent ./tools/check-log-pipeline.sh` | `ERROR: Log base does not exist` |
| watch-alerts.py unreadable file | `sudo python3 tools/watch-alerts.py --file /root/secret.log` (no perms) | Logs `Cannot open ...` error, does not crash |

## Quick Checklist

After any install or config change, run through this in order:

- [ ] `openssl s_client` mTLS handshake succeeds
- [ ] `ss -tlnp | grep 6514` shows rsyslogd
- [ ] `logger` on agent → file appears in `/var/log/remote/<host>/auth.log` within 5s
- [ ] `check-log-pipeline.sh` exits 0 for all active agents
- [ ] Injected `Failed password` line triggers `[HIGH]` alert in `watch-alerts.py`
- [ ] `search-logs.sh ssh-fails` returns results without error
- [ ] `export-for-ai.py --hours 1` returns valid JSON with `total_events > 0`

<br>
