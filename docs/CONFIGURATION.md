# Configuration

LogHawk reads tunable values from a single INI config file shared by all tools.

## Config file location

| Priority | Source |
|---|---|
| 1 | `--config PATH` flag (Python tools only) |
| 2 | `LOGHAWK_CONFIG` environment variable |
| 3 | `/etc/loghawk/loghawk.conf` |
| 4 | Built-in defaults (no file needed) |

If a path is given explicitly (via flag or env var) and the file is missing, tools exit with an error.
If the default path doesn't exist, tools run with built-in defaults — no error.

## Setting precedence

Within each tool, values are resolved in this order (highest wins):

```
CLI flags  >  environment variables  >  config file  >  built-in defaults
```

For example, `--dedup-window 7200` on the command line overrides whatever `dedup_window_seconds` is set to in the config file.

## Installing the config file

The daemon installer creates a default config automatically on first install:

```bash
sudo ./tools/install-alerts-daemon.sh --email admin@example.com
# creates /etc/loghawk/loghawk.conf if it doesn't exist
```

To install manually:

```bash
sudo mkdir -p /etc/loghawk
sudo cp tools/loghawk.conf.example /etc/loghawk/loghawk.conf
sudo chmod 644 /etc/loghawk/loghawk.conf
```

After editing, restart the daemon to pick up changes:

```bash
sudo systemctl restart loghawk-alerts
```

## Config file reference

```ini
[paths]
# Base directory for centralized remote host logs.
# Each host gets a subdirectory: <log_base>/<hostname>/*.log
log_base = /var/log/remote

[alerting]
# Brute force detection: alert fires when the same IP fails >= threshold
# times within the window.
brute_force_window_seconds = 60
brute_force_threshold = 3

# Suppress duplicate non-critical alerts within this window (seconds).
# CRITICAL and HIGH alerts always fire immediately.
dedup_window_seconds = 14400

# Severity levels that trigger email notifications (comma-separated).
# Valid: CRITICAL, HIGH, MEDIUM, LOW, INFO
email_severities = CRITICAL,HIGH

[pipeline]
# check-log-pipeline.sh marks a host stale when any expected log file
# has not been written within this many minutes.
stale_minutes = 15

# Expected log files per host (comma-separated).
# Used as the default set; per-host overrides are possible (see below).
expected_logs = auth.log,kern.log,cron.log,audit.log,syslog.log
```

## Which tools read what

| Config key | watch-alerts.py | export-for-ai.py | search-logs.sh | check-log-pipeline.sh |
|---|---|---|---|---|
| `log_base` | | X | X | X |
| `brute_force_window_seconds` | X | | | |
| `brute_force_threshold` | X | | | |
| `dedup_window_seconds` | X | | | |
| `email_severities` | X | | | |
| `stale_minutes` | | | | X |
| `expected_logs` | | | | X |

## Per-host expected logs

By default, `check-log-pipeline.sh` only checks log files that already exist for each host — no false MISS alerts for logs the host never produced.

To enable strict checking for a specific host, create a `.expected-logs` file in that host's log directory listing one filename per line:

```bash
cat > /var/log/remote/web-01/.expected-logs <<EOF
auth.log
kern.log
syslog.log
EOF
```

With this file present, the pipeline check reports MISS if any listed file is absent. Comments (`#`) and blank lines are ignored.

### Behavior summary

| `.expected-logs` present? | File status | Result |
|---|---|---|
| No | Exists and fresh | OK |
| No | Exists and stale | STALE |
| No | Never existed | Skipped (no noise) |
| No | All files gone | EMPTY |
| Yes | Listed and fresh | OK |
| Yes | Listed and stale | STALE |
| Yes | Listed but missing | MISS |

## Error handling

The config loader fails loudly and exits when:

- An explicit path (flag or `LOGHAWK_CONFIG`) points to a nonexistent file
- The file exists but is unreadable (wrong permissions)
- The file is malformed (bad INI syntax)
- A value is invalid (negative integer, unknown severity name, empty required field)

Example error output:

```
ERROR: Invalid value for alerting.brute_force_threshold: -5 (must be positive)
```

## Environment variable overrides

Bash tools honor these env vars (set before running the tool):

| Variable | Overrides |
|---|---|
| `LOG_BASE` | `[paths] log_base` |
| `STALE_MINUTES` | `[pipeline] stale_minutes` |
| `LOGHAWK_CONFIG` | Config file path |

```bash
LOG_BASE=/var/log/custom ./tools/search-logs.sh ssh-fails
```

Python tools use `--config` and tool-specific flags (`--log-base`, `--dedup-window`) for overrides.
