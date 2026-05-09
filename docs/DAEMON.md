`watch-alerts.py` must run continuously — it tails log files and emails CRITICAL/HIGH alerts via
 local SMTP. Needed daemon to survive reboots.

## Created:

**File:** `loghawk-alerts.service`  
**Purpose:** Systemd unit — restarts on failure, starts after rsyslog, hardened with `ProtectSystem=strict`

**File:**` install-alerts-daemon.sh`  
**Purpose:** Copies scripts to `/opt/loghawk`, writes config to `/etc/loghawk/alerts.conf`, enables+starts service

**File:** `uninstall-alerts-daemon.sh`  
**Purpose:** Stops, disables, removes everything. `--keep-config` option to preserve config

## Usage:

## Install

```sh
sudo ./tools/install-alerts-daemon.sh --email admin@example.com
```

### Install with remote logs + JSON output
```sh
sudo ./tools/install-alerts-daemon.sh \
--email admin@example.com \
--file '/var/log/remote/*/*.log' \
--json-out /var/log/loghawk-alerts.jsonl
```

### Check status
```sh
systemctl status loghawk-alerts
journalctl -u loghawk-alerts -f
```

### Reconfigure — edit /etc/loghawk/alerts.conf, then:

```sh
systemctl restart loghawk-alerts
```

## Uninstall
```sh
sudo ./tools/uninstall-alerts-daemon.sh
```

**Prereq reminder:** Local MTA (postfix/sendmail) must be running on localhost:25 for email delivery to work.

<br>
