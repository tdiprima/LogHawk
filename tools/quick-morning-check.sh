#!/usr/bin/env bash
# quick-morning-check.sh — run daily on each server

echo "=== WHO IS LOGGED IN ==="
w

echo ""
echo "=== LAST 10 LOGINS ==="
last -n 10

echo ""
echo "=== FAILED SSH (last 24h, top IPs) ==="
if [[ -s /var/log/auth.log ]]; then
  grep "Failed password" /var/log/auth.log \
    | grep -oP "from \K[\d.]+" \
    | sort | uniq -c | sort -rn | head -10
elif [[ -s /var/log/secure ]]; then
  grep "Failed password" /var/log/secure \
    | grep -oP "from \K[\d.]+" \
    | sort | uniq -c | sort -rn | head -10
else
  journalctl -u sshd -u ssh --since today | grep "Failed password" \
    | grep -oP "from \K[\d.]+" \
    | sort | uniq -c | sort -rn | head -10
fi

echo ""
echo "=== SUCCESSFUL LOGINS TODAY ==="
if [[ -s /var/log/auth.log ]]; then
  grep "Accepted" /var/log/auth.log | grep "$(date '+%b %e')"
elif [[ -s /var/log/secure ]]; then
  grep "Accepted" /var/log/secure | grep "$(date '+%b %e')"
else
  journalctl -u sshd -u ssh --since today | grep "Accepted"
fi

echo ""
echo "=== SUDO COMMANDS TODAY ==="
if [[ -s /var/log/auth.log ]]; then
  grep "sudo:.*COMMAND=" /var/log/auth.log | grep "$(date '+%b %e')"
elif [[ -s /var/log/secure ]]; then
  grep "sudo:.*COMMAND=" /var/log/secure | grep "$(date '+%b %e')"
else
  journalctl --since today | grep "sudo:.*COMMAND="
fi

echo ""
echo "=== OOM KILLS (last 24h) ==="
if [[ -s /var/log/kern.log ]]; then
  grep -E "Out of memory|Killed process" /var/log/kern.log | grep "$(date '+%b %e')" || echo "  (none)"
elif [[ -s /var/log/messages ]]; then
  grep -E "Out of memory|Killed process" /var/log/messages | grep "$(date '+%b %e')" || echo "  (none)"
fi

echo ""
echo "=== DISK / FS ERRORS (last 24h) ==="
if [[ -s /var/log/kern.log ]]; then
  grep -E "I/O error|EXT4-fs error|XFS.*error" /var/log/kern.log | grep "$(date '+%b %e')" || echo "  (none)"
fi

echo ""
echo "=== SERVICE FAILURES TODAY ==="
if [[ -s /var/log/syslog ]]; then
  grep -E "Failed with result|failed to start" /var/log/syslog | grep "$(date '+%b %e')" || echo "  (none)"
elif [[ -s /var/log/messages ]]; then
  grep -E "Failed with result|failed to start" /var/log/messages | grep "$(date '+%b %e')" || echo "  (none)"
fi

echo ""
echo "=== CRONTAB CHANGES TODAY ==="
if [[ -s /var/log/cron.log ]]; then
  grep -E "REPLACE|BEGIN EDIT|END EDIT" /var/log/cron.log | grep "$(date '+%b %e')" || echo "  (none)"
elif [[ -s /var/log/cron ]]; then
  grep -E "REPLACE|BEGIN EDIT|END EDIT" /var/log/cron | grep "$(date '+%b %e')" || echo "  (none)"
fi

echo ""
echo "=== NEW LISTENING PORTS ==="
ss -tlnp

echo ""
echo "=== FILES CREATED IN /tmp /var/tmp (last 24h) ==="
find /tmp /var/tmp -newer /proc/1 -type f 2>/dev/null
