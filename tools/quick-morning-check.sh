#!/usr/bin/env bash
# quick-morning-check.sh — run daily on each server

echo "=== WHO IS LOGGED IN ==="
w

echo ""
echo "=== LAST 10 LOGINS ==="
last -n 10

echo ""
echo "=== FAILED SSH (last 24h, top IPs) ==="
grep "Failed password" /var/log/auth.log \
  | grep -oP "from \K[\d.]+" \
  | sort | uniq -c | sort -rn | head -10
# On RHEL-family systems, use /var/log/secure instead.

echo ""
echo "=== SUCCESSFUL LOGINS TODAY ==="
grep "Accepted" /var/log/auth.log | grep "$(date '+%b %e')"
# On RHEL-family systems, use /var/log/secure instead.

echo ""
echo "=== SUDO COMMANDS TODAY ==="
grep "sudo:.*COMMAND=" /var/log/auth.log | grep "$(date '+%b %e')"
# On RHEL-family systems, use /var/log/secure instead.

echo ""
echo "=== NEW LISTENING PORTS ==="
ss -tlnp

echo ""
echo "=== FILES CREATED IN /tmp /var/tmp (last 24h) ==="
find /tmp /var/tmp -newer /proc/1 -type f 2>/dev/null
