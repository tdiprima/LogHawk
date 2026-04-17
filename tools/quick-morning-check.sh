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
echo "=== NEW LISTENING PORTS ==="
ss -tlnp

echo ""
echo "=== FILES CREATED IN /tmp /var/tmp (last 24h) ==="
find /tmp /var/tmp -newer /proc/1 -type f 2>/dev/null
