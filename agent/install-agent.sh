#!/usr/bin/env bash
# install-agent.sh
# Run this on each server you want to monitor.
# Usage: sudo ./install-agent.sh <central-log-server-ip>
#
# What it does:
#   1. Installs rsyslog if missing
#   2. Drops the forwarding config
#   3. Restarts rsyslog
#   4. Verifies the connection

set -euo pipefail

CENTRAL_SERVER="${1:-}"
AGENT_CONF="/etc/rsyslog.d/99-security-forward.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Validate ──────────────────────────────────────────────────────────
if [[ -z "${CENTRAL_SERVER}" ]]; then
    echo "ERROR: Central log server IP/hostname required." >&2
    echo "Usage: sudo $0 <central-log-server>" >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Must run as root." >&2
    exit 2
fi

# ── Detect OS ─────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
    INSTALL_CMD="apt-get install -y rsyslog"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="dnf install -y rsyslog"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD="yum install -y rsyslog"
else
    echo "ERROR: No supported package manager found (apt/dnf/yum)." >&2
    exit 3
fi

echo "[1/4] Installing rsyslog if not present..."
if ! command -v rsyslogd &>/dev/null; then
    ${INSTALL_CMD}
else
    echo "      rsyslog already installed. Skipping."
fi

echo "[2/4] Writing forwarding config to ${AGENT_CONF}..."
# Replace the placeholder with the actual server address
sed "s/CENTRAL_LOG_SERVER/${CENTRAL_SERVER}/g" \
    "${SCRIPT_DIR}/rsyslog-agent.conf" > "${AGENT_CONF}"

echo "      Forwarding to: ${CENTRAL_SERVER}:514 (TCP)"

echo "[3/4] Restarting rsyslog..."
systemctl restart rsyslog
systemctl is-active --quiet rsyslog && echo "      rsyslog running." || {
    echo "ERROR: rsyslog failed to start." >&2
    journalctl -u rsyslog --no-pager -n 20 >&2
    exit 4
}

echo "[4/4] Testing TCP connection to ${CENTRAL_SERVER}:514..."
if timeout 5 bash -c ">/dev/tcp/${CENTRAL_SERVER}/514" 2>/dev/null; then
    echo "      Connection OK."
else
    echo "WARNING: Cannot reach ${CENTRAL_SERVER}:514." >&2
    echo "         Logs will queue locally and retry. Check firewall rules." >&2
fi

echo ""
echo "Done. This server now forwards logs to ${CENTRAL_SERVER}."
echo "Local auth log: /var/log/auth.log (Ubuntu) or /var/log/secure (RHEL)"
