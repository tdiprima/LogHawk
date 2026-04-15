#!/usr/bin/env bash
# install-central.sh
# Run this on the server that will RECEIVE logs from all other servers.
# Usage: sudo ./install-central.sh
#
# What it does:
#   1. Installs rsyslog
#   2. Creates /var/log/remote/ storage directory
#   3. Drops the receiver config
#   4. Opens port 514/tcp in the firewall
#   5. Sets up log rotation
#   6. Restarts rsyslog

set -euo pipefail

CENTRAL_CONF="/etc/rsyslog.d/10-security-central.conf"
LOG_DIR="/var/log/remote"
LOGROTATE_CONF="/etc/logrotate.d/remote-security-logs"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Validate ──────────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Must run as root." >&2
    exit 1
fi

# ── Detect OS ─────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    INSTALL_CMD="apt-get install -y rsyslog"
    FIREWALL_CMD="ufw allow 514/tcp"
elif command -v dnf &>/dev/null; then
    INSTALL_CMD="dnf install -y rsyslog"
    FIREWALL_CMD="firewall-cmd --permanent --add-port=514/tcp && firewall-cmd --reload"
elif command -v yum &>/dev/null; then
    INSTALL_CMD="yum install -y rsyslog"
    FIREWALL_CMD="firewall-cmd --permanent --add-port=514/tcp && firewall-cmd --reload"
else
    echo "ERROR: No supported package manager found." >&2
    exit 2
fi

echo "[1/5] Installing rsyslog..."
if ! command -v rsyslogd &>/dev/null; then
    ${INSTALL_CMD}
else
    echo "      Already installed."
fi

echo "[2/5] Creating log storage at ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"
# rsyslog needs to be able to write here
chown -R syslog:adm "${LOG_DIR}" 2>/dev/null || chown -R root:root "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

echo "[3/5] Writing central receiver config..."
cp "${SCRIPT_DIR}/rsyslog-central.conf" "${CENTRAL_CONF}"

echo "[4/5] Setting up log rotation (30 days, compressed)..."
cat > "${LOGROTATE_CONF}" <<'EOF'
/var/log/remote/*/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

echo "[5/5] Opening firewall port 514/tcp..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 514/tcp
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=514/tcp
    firewall-cmd --reload
else
    echo "WARNING: No active firewall detected. Manually allow TCP port 514 if needed." >&2
fi

systemctl restart rsyslog
systemctl is-active --quiet rsyslog && echo "      rsyslog running." || {
    echo "ERROR: rsyslog failed to start." >&2
    journalctl -u rsyslog --no-pager -n 20 >&2
    exit 3
}

echo ""
echo "Central log server ready."
echo "Logs will appear in: ${LOG_DIR}/<hostname>/"
echo ""
echo "Next step: run install-agent.sh on each server you want to monitor."
echo "  sudo ./agent/install-agent.sh $(hostname -I | awk '{print $1}')"
