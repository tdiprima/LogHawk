#!/usr/bin/env bash
# install-central.sh
# Run this on the server that will RECEIVE logs from all other servers.
#
# Usage:
#   sudo ./install-central.sh
#       [--port 6514]
#       [--allow-from 10.0.0.0/24]
#       [--tls-ca /etc/rsyslog.d/certs/logging-ca.pem]
#       [--tls-cert /etc/rsyslog.d/certs/server-cert.pem]
#       [--tls-key /etc/rsyslog.d/certs/server-key.pem]
#       [--retention-days 90]
#
# What it does:
#   1. Installs rsyslog (+ TLS support if available)
#   2. Creates /var/log/remote/ storage directory
#   3. Drops the TLS receiver config
#   4. Optionally opens the firewall on the TLS port
#   5. Sets up log rotation
#   6. Restarts rsyslog

set -euo pipefail

TLS_PORT="6514"
ALLOW_FROM=""
TLS_CA="/etc/rsyslog.d/certs/logging-ca.pem"
TLS_CERT="/etc/rsyslog.d/certs/server-cert.pem"
TLS_KEY="/etc/rsyslog.d/certs/server-key.pem"
RETENTION_DAYS="90"
CENTRAL_CONF="/etc/rsyslog.d/10-security-central.conf"
LOG_DIR="/var/log/remote"
LOGROTATE_CONF="/etc/logrotate.d/remote-security-logs"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --port PORT          TLS listen port (default: ${TLS_PORT})
  --allow-from CIDR    Restrict the firewall rule to a source subnet/IP.
  --tls-ca PATH        CA certificate path (default: ${TLS_CA})
  --tls-cert PATH      Server certificate path (default: ${TLS_CERT})
  --tls-key PATH       Server private key path (default: ${TLS_KEY})
  --retention-days N   Log rotation retention in days (default: ${RETENTION_DAYS})
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            TLS_PORT="${2:-}"
            shift 2
            ;;
        --allow-from)
            ALLOW_FROM="${2:-}"
            shift 2
            ;;
        --tls-ca)
            TLS_CA="${2:-}"
            shift 2
            ;;
        --tls-cert)
            TLS_CERT="${2:-}"
            shift 2
            ;;
        --tls-key)
            TLS_KEY="${2:-}"
            shift 2
            ;;
        --retention-days)
            RETENTION_DAYS="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            echo "ERROR: Unexpected argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# ── Validate ──────────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Must run as root." >&2
    exit 1
fi

install_optional_package() {
    local pkg="$1"

    case "${PKG_MANAGER}" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" >/dev/null 2>&1 || true
            ;;
        dnf|yum)
            "${PKG_MANAGER}" install -y "${pkg}" >/dev/null 2>&1 || true
            ;;
    esac
}

# ── Detect OS ─────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
    INSTALL_CMD=(apt-get install -y rsyslog)
    TLS_PKG="rsyslog-gnutls"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD=(dnf install -y rsyslog)
    TLS_PKG="rsyslog-gnutls"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD=(yum install -y rsyslog)
    TLS_PKG="rsyslog-gnutls"
else
    echo "ERROR: No supported package manager found." >&2
    exit 2
fi

echo "[1/5] Installing rsyslog..."
if ! command -v rsyslogd &>/dev/null; then
    "${INSTALL_CMD[@]}"
else
    echo "      Already installed."
fi

echo "      Ensuring TLS driver package is available..."
install_optional_package "${TLS_PKG}"

for path in "${TLS_CA}" "${TLS_CERT}" "${TLS_KEY}"; do
    if [[ ! -f "${path}" ]]; then
        echo "ERROR: Missing TLS file: ${path}" >&2
        echo "       Provision certificates before installing the collector." >&2
        exit 3
    fi
done

echo "[2/5] Creating log storage at ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"
chown -R syslog:adm "${LOG_DIR}" 2>/dev/null || chown -R root:root "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

echo "[3/5] Writing central receiver config..."
sed \
    -e "s|TLS_PORT|${TLS_PORT}|g" \
    -e "s|TLS_CA_FILE|${TLS_CA}|g" \
    -e "s|TLS_CERT_FILE|${TLS_CERT}|g" \
    -e "s|TLS_KEY_FILE|${TLS_KEY}|g" \
    "${SCRIPT_DIR}/rsyslog-central.conf" > "${CENTRAL_CONF}"

chmod 640 "${CENTRAL_CONF}"

echo "[4/5] Setting up log rotation (${RETENTION_DAYS} days, compressed)..."
cat > "${LOGROTATE_CONF}" <<EOF
/var/log/remote/*/*.log {
    daily
    rotate ${RETENTION_DAYS}
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

echo "[5/5] Configuring firewall for TCP ${TLS_PORT}..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    if [[ -n "${ALLOW_FROM}" ]]; then
        ufw allow from "${ALLOW_FROM}" to any port "${TLS_PORT}" proto tcp
        echo "      Allowed source ${ALLOW_FROM}."
    else
        ufw allow "${TLS_PORT}/tcp"
        echo "      WARNING: Opened ${TLS_PORT}/tcp to any source. Prefer --allow-from." >&2
    fi
elif command -v firewall-cmd &>/dev/null; then
    if [[ -n "${ALLOW_FROM}" ]]; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='${ALLOW_FROM}' port protocol='tcp' port='${TLS_PORT}' accept"
        echo "      Allowed source ${ALLOW_FROM}."
    else
        firewall-cmd --permanent --add-port="${TLS_PORT}/tcp"
        echo "      WARNING: Opened ${TLS_PORT}/tcp to any source. Prefer --allow-from." >&2
    fi
    firewall-cmd --reload
else
    echo "WARNING: No active firewall detected. Manually allow TCP port ${TLS_PORT} if needed." >&2
fi

systemctl restart rsyslog
systemctl is-active --quiet rsyslog && echo "      rsyslog running." || {
    echo "ERROR: rsyslog failed to start." >&2
    journalctl -u rsyslog --no-pager -n 20 >&2
    exit 4
}

echo ""
echo "Central log server ready."
echo "Logs will appear in: ${LOG_DIR}/<hostname>/"
echo "Listening for TLS syslog on TCP ${TLS_PORT}."
