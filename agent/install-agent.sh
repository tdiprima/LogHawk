#!/usr/bin/env bash
# install-agent.sh
# Run this on each server you want to monitor.
#
# Usage:
#   sudo ./install-agent.sh <central-log-server> [--server-name fqdn]
#       [--port 6514]
#       [--tls-ca /etc/rsyslog.d/certs/logging-ca.pem]
#       [--tls-cert /etc/rsyslog.d/certs/agent-cert.pem]
#       [--tls-key /etc/rsyslog.d/certs/agent-key.pem]
#
# What it does:
#   1. Installs rsyslog (+ TLS support if available)
#   2. Drops the forwarding config
#   3. Restarts rsyslog
#   4. Verifies the TCP connection

set -euo pipefail

CENTRAL_SERVER=""
SERVER_NAME=""
TLS_PORT="6514"
TLS_CA="/etc/rsyslog.d/certs/logging-ca.pem"
TLS_CERT="/etc/rsyslog.d/certs/agent-cert.pem"
TLS_KEY="/etc/rsyslog.d/certs/agent-key.pem"
AGENT_CONF="/etc/rsyslog.d/99-security-forward.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_AUTH_LOG="/var/log/auth.log"

usage() {
    cat <<EOF
Usage: sudo $0 <central-log-server> [options]

Options:
  --server-name NAME   TLS peer name to validate on the central server cert.
                       Defaults to <central-log-server>.
  --port PORT          TLS port to use (default: 6514)
  --tls-ca PATH        CA certificate path (default: ${TLS_CA})
  --tls-cert PATH      Client certificate path (default: ${TLS_CERT})
  --tls-key PATH       Client private key path (default: ${TLS_KEY})
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-name)
            SERVER_NAME="${2:-}"
            shift 2
            ;;
        --port)
            TLS_PORT="${2:-}"
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
            if [[ -z "${CENTRAL_SERVER}" ]]; then
                CENTRAL_SERVER="$1"
                shift
            else
                echo "ERROR: Unexpected argument: $1" >&2
                usage >&2
                exit 1
            fi
            ;;
    esac
done

if [[ -z "${CENTRAL_SERVER}" ]]; then
    echo "ERROR: Central log server IP/hostname required." >&2
    usage >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Must run as root." >&2
    exit 2
fi

SERVER_NAME="${SERVER_NAME:-${CENTRAL_SERVER}}"

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
    LOCAL_AUTH_LOG="/var/log/auth.log"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD=(dnf install -y rsyslog)
    TLS_PKG="rsyslog-gnutls"
    LOCAL_AUTH_LOG="/var/log/secure"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD=(yum install -y rsyslog)
    TLS_PKG="rsyslog-gnutls"
    LOCAL_AUTH_LOG="/var/log/secure"
else
    echo "ERROR: No supported package manager found (apt/dnf/yum)." >&2
    exit 3
fi

echo "[1/4] Installing rsyslog if not present..."
if ! command -v rsyslogd &>/dev/null; then
    "${INSTALL_CMD[@]}"
else
    echo "      rsyslog already installed. Skipping."
fi

echo "      Ensuring TLS driver package is available..."
install_optional_package "${TLS_PKG}"

for path in "${TLS_CA}" "${TLS_CERT}" "${TLS_KEY}"; do
    if [[ ! -f "${path}" ]]; then
        echo "ERROR: Missing TLS file: ${path}" >&2
        echo "       Provision certificates before installing the agent." >&2
        exit 4
    fi
done

echo "[2/4] Writing forwarding config to ${AGENT_CONF}..."
sed \
    -e "s|CENTRAL_LOG_SERVER|${CENTRAL_SERVER}|g" \
    -e "s|CENTRAL_PERMITTED_PEER|${SERVER_NAME}|g" \
    -e "s|TLS_PORT|${TLS_PORT}|g" \
    -e "s|TLS_CA_FILE|${TLS_CA}|g" \
    -e "s|TLS_CERT_FILE|${TLS_CERT}|g" \
    -e "s|TLS_KEY_FILE|${TLS_KEY}|g" \
    -e "s|LOCAL_AUTH_LOG|${LOCAL_AUTH_LOG}|g" \
    "${SCRIPT_DIR}/rsyslog-agent.conf" > "${AGENT_CONF}"

chmod 640 "${AGENT_CONF}"
echo "      Forwarding to: ${CENTRAL_SERVER}:${TLS_PORT} (TLS)"
echo "      Expecting server certificate name: ${SERVER_NAME}"

echo "[3/4] Restarting rsyslog..."
systemctl restart rsyslog
systemctl is-active --quiet rsyslog && echo "      rsyslog running." || {
    echo "ERROR: rsyslog failed to start." >&2
    journalctl -u rsyslog --no-pager -n 20 >&2
    exit 5
}

echo "[4/4] Testing TCP connection to ${CENTRAL_SERVER}:${TLS_PORT}..."
if timeout 5 bash -c ">/dev/tcp/${CENTRAL_SERVER}/${TLS_PORT}" 2>/dev/null; then
    echo "      TCP connection OK."
else
    echo "WARNING: Cannot reach ${CENTRAL_SERVER}:${TLS_PORT}." >&2
    echo "         Logs will queue locally and retry. Check firewall rules." >&2
fi

echo ""
echo "Done. This server now forwards logs to ${CENTRAL_SERVER} over TLS."
echo "Local auth log: ${LOCAL_AUTH_LOG}"
