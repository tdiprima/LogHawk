#!/usr/bin/env bash
# install-alerts-daemon.sh
# Install watch-alerts.py as a systemd service that survives reboots.
#
# Usage:
#   sudo ./install-alerts-daemon.sh --email admin@example.com
#   sudo ./install-alerts-daemon.sh --email admin@example.com --file '/var/log/remote/*/*.log'
#   sudo ./install-alerts-daemon.sh --email admin@example.com --min-severity HIGH
#   sudo ./install-alerts-daemon.sh --email admin@example.com --json-out /var/log/loghawk-alerts.jsonl

INSTALL_DIR="/opt/loghawk"
CONF_DIR="/etc/loghawk"
CONF_FILE="${CONF_DIR}/alerts.conf"
SERVICE_NAME="loghawk-alerts"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EMAIL=""
LOG_FILES=""
MIN_SEVERITY=""
JSON_OUT=""

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --email ADDRESS        Email address for CRITICAL/HIGH alerts (required)
  --file PATTERN         Log file(s) to watch (supports globs, quote them)
                         Default: all local security logs
  --min-severity LEVEL   Minimum severity: INFO|LOW|MEDIUM|HIGH|CRITICAL
                         Default: INFO
  --json-out PATH        Write JSON alert records to this file
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --email)
            EMAIL="${2:-}"
            shift 2
            ;;
        --file)
            LOG_FILES="${2:-}"
            shift 2
            ;;
        --min-severity)
            MIN_SEVERITY="${2:-}"
            shift 2
            ;;
        --json-out)
            JSON_OUT="${2:-}"
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

if [[ -z "${EMAIL}" ]]; then
    echo "ERROR: --email is required." >&2
    usage >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.9+." >&2
    exit 2
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="${PYTHON_VERSION%%.*}"
PYTHON_MINOR="${PYTHON_VERSION##*.}"
if [[ "${PYTHON_MAJOR}" -lt 3 ]] || { [[ "${PYTHON_MAJOR}" -eq 3 ]] && [[ "${PYTHON_MINOR}" -lt 9 ]]; }; then
    echo "ERROR: Python 3.9+ required. Found ${PYTHON_VERSION}." >&2
    exit 2
fi

if ! command -v systemctl &>/dev/null; then
    echo "ERROR: systemd not found. This installer requires systemd." >&2
    exit 3
fi

# ── Build WATCH_ALERTS_OPTS ──────────────────────────────────────────
build_opts() {
    local opts="--email ${EMAIL}"

    if [[ -n "${LOG_FILES}" ]]; then
        opts="${opts} --file ${LOG_FILES}"
    fi

    if [[ -n "${MIN_SEVERITY}" ]]; then
        opts="${opts} --min-severity ${MIN_SEVERITY}"
    fi

    if [[ -n "${JSON_OUT}" ]]; then
        opts="${opts} --json-out ${JSON_OUT}"
    fi

    echo "${opts}"
}

# ── Install ──────────────────────────────────────────────────────────

echo "[1/5] Copying watch-alerts to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/watch-alerts.py" "${INSTALL_DIR}/watch-alerts.py"
cp "${SCRIPT_DIR}/alert_patterns.py" "${INSTALL_DIR}/alert_patterns.py"
cp "${SCRIPT_DIR}/loghawk_config.py" "${INSTALL_DIR}/loghawk_config.py"
chmod 755 "${INSTALL_DIR}/watch-alerts.py"
chmod 644 "${INSTALL_DIR}/alert_patterns.py"
chmod 644 "${INSTALL_DIR}/loghawk_config.py"

if [[ ! -f "${CONF_DIR}/loghawk.conf" ]]; then
    echo "      Installing default loghawk.conf..."
    cp "${SCRIPT_DIR}/loghawk.conf.example" "${CONF_DIR}/loghawk.conf"
    chmod 644 "${CONF_DIR}/loghawk.conf"
fi

echo "[2/5] Writing configuration to ${CONF_FILE}..."
mkdir -p "${CONF_DIR}"
WATCH_ALERTS_OPTS="$(build_opts)"
cat > "${CONF_FILE}" <<EOF
# LogHawk alert daemon configuration
# Edit this file, then run: systemctl restart ${SERVICE_NAME}
WATCH_ALERTS_OPTS=${WATCH_ALERTS_OPTS}
EOF
chmod 600 "${CONF_FILE}"

echo "[3/5] Installing systemd service..."
cp "${SCRIPT_DIR}/loghawk-alerts.service" "${SERVICE_FILE}"
systemctl daemon-reload

echo "[4/5] Enabling service to start on boot..."
systemctl enable "${SERVICE_NAME}"

echo "[5/5] Starting service..."
systemctl start "${SERVICE_NAME}"

systemctl is-active --quiet "${SERVICE_NAME}" && echo "      ${SERVICE_NAME} running." || {
    echo "ERROR: ${SERVICE_NAME} failed to start." >&2
    journalctl -u "${SERVICE_NAME}" --no-pager -n 20 >&2
    exit 4
}

echo ""
echo "LogHawk alert daemon installed."
echo "  Service:  systemctl status ${SERVICE_NAME}"
echo "  Logs:     journalctl -u ${SERVICE_NAME} -f"
echo "  Config:   ${CONF_FILE}"
echo "  Alerts:   ${EMAIL}"
