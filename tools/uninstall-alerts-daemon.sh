#!/usr/bin/env bash
# uninstall-alerts-daemon.sh
# Remove the LogHawk alert daemon service and installed files.
#
# Usage:
#   sudo ./uninstall-alerts-daemon.sh
#   sudo ./uninstall-alerts-daemon.sh --keep-config

SERVICE_NAME="loghawk-alerts"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="/opt/loghawk"
CONF_DIR="/etc/loghawk"
KEEP_CONFIG=false

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --keep-config    Preserve /etc/loghawk/alerts.conf for future reinstalls
  -h, --help       Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-config)
            KEEP_CONFIG=true
            shift
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

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Must run as root." >&2
    exit 1
fi

echo "[1/4] Stopping service..."
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl stop "${SERVICE_NAME}"
    echo "      Stopped."
else
    echo "      Not running."
fi

echo "[2/4] Disabling service..."
if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}"
    echo "      Disabled."
else
    echo "      Not enabled."
fi

echo "[3/4] Removing service file and installed scripts..."
rm -f "${SERVICE_FILE}"
systemctl daemon-reload
rm -rf "${INSTALL_DIR}"
echo "      Removed ${SERVICE_FILE}"
echo "      Removed ${INSTALL_DIR}"

echo "[4/4] Removing configuration..."
if [[ "${KEEP_CONFIG}" == true ]]; then
    echo "      Kept ${CONF_DIR} (--keep-config)."
else
    rm -rf "${CONF_DIR}"
    echo "      Removed ${CONF_DIR}"
fi

echo ""
echo "LogHawk alert daemon uninstalled."
