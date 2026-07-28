#!/usr/bin/env bash
# install-dashboard.sh
# Installs the LogHawk Dashboard as a systemd service on the central log server.
#
# The dashboard serves a web UI on the specified port. Point a browser at
# http://<server>:<port> from any machine on the network.
#
# Usage:
#   sudo ./install-dashboard.sh
#   sudo ./install-dashboard.sh --port 9090
#   sudo ./install-dashboard.sh --port 8080 --bind 10.0.0.10
#   sudo ./install-dashboard.sh --jsonl /var/log/loghawk-alerts.jsonl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_DIR="/opt/loghawk"
SERVICE_NAME="loghawk-dashboard"
PORT="8080"
BIND="0.0.0.0"
JSONL_PATH=""

# ── Argument parsing ─────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --port PORT        Listen port (default: ${PORT})
  --bind ADDRESS     Bind address (default: ${BIND})
  --jsonl PATH       Path to JSONL alert file from watch-alerts daemon
  --install-dir DIR  Installation directory (default: ${INSTALL_DIR})
  -h, --help         Show this help

The dashboard needs read access to log files under the configured log_base
(default /var/log/remote). It runs as root by default.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            PORT="${2:?--port requires a value}"
            shift 2
            ;;
        --bind)
            BIND="${2:?--bind requires a value}"
            shift 2
            ;;
        --jsonl)
            JSONL_PATH="${2:?--jsonl requires a value}"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="${2:?--install-dir requires a value}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# ── Preflight checks ────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: Run as root (sudo)." >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found." >&2
    exit 1
fi

python_version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
required="3.9"
if [[ "$(printf '%s\n' "${required}" "${python_version}" | sort -V | head -n1)" != "${required}" ]]; then
    echo "ERROR: Python ${required}+ required, found ${python_version}." >&2
    exit 1
fi

# ── Install files ────────────────────────────────────────────────────
echo "Installing LogHawk Dashboard to ${INSTALL_DIR} ..."

mkdir -p "${INSTALL_DIR}/dashboard/static"
mkdir -p "${INSTALL_DIR}/tools"

cp "${SCRIPT_DIR}/server.py"            "${INSTALL_DIR}/dashboard/server.py"
cp "${SCRIPT_DIR}/static/index.html"    "${INSTALL_DIR}/dashboard/static/index.html"

# Copy shared tools if not already present
for tool_file in alert_patterns.py loghawk_config.py; do
    src="${PROJECT_ROOT}/tools/${tool_file}"
    dest="${INSTALL_DIR}/tools/${tool_file}"
    if [[ -f "${src}" ]]; then
        cp "${src}" "${dest}"
    elif [[ ! -f "${dest}" ]]; then
        echo "WARNING: ${tool_file} not found at ${src} or ${dest}." >&2
        echo "  The dashboard needs alert_patterns.py and loghawk_config.py from tools/." >&2
    fi
done

# ── Build ExecStart command ──────────────────────────────────────────
exec_start="/usr/bin/python3 ${INSTALL_DIR}/dashboard/server.py --port ${PORT} --bind ${BIND}"
if [[ -n "${JSONL_PATH}" ]]; then
    exec_start="${exec_start} --jsonl ${JSONL_PATH}"
fi

# ── Create systemd service ───────────────────────────────────────────
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=LogHawk Dashboard — fleet log monitoring
After=network.target rsyslog.service
Wants=rsyslog.service

[Service]
Type=simple
ExecStart=${exec_start}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

echo ""
echo "LogHawk Dashboard installed."
echo "  URL:     http://${BIND}:${PORT}"
echo "  Service: systemctl status ${SERVICE_NAME}"
echo "  Logs:    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "Open the URL in a browser from any machine on the network."
