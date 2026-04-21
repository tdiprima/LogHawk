#!/usr/bin/env bash
# copy-certs.sh
# Copy generated rsyslog TLS certificates to a collector or agent host.
#
# Usage:
#   ./copy-certs.sh <host> --role collector
#   ./copy-certs.sh <host> --role agent [--client-name web-01]
#
# Notes:
#   - Uses ssh/scp to copy files to the remote host.
#   - Assumes the remote user can run sudo to install files under /etc/rsyslog.d/certs.

# set -euo pipefail

HOST=""
ROLE=""
REMOTE_USER="${USER:-$(id -un)}"
REMOTE_DIR="/etc/rsyslog.d/certs"
OUT_DIR="${PWD}/central/certs"
CLIENT_NAME=""
SSH_PORT="22"
SSH_OPTS=(
    -o ConnectTimeout=10
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=3
)

usage() {
    cat <<EOF
Usage: $0 <host> --role collector|agent [options]

Options:
  --role ROLE          Required. Either 'collector' or 'agent'.
  --client-name NAME   Client certificate directory name for agent copies.
                       Defaults to <host>.
  --user USER          SSH user for the remote host (default: ${REMOTE_USER})
  --remote-dir PATH    Destination certificate directory (default: ${REMOTE_DIR})
  --out-dir PATH       Certificate output directory (default: ${OUT_DIR})
  --port PORT          SSH port (default: ${SSH_PORT})
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            ROLE="${2:-}"
            shift 2
            ;;
        --client-name)
            CLIENT_NAME="${2:-}"
            shift 2
            ;;
        --user)
            REMOTE_USER="${2:-}"
            shift 2
            ;;
        --remote-dir)
            REMOTE_DIR="${2:-}"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --port)
            SSH_PORT="${2:-}"
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
            if [[ -z "${HOST}" ]]; then
                HOST="$1"
                shift
            else
                echo "ERROR: Unexpected argument: $1" >&2
                usage >&2
                exit 1
            fi
            ;;
    esac
done

if [[ -z "${HOST}" ]]; then
    echo "ERROR: Remote host IP/DNS name is required." >&2
    usage >&2
    exit 1
fi

if [[ "${ROLE}" != "collector" && "${ROLE}" != "agent" ]]; then
    echo "ERROR: --role must be 'collector' or 'agent'." >&2
    usage >&2
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: ssh is required." >&2
    exit 2
fi

if ! command -v scp >/dev/null 2>&1; then
    echo "ERROR: scp is required." >&2
    exit 2
fi

CA_CERT="${OUT_DIR}/ca/logging-ca.pem"
declare -a SOURCE_FILES=()
declare -a DEST_FILES=()

case "${ROLE}" in
    collector)
        SOURCE_FILES=(
            "${CA_CERT}"
            "${OUT_DIR}/server/server-cert.pem"
            "${OUT_DIR}/server/server-key.pem"
        )
        DEST_FILES=(
            "logging-ca.pem"
            "server-cert.pem"
            "server-key.pem"
        )
        ;;
    agent)
        CLIENT_NAME="${CLIENT_NAME:-${HOST}}"
        SOURCE_FILES=(
            "${CA_CERT}"
            "${OUT_DIR}/clients/${CLIENT_NAME}/client-cert.pem"
            "${OUT_DIR}/clients/${CLIENT_NAME}/client-key.pem"
        )
        DEST_FILES=(
            "logging-ca.pem"
            "agent-cert.pem"
            "agent-key.pem"
        )
        ;;
esac

for path in "${SOURCE_FILES[@]}"; do
    if [[ ! -f "${path}" ]]; then
        echo "ERROR: Missing certificate file: ${path}" >&2
        exit 3
    fi
done

REMOTE="${REMOTE_USER}@${HOST}"
REMOTE_TMP="/tmp/log-hawk-certs.$$"

echo "[1/4] Creating remote staging directory on ${REMOTE}..."
ssh -p "${SSH_PORT}" "${SSH_OPTS[@]}" "${REMOTE}" "mkdir -p '${REMOTE_TMP}'"

cleanup() {
    ssh -p "${SSH_PORT}" "${SSH_OPTS[@]}" "${REMOTE}" "rm -rf '${REMOTE_TMP}'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[2/4] Copying certificate files to ${REMOTE_TMP}..."
for i in "${!SOURCE_FILES[@]}"; do
    scp -P "${SSH_PORT}" "${SSH_OPTS[@]}" "${SOURCE_FILES[$i]}" "${REMOTE}:${REMOTE_TMP}/${DEST_FILES[$i]}"
done

if [[ "${ROLE}" == "collector" ]]; then
    ROLE_INSTALLS="
        sudo install -m 644 '${REMOTE_TMP}/server-cert.pem' '${REMOTE_DIR}/server-cert.pem' &&
        sudo install -m 600 '${REMOTE_TMP}/server-key.pem' '${REMOTE_DIR}/server-key.pem'
    "
else
    ROLE_INSTALLS="
        sudo install -m 644 '${REMOTE_TMP}/agent-cert.pem' '${REMOTE_DIR}/agent-cert.pem' &&
        sudo install -m 600 '${REMOTE_TMP}/agent-key.pem' '${REMOTE_DIR}/agent-key.pem'
    "
fi

echo "[3/4] Installing files into ${REMOTE_DIR}..."
ssh -tt -p "${SSH_PORT}" "${SSH_OPTS[@]}" "${REMOTE}" "
    sudo mkdir -p '${REMOTE_DIR}' &&
    sudo chmod 700 '${REMOTE_DIR}' &&
    sudo install -m 644 '${REMOTE_TMP}/logging-ca.pem' '${REMOTE_DIR}/logging-ca.pem' &&
    ${ROLE_INSTALLS}
"

echo "[4/4] Verifying remote files..."
ssh -p "${SSH_PORT}" "${SSH_OPTS[@]}" "${REMOTE}" "ls -l '${REMOTE_DIR}'"

echo ""
echo "Installed ${ROLE} certificates on ${REMOTE}:${REMOTE_DIR}"
if [[ "${ROLE}" == "agent" ]]; then
    echo "Client certificate source: ${OUT_DIR}/clients/${CLIENT_NAME}/"
fi
