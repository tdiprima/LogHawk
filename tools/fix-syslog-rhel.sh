#!/usr/bin/env bash
# fix-syslog-rhel.sh
# Ensures rsyslog is installed, running, and /dev/log socket exists on RHEL.
# Run this before logger or install-central.sh if logger fails with
# "socket /dev/log: No such file or directory".
#
# Usage:
#   sudo ./fix-syslog-rhel.sh [--dry-run]

DRY_RUN=0

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --dry-run   Show what would be done without making changes
  -h, --help  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
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

run_cmd() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "  [dry-run] $*"
    else
        "$@"
    fi
}

detect_pkg_manager() {
    if command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo ""
    fi
}

PKG_MGR="$(detect_pkg_manager)"
if [[ -z "${PKG_MGR}" ]]; then
    echo "ERROR: Neither dnf nor yum found. Is this RHEL?" >&2
    exit 2
fi

echo "[1/4] Checking rsyslog installation..."
if ! rpm -q rsyslog &>/dev/null; then
    echo "      rsyslog not installed. Installing..."
    run_cmd "${PKG_MGR}" install -y rsyslog
else
    echo "      rsyslog already installed: $(rpm -q rsyslog)"
fi

echo "[2/4] Enabling rsyslog service..."
run_cmd systemctl enable rsyslog

echo "[3/4] Starting rsyslog..."
if systemctl is-active --quiet rsyslog; then
    echo "      Already running."
else
    run_cmd systemctl start rsyslog
fi

echo "[4/4] Verifying..."

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  [dry-run] Would verify /dev/log socket and run logger self-test."
    exit 0
fi

if [[ -S /dev/log ]]; then
    echo "      /dev/log socket exists."
else
    echo "ERROR: /dev/log still missing after starting rsyslog." >&2
    echo "       Checking journal for errors:" >&2
    journalctl -u rsyslog --no-pager -n 15 >&2
    exit 3
fi

if systemctl is-active --quiet rsyslog; then
    echo "      rsyslog service active."
else
    echo "ERROR: rsyslog not running." >&2
    journalctl -u rsyslog --no-pager -n 15 >&2
    exit 4
fi

echo ""
echo "Running self-test..."
logger -p auth.info "LogHawk central self-test $(date)"
if [[ $? -eq 0 ]]; then
    echo "Self-test passed. logger working."
else
    echo "ERROR: logger command failed." >&2
    exit 5
fi

# logger -p auth.info "LogHawk central self-test $(date)"                                                  
# logger: socket /dev/log: No such file or directory
# ln -s /run/systemd/journal/dev-log /dev/log
