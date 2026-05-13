#!/usr/bin/env bash
# check-log-pipeline.sh
# Reports remote hosts whose logs have gone stale on the central collector.
#
# Per-host expected logs:
#   Drop a .expected-logs file in a host's log directory to declare which
#   log files that host should produce (one filename per line).
#   Hosts without .expected-logs are checked against whatever files actually
#   exist — no MISS noise for logs the host never produced.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=loghawk-config.sh
source "${SCRIPT_DIR}/loghawk-config.sh" || exit 1

LOG_BASE="${LOG_BASE:-/var/log/remote}"
STALE_MINUTES="${STALE_MINUTES:-15}"

if [[ -n "${_LOGHAWK_EXPECTED_LOGS_CSV:-}" ]]; then
    IFS=',' read -ra EXPECTED_LOGS <<< "${_LOGHAWK_EXPECTED_LOGS_CSV}"
else
    EXPECTED_LOGS=(auth.log kern.log cron.log audit.log syslog.log)
fi

usage() {
    cat <<EOF
Usage: $0 [--minutes N] [--log-base PATH]

Options:
  --minutes N     Mark a host stale if any log is older than N minutes (default: ${STALE_MINUTES})
  --log-base PATH Remote log base directory (default: ${LOG_BASE})
  -h, --help      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --minutes)
            STALE_MINUTES="${2:-}"
            shift 2
            ;;
        --log-base)
            LOG_BASE="${2:-}"
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

if [[ ! -d "${LOG_BASE}" ]]; then
    echo "ERROR: Log base does not exist: ${LOG_BASE}" >&2
    exit 1
fi

resolve_host_logs() {
    # Determine which log files to check for a given host directory.
    #   1. .expected-logs file present → use it (strict: MISS if listed file absent)
    #   2. No .expected-logs → check only files that actually exist (no false MISS)
    local host_dir="$1"
    local manifest="${host_dir}.expected-logs"

    if [[ -f "${manifest}" ]]; then
        # Strict mode: operator declared what this host should produce.
        grep -v '^\s*#' "${manifest}" | grep -v '^\s*$'
        echo "__strict__"
        return
    fi

    # Auto-discover: only check log files that exist.
    for candidate in "${EXPECTED_LOGS[@]}"; do
        [[ -f "${host_dir}${candidate}" ]] && echo "${candidate}"
    done
}

now_epoch="$(date +%s)"
stale_found=0

for host_dir in "${LOG_BASE}"/*/; do
    [[ -d "${host_dir}" ]] || continue
    host="$(basename "${host_dir}")"

    mapfile -t host_logs < <(resolve_host_logs "${host_dir}")

    # Check if strict mode (last element is sentinel)
    strict="false"
    if [[ "${host_logs[*]:(-1)}" == "__strict__" ]]; then
        strict="true"
        unset 'host_logs[-1]'
    fi

    if [[ ${#host_logs[@]} -eq 0 ]]; then
        printf 'EMPTY  %-25s  %-12s  %s\n' "${host}" "-" "(no log files found)"
        stale_found=1
        continue
    fi

    for log_name in "${host_logs[@]}"; do
        log_file="${host_dir}${log_name}"

        if [[ ! -f "${log_file}" ]]; then
            if [[ "${strict}" == "true" ]]; then
                printf 'MISS   %-25s  %-12s  %s\n' "${host}" "${log_name}" "(expected by .expected-logs)"
                stale_found=1
            fi
            continue
        fi

        file_epoch="$(stat -c %Y "${log_file}")"
        age_minutes="$(( (now_epoch - file_epoch) / 60 ))"

        if (( age_minutes > STALE_MINUTES )); then
            printf 'STALE  %-25s  %-12s  %4sm  %s\n' "${host}" "${log_name}" "${age_minutes}" "${log_file}"
            stale_found=1
        else
            printf 'OK     %-25s  %-12s  %4sm  %s\n' "${host}" "${log_name}" "${age_minutes}" "${log_file}"
        fi
    done
done

exit "${stale_found}"
