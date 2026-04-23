#!/usr/bin/env bash
# check-log-pipeline.sh
# Reports remote hosts whose logs have gone stale on the central collector.
# Checks all expected log files: auth, kern, cron, audit, syslog.

LOG_BASE="${LOG_BASE:-/var/log/remote}"
STALE_MINUTES="${STALE_MINUTES:-15}"
EXPECTED_LOGS=(auth.log kern.log cron.log audit.log syslog.log)

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

now_epoch="$(date +%s)"
stale_found=0

for host_dir in "${LOG_BASE}"/*/; do
    [[ -d "${host_dir}" ]] || continue
    host="$(basename "${host_dir}")"

    for log_name in "${EXPECTED_LOGS[@]}"; do
        log_file="${host_dir}${log_name}"

        if [[ ! -f "${log_file}" ]]; then
            printf 'MISS   %-25s  %-12s  %s\n' "${host}" "${log_name}" "(not found)"
            stale_found=1
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
