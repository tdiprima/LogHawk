#!/usr/bin/env bash
# check-log-pipeline.sh
# Reports remote hosts whose auth log has gone stale on the central collector.

set -euo pipefail

LOG_BASE="${LOG_BASE:-/var/log/remote}"
STALE_MINUTES="${STALE_MINUTES:-15}"

usage() {
    cat <<EOF
Usage: $0 [--minutes N] [--log-base PATH]

Options:
  --minutes N     Mark a host stale if auth.log is older than N minutes (default: ${STALE_MINUTES})
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

while IFS= read -r -d '' auth_log; do
    host="$(basename "$(dirname "${auth_log}")")"
    file_epoch="$(stat -c %Y "${auth_log}")"
    age_minutes="$(( (now_epoch - file_epoch) / 60 ))"

    if (( age_minutes > STALE_MINUTES )); then
        printf 'STALE  %-25s %4sm  %s\n' "${host}" "${age_minutes}" "${auth_log}"
        stale_found=1
    else
        printf 'OK     %-25s %4sm  %s\n' "${host}" "${age_minutes}" "${auth_log}"
    fi
done < <(find "${LOG_BASE}" -mindepth 2 -maxdepth 2 -name auth.log -print0 | sort -z)

exit "${stale_found}"
