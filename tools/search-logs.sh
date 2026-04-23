#!/usr/bin/env bash
# search-logs.sh
# Quick grep shortcuts for common security investigations.
# Run on the central log server.
#
# Usage:
#   ./search-logs.sh ssh-fails              — all SSH failures
#   ./search-logs.sh ssh-fails web-01       — SSH failures on specific host
#   ./search-logs.sh from-ip 192.168.1.50   — everything from an IP
#   ./search-logs.sh oom-kills              — OOM killer events
#   ./search-logs.sh disk-errors            — disk/filesystem errors
#   ./search-logs.sh crontab-changes        — crontab modifications
#   ./search-logs.sh audit-failures         — auditd auth failures
#   ./search-logs.sh service-failures       — systemd service crashes
#   ./search-logs.sh help                   — show all commands

LOG_BASE="${LOG_BASE:-/var/log/remote}"
LOCAL_AUTH="/var/log/auth.log"       # Ubuntu
LOCAL_AUTH_RHEL="/var/log/secure"    # RHEL

# ── Color helpers ─────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

function header() {
    echo -e "\n${CYAN}=== $1 ===${NC}\n"
}

# ── Resolve log files by name ────────────────────────────────────────
# Finds matching log files across remote hosts (+ local fallback for auth).
function resolve_logs() {
    local log_name="${1}"
    local hostname_filter="${2:-}"
    local files=()

    if [[ -n "${hostname_filter}" ]]; then
        local target="${LOG_BASE}/${hostname_filter}/${log_name}"
        if [[ -f "${target}" ]]; then
            files+=("${target}")
        else
            echo "ERROR: No ${log_name} found for host: ${hostname_filter}" >&2
            echo "Available hosts:" >&2
            ls "${LOG_BASE}/" >&2
            exit 1
        fi
    else
        while IFS= read -r -d '' f; do
            files+=("${f}")
        done < <(find "${LOG_BASE}" -name "${log_name}" -print0 2>/dev/null)

        if [[ "${log_name}" == "auth.log" ]]; then
            [[ -f "${LOCAL_AUTH}" ]]      && files+=("${LOCAL_AUTH}")
            [[ -f "${LOCAL_AUTH_RHEL}" ]] && files+=("${LOCAL_AUTH_RHEL}")
        fi
    fi

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "ERROR: No ${log_name} files found under ${LOG_BASE}" >&2
        exit 2
    fi

    printf '%s\n' "${files[@]}"
}

function resolve_auth_logs() {
    resolve_logs "auth.log" "${1:-}"
}

# ── Search functions ──────────────────────────────────────────────────

function search_ssh_fails() {
    local hostname_filter="${1:-}"
    header "SSH Failed Logins${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_auth_logs "${hostname_filter}")

    grep --with-filename --color=always \
        -E "Failed password|Invalid user" \
        "${log_files[@]}" \
    | sort | uniq -c | sort --reverse --numeric-sort \
    | head --lines=50

    echo ""
    echo -e "${YELLOW}Top IPs attacking:${NC}"
    grep --no-filename \
        -E "Failed password|Invalid user" \
        "${log_files[@]}" \
    | grep -oP "from \K[\d.]+" \
    | sort | uniq -c | sort --reverse --numeric-sort \
    | head --lines=20
}

function search_from_ip() {
    local target_ip="${1:-}"
    if [[ -z "${target_ip}" ]]; then
        echo "ERROR: Provide an IP address." >&2
        echo "Usage: $0 from-ip <ip-address>" >&2
        exit 1
    fi

    header "All activity from IP: ${target_ip}"

    # Search all log files for this IP
    find "${LOG_BASE}" -name "*.log" -print0 2>/dev/null \
    | xargs -0 grep --with-filename --color=always "${target_ip}" 2>/dev/null \
    | head --lines=200

    # Also check local
    grep --with-filename --color=always "${target_ip}" \
        "${LOCAL_AUTH}" "${LOCAL_AUTH_RHEL}" 2>/dev/null || true
}

function search_root_logins() {
    local hostname_filter="${1:-}"
    header "Successful Root SSH Logins${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_auth_logs "${hostname_filter}")

    grep --with-filename --color=always \
        -E "Accepted .+ for root" \
        "${log_files[@]}" || echo "None found."
}

function search_sudo_commands() {
    local hostname_filter="${1:-}"
    header "Sudo Commands${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_auth_logs "${hostname_filter}")

    grep --with-filename --color=always \
        -E "sudo:.*COMMAND=" \
        "${log_files[@]}" \
    | head --lines=100 || echo "None found."
}

function search_new_accounts() {
    local hostname_filter="${1:-}"
    header "Account Changes (create/delete)${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_auth_logs "${hostname_filter}")

    grep --with-filename --color=always \
        -E "useradd|userdel|groupadd|groupdel|usermod" \
        "${log_files[@]}" || echo "None found."
}

function search_last_logins() {
    local hostname_filter="${1:-}"
    header "Successful Logins (last 50)${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_auth_logs "${hostname_filter}")

    grep --with-filename --color=always \
        -E "Accepted (password|publickey)" \
        "${log_files[@]}" \
    | tail --lines=50
}

# ── kern.log searches ────────────────────────────────────────────────

function search_oom_kills() {
    local hostname_filter="${1:-}"
    header "OOM Killer Events${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "kern.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "Out of memory|Killed process|oom-kill" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

function search_disk_errors() {
    local hostname_filter="${1:-}"
    header "Disk / Filesystem Errors${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "kern.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "I/O error|EXT4-fs error|XFS.*error|SCSI error|medium error" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

function search_segfaults() {
    local hostname_filter="${1:-}"
    header "Segfaults${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "kern.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "segfault at" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

function search_firewall() {
    local hostname_filter="${1:-}"
    header "Firewall Drops${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "kern.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "BLOCK|DROP|REJECT|DPT=" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

# ── cron.log searches ────────────────────────────────────────────────

function search_crontab_changes() {
    local hostname_filter="${1:-}"
    header "Crontab Modifications${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "cron.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "REPLACE|BEGIN EDIT|END EDIT" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

function search_root_crons() {
    local hostname_filter="${1:-}"
    header "Root Cron Jobs${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "cron.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "\(root\) CMD" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

# ── audit.log searches ──────────────────────────────────────────────

function search_audit_failures() {
    local hostname_filter="${1:-}"
    header "Audit Auth Failures${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "audit.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "type=USER_AUTH.*res=failed|type=ANOM_" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

function search_audit_commands() {
    local hostname_filter="${1:-}"
    header "Audit Command Execution (permission changes)${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "audit.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E 'type=EXECVE.*a0="(/usr/s?bin/(chmod|chown|chattr|setfacl|visudo))' \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

# ── syslog.log searches ─────────────────────────────────────────────

function search_service_failures() {
    local hostname_filter="${1:-}"
    header "Service Failures${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "syslog.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -E "Failed with result|Entered failed state|failed to start" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

function search_disk_full() {
    local hostname_filter="${1:-}"
    header "Disk Full Events${hostname_filter:+ — host: $hostname_filter}"

    local log_files
    mapfile -t log_files < <(resolve_logs "syslog.log" "${hostname_filter}")

    grep --with-filename --color=always \
        -Ei "No space left on device" \
        "${log_files[@]}" 2>/dev/null \
    | tail --lines=50 || echo "None found."
}

# ── Help & dispatch ──────────────────────────────────────────────────

function show_help() {
    echo ""
    echo "Usage: $0 <command> [hostname]"
    echo ""
    echo "Auth log commands:"
    echo "  ssh-fails      [host]   — failed SSH logins"
    echo "  from-ip        <ip>     — all log lines mentioning a specific IP"
    echo "  root-logins    [host]   — successful SSH logins as root"
    echo "  sudo-commands  [host]   — sudo command history"
    echo "  new-accounts   [host]   — user/group create or delete events"
    echo "  last-logins    [host]   — recent successful logins"
    echo ""
    echo "Kernel log commands:"
    echo "  oom-kills      [host]   — OOM killer events"
    echo "  disk-errors    [host]   — disk and filesystem errors"
    echo "  segfaults      [host]   — process segfaults"
    echo "  firewall       [host]   — firewall drops/rejects"
    echo ""
    echo "Cron log commands:"
    echo "  crontab-changes [host]  — crontab modifications"
    echo "  root-crons     [host]   — root cron job execution"
    echo ""
    echo "Audit log commands:"
    echo "  audit-failures [host]   — auditd auth failures and anomalies"
    echo "  audit-commands [host]   — permission change commands"
    echo ""
    echo "Syslog commands:"
    echo "  service-failures [host] — systemd service failures"
    echo "  disk-full      [host]   — disk full events"
    echo ""
    echo "Environment variables:"
    echo "  LOG_BASE   — path to remote log directory (default: /var/log/remote)"
    echo ""
    echo "Examples:"
    echo "  $0 ssh-fails"
    echo "  $0 oom-kills web-server-01"
    echo "  $0 from-ip 10.0.0.55"
    echo "  $0 service-failures"
}

COMMAND="${1:-help}"
ARGUMENT="${2:-}"

case "${COMMAND}" in
    ssh-fails)        search_ssh_fails       "${ARGUMENT}" ;;
    from-ip)          search_from_ip         "${ARGUMENT}" ;;
    root-logins)      search_root_logins     "${ARGUMENT}" ;;
    sudo-commands)    search_sudo_commands   "${ARGUMENT}" ;;
    new-accounts)     search_new_accounts    "${ARGUMENT}" ;;
    last-logins)      search_last_logins     "${ARGUMENT}" ;;
    oom-kills)        search_oom_kills       "${ARGUMENT}" ;;
    disk-errors)      search_disk_errors     "${ARGUMENT}" ;;
    segfaults)        search_segfaults       "${ARGUMENT}" ;;
    firewall)         search_firewall        "${ARGUMENT}" ;;
    crontab-changes)  search_crontab_changes "${ARGUMENT}" ;;
    root-crons)       search_root_crons      "${ARGUMENT}" ;;
    audit-failures)   search_audit_failures  "${ARGUMENT}" ;;
    audit-commands)   search_audit_commands  "${ARGUMENT}" ;;
    service-failures) search_service_failures "${ARGUMENT}" ;;
    disk-full)        search_disk_full       "${ARGUMENT}" ;;
    help|--help|-h)   show_help ;;
    *)
        echo "ERROR: Unknown command '${COMMAND}'" >&2
        show_help
        exit 1
        ;;
esac
