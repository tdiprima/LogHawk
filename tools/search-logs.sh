#!/usr/bin/env bash
# search-logs.sh
# Quick grep shortcuts for common security investigations.
# Run on the central log server.
#
# Usage:
#   ./search-logs.sh ssh-fails              — all SSH failures
#   ./search-logs.sh ssh-fails web-01       — SSH failures on specific host
#   ./search-logs.sh from-ip 192.168.1.50   — everything from an IP
#   ./search-logs.sh root-logins            — successful root SSH logins
#   ./search-logs.sh sudo-commands          — all sudo usage
#   ./search-logs.sh new-accounts           — users or groups created/deleted
#   ./search-logs.sh last-logins [host]     — recent successful logins
#   ./search-logs.sh help                   — show this help

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

# ── Resolve which auth log files to search ───────────────────────────
# If a hostname is given, search only that host's log.
# Otherwise search all remote logs + local.
function resolve_auth_logs() {
    local hostname_filter="${1:-}"
    local files=()

    if [[ -n "${hostname_filter}" ]]; then
        local target="${LOG_BASE}/${hostname_filter}/auth.log"
        if [[ -f "${target}" ]]; then
            files+=("${target}")
        else
            echo "ERROR: No log found for host: ${hostname_filter}" >&2
            echo "Available hosts:" >&2
            ls "${LOG_BASE}/" >&2
            exit 1
        fi
    else
        # All remote hosts
        while IFS= read -r -d '' f; do
            files+=("${f}")
        done < <(find "${LOG_BASE}" -name "auth.log" -print0 2>/dev/null)

        # Local log too
        [[ -f "${LOCAL_AUTH}" ]]      && files+=("${LOCAL_AUTH}")
        [[ -f "${LOCAL_AUTH_RHEL}" ]] && files+=("${LOCAL_AUTH_RHEL}")
    fi

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "ERROR: No auth log files found under ${LOG_BASE}" >&2
        exit 2
    fi

    printf '%s\n' "${files[@]}"
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

function show_help() {
    echo ""
    echo "Usage: $0 <command> [hostname]"
    echo ""
    echo "Commands:"
    echo "  ssh-fails    [host]       — failed SSH logins, optionally filtered by host"
    echo "  from-ip      <ip>         — all log lines mentioning a specific IP"
    echo "  root-logins  [host]       — successful SSH logins as root"
    echo "  sudo-commands [host]      — sudo command history"
    echo "  new-accounts [host]       — user/group create or delete events"
    echo "  last-logins  [host]       — recent successful logins"
    echo "  help                      — show this help"
    echo ""
    echo "Environment variables:"
    echo "  LOG_BASE   — path to remote log directory (default: /var/log/remote)"
    echo ""
    echo "Examples:"
    echo "  $0 ssh-fails"
    echo "  $0 ssh-fails web-server-01"
    echo "  $0 from-ip 10.0.0.55"
    echo "  $0 sudo-commands db-server-01"
}

# ── Dispatch ──────────────────────────────────────────────────────────
COMMAND="${1:-help}"
ARGUMENT="${2:-}"

case "${COMMAND}" in
    ssh-fails)      search_ssh_fails    "${ARGUMENT}" ;;
    from-ip)        search_from_ip      "${ARGUMENT}" ;;
    root-logins)    search_root_logins  "${ARGUMENT}" ;;
    sudo-commands)  search_sudo_commands "${ARGUMENT}" ;;
    new-accounts)   search_new_accounts  "${ARGUMENT}" ;;
    last-logins)    search_last_logins   "${ARGUMENT}" ;;
    help|--help|-h) show_help ;;
    *)
        echo "ERROR: Unknown command '${COMMAND}'" >&2
        show_help
        exit 1
        ;;
esac
