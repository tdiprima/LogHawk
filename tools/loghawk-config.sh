#!/usr/bin/env bash
# loghawk-config.sh — Sourceable config loader for LogHawk bash tools.
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/loghawk-config.sh" || exit 1
#
# After sourcing, these variables are set (only if not already in the environment):
#   LOG_BASE           — from [paths] log_base
#   STALE_MINUTES      — from [pipeline] stale_minutes
#   _LOGHAWK_EXPECTED_LOGS_CSV — from [pipeline] expected_logs (comma-separated)
#
# Config file search order:
#   1. LOGHAWK_CONFIG environment variable
#   2. /etc/loghawk/loghawk.conf
#   3. Variables left unset (caller applies its own defaults)
#
# Failure behavior:
#   - LOGHAWK_CONFIG set but file missing → error, return 1
#   - File exists but unreadable → error, return 1
#   - Default path missing → no error, variables left for caller to default

_LOGHAWK_CONFIG_DEFAULT="/etc/loghawk/loghawk.conf"

_loghawk_parse_ini() {
    # Extract a value from an INI file by section and key.
    local file="$1" section="$2" key="$3"
    sed -n "/^\[${section}\]/,/^\[/p" "${file}" \
        | grep -m1 "^${key}[[:space:]]*=" \
        | cut -d= -f2- \
        | sed 's/^[[:space:]]*//' \
        | sed 's/[[:space:]]*$//'
}

_loghawk_load_config() {
    local config_file="${LOGHAWK_CONFIG:-${_LOGHAWK_CONFIG_DEFAULT}}"
    local explicit="false"
    [[ -n "${LOGHAWK_CONFIG:-}" ]] && explicit="true"

    if [[ ! -f "${config_file}" ]]; then
        if [[ "${explicit}" == "true" ]]; then
            echo "ERROR: LogHawk config not found: ${config_file} (from LOGHAWK_CONFIG)" >&2
            return 1
        fi
        # Default path missing — not an error; caller will apply its own defaults.
        return 0
    fi

    if [[ ! -r "${config_file}" ]]; then
        echo "ERROR: Cannot read LogHawk config (permission denied): ${config_file}" >&2
        return 1
    fi

    # Parse values from config. Existing env vars take precedence.
    local val

    if [[ -z "${LOG_BASE:-}" ]]; then
        val="$(_loghawk_parse_ini "${config_file}" "paths" "log_base")"
        [[ -n "${val}" ]] && LOG_BASE="${val}"
    fi

    if [[ -z "${STALE_MINUTES:-}" ]]; then
        val="$(_loghawk_parse_ini "${config_file}" "pipeline" "stale_minutes")"
        [[ -n "${val}" ]] && STALE_MINUTES="${val}"
    fi

    if [[ -z "${_LOGHAWK_EXPECTED_LOGS_CSV:-}" ]]; then
        val="$(_loghawk_parse_ini "${config_file}" "pipeline" "expected_logs")"
        [[ -n "${val}" ]] && _LOGHAWK_EXPECTED_LOGS_CSV="${val}"
    fi
}

_loghawk_load_config
