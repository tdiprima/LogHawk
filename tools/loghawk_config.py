"""
Centralized configuration loader for LogHawk tools.

Config file search order:
    1. Explicit path passed to load_config()
    2. LOGHAWK_CONFIG environment variable
    3. /etc/loghawk/loghawk.conf
    4. Built-in defaults (when no file found at default path)

Failure behavior:
    - Explicit path or env var points to missing file: ConfigError
    - File exists but unreadable (permissions): ConfigError
    - File exists but malformed: ConfigError
    - Field has invalid value: ConfigError
    - No config file found at default path: returns defaults silently
"""

from __future__ import annotations

import configparser
import logging
import os

log = logging.getLogger(__name__)

CONFIG_PATH_DEFAULT = "/etc/loghawk/loghawk.conf"
CONFIG_ENV_VAR = "LOGHAWK_CONFIG"

VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

_DEFAULTS = {
    "paths": {
        "log_base": "/var/log/remote",
    },
    "alerting": {
        "brute_force_window_seconds": "60",
        "brute_force_threshold": "3",
        "dedup_window_seconds": "14400",
        "email_severities": "CRITICAL,HIGH",
    },
    "pipeline": {
        "stale_minutes": "15",
        "expected_logs": "auth.log,kern.log,cron.log,audit.log,syslog.log",
    },
}


class ConfigError(Exception):
    """Config file missing, unreadable, or contains invalid values."""


def _validate_positive_int(section: str, key: str, raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(
            f"Invalid value for {section}.{key}: {raw!r} (must be a positive integer)"
        )
    if value <= 0:
        raise ConfigError(
            f"Invalid value for {section}.{key}: {value} (must be positive)"
        )
    return value


def _validate_severities(raw: str) -> set[str]:
    names = {s.strip() for s in raw.split(",") if s.strip()}
    if not names:
        raise ConfigError("alerting.email_severities cannot be empty")
    invalid = names - VALID_SEVERITIES
    if invalid:
        raise ConfigError(
            f"Invalid severity in alerting.email_severities: {', '.join(sorted(invalid))}. "
            f"Valid: {', '.join(sorted(VALID_SEVERITIES))}"
        )
    return names


def _validate(parser: configparser.ConfigParser) -> dict:
    """Validate all fields and return a flat dict with typed values."""
    result = {}

    log_base = parser.get("paths", "log_base").strip()
    if not log_base:
        raise ConfigError("paths.log_base cannot be empty")
    result["log_base"] = log_base

    for key in ("brute_force_window_seconds", "brute_force_threshold", "dedup_window_seconds"):
        result[key] = _validate_positive_int(
            "alerting", key, parser.get("alerting", key),
        )

    result["email_severities"] = _validate_severities(
        parser.get("alerting", "email_severities"),
    )

    result["stale_minutes"] = _validate_positive_int(
        "pipeline", "stale_minutes", parser.get("pipeline", "stale_minutes"),
    )

    raw_logs = parser.get("pipeline", "expected_logs")
    logs = [s.strip() for s in raw_logs.split(",") if s.strip()]
    if not logs:
        raise ConfigError("pipeline.expected_logs cannot be empty")
    result["expected_logs"] = logs

    return result


def load_config(config_path: str | None = None) -> dict:
    """
    Load and validate LogHawk configuration.

    Returns a flat dict:
        log_base: str
        brute_force_window_seconds: int
        brute_force_threshold: int
        dedup_window_seconds: int
        email_severities: set[str]
        stale_minutes: int
        expected_logs: list[str]
    """
    explicit_path = config_path or os.environ.get(CONFIG_ENV_VAR)

    parser = configparser.ConfigParser()
    parser.read_dict(_DEFAULTS)

    if explicit_path:
        if not os.path.exists(explicit_path):
            source = CONFIG_ENV_VAR if not config_path else "--config"
            raise ConfigError(
                f"Config file not found: {explicit_path} (from {source})"
            )
        _read_file(parser, explicit_path)
        log.info("Loaded config from %s", explicit_path)
    elif os.path.exists(CONFIG_PATH_DEFAULT):
        _read_file(parser, CONFIG_PATH_DEFAULT)
        log.info("Loaded config from %s", CONFIG_PATH_DEFAULT)
    else:
        log.debug(
            "No config file at %s — using built-in defaults", CONFIG_PATH_DEFAULT
        )

    return _validate(parser)


def _read_file(parser: configparser.ConfigParser, path: str) -> None:
    """Read and parse an INI file, raising ConfigError on any problem."""
    try:
        with open(path) as fh:
            parser.read_file(fh)
    except PermissionError:
        raise ConfigError(f"Cannot read config file (permission denied): {path}")
    except configparser.Error as err:
        raise ConfigError(f"Malformed config file {path}: {err}")
    except OSError as err:
        raise ConfigError(f"Cannot read config file: {err}")
