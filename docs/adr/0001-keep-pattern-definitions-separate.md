# ADR-0001: Keep pattern definitions separate across tools

**Status:** Accepted
**Date:** 2026-05-13

## Context

`alert_patterns.py` defines ~45 Python regex patterns used by `watch-alerts.py` and `export-for-ai.py` for real-time and batch alerting. `search-logs.sh` and `quick-morning-check.sh` define overlapping grep patterns for investigation and daily checks.

We considered consolidating into a single source of truth — either by adding grep-compatible fields to `alert_patterns.py` or by generating grep patterns from Python at runtime.

## Decision

Keep pattern definitions separate in each tool.

## Reasons

1. **Patterns rarely change.** The alert pattern list is stable. Drift between alerting and investigation patterns is theoretical, not a real maintenance burden.

2. **Different purposes tolerate mismatch.** Alerting patterns (Python) need precision — capture groups, lookaheads, severity assignment. Investigation patterns (grep) need speed and simplicity — an operator grepping during incident response. Slight differences between them are acceptable.

3. **Fix complexity exceeds the problem.** Adding a grep dialect field to every tuple, or injecting a Python helper into a bash workflow, adds moving parts for ~15 grep strings that work fine as-is.

## Consequences

- If a new attack pattern is added to `alert_patterns.py`, the corresponding grep in `search-logs.sh` must be added manually. This is a low-frequency task.
- `quick-morning-check.sh` runs on agent servers without Python — consolidation would require a generation step at deploy time, which is not worth the complexity.
