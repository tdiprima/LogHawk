# LogHawk Docs Reading Order 📚

Start here if you are new to the project and want the fastest path from "what is this?" to "I can run and operate it."
## Recommended Order

### 1. [LOGHAWK_COMPONENTS_CHEAT_SHEET.md](LOGHAWK_COMPONENTS_CHEAT_SHEET.md)

Read this first for the mental model. It explains what each major piece does: agents, central collector, certificates, alerting, search, health checks, AI export, and config.

### 2. [USAGE.md](USAGE.md)

Read this second when you are ready to run the system. It walks through certificate generation, collector setup, agent setup, alert watching, search, pipeline checks, and AI export.

### 3. [KEYS.md](KEYS.md)

Read this before touching TLS files. It explains the CA, server cert, client certs, keys, CSRs, config extensions, and which files belong on each host.

### 4. [CONFIGURATION.md](CONFIGURATION.md)

Read this when you need to tune behavior. It covers `/etc/loghawk/loghawk.conf`, setting precedence, environment overrides, brute force thresholds, dedup windows, expected logs, and stale-log checks.

### 5. [DAEMON.md](DAEMON.md)

Read this when you want `watch-alerts.py` to run continuously under systemd. It covers install, status checks, reconfiguration, and uninstall.

### 6. [STREAMS.md](STREAMS.md)

Read this to understand which log streams are forwarded from each agent and why those streams matter.

### 7. [TESTING.md](TESTING.md)

Read this after setup or before changing behavior. It gives verification steps for TLS, collector intake, agent forwarding, pipeline health, alerting, search, export, config loading, and end-to-end scenarios.

### 8. [adr/0001-keep-pattern-definitions-separate.md](adr/0001-keep-pattern-definitions-separate.md)

Read this last if you are modifying internals. It explains why alert patterns and search patterns are intentionally maintained separately.

## Fast Paths

For a quick demo:

1. [LOGHAWK_COMPONENTS_CHEAT_SHEET.md](LOGHAWK_COMPONENTS_CHEAT_SHEET.md)
2. [USAGE.md](USAGE.md)
3. [TESTING.md](TESTING.md)

For deployment:

1. [KEYS.md](KEYS.md)
2. [USAGE.md](USAGE.md)
3. [CONFIGURATION.md](CONFIGURATION.md)
4. [DAEMON.md](DAEMON.md)
5. [TESTING.md](TESTING.md)

For development:

1. [LOGHAWK_COMPONENTS_CHEAT_SHEET.md](LOGHAWK_COMPONENTS_CHEAT_SHEET.md)
2. [CONFIGURATION.md](CONFIGURATION.md)
3. [TESTING.md](TESTING.md)
4. [adr/0001-keep-pattern-definitions-separate.md](adr/0001-keep-pattern-definitions-separate.md)
