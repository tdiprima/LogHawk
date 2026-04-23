## Six streams forwarded from each agent

| Facility         | What it captures                                   | Source                                          |
|-----------------|----------------------------------------------------|-------------------------------------------------|
| auth,authpriv.* | SSH logins, sudo, PAM, passwd changes              | syslog facility                                 |
| kern.*          | Kernel messages, hardware errors, firewall drops   | syslog facility                                 |
| cron.*          | Cron job execution                                 | syslog facility                                 |
| daemon.*        | Service/daemon messages (systemd, etc.)            | syslog facility                                 |
| syslog.*        | rsyslog internal + catchall syslog messages        | syslog facility                                 |
| local6.*        | auditd logs                                        | file-tailed from /var/log/audit/audit.log via imfile |

Three also kept locally on each agent: `auth.log`, `kern.log`, `cron.log`. Auditd already keeps its own local copy natively.
 
On central server, these land in separate files per host: `auth.log`, `kern.log`, `cron.log`, `audit.log`, and 
`syslog.log` (catchall for daemon + syslog facilities).
