#!/bin/bash

# 1. Inject known-bad lines on each agent
logger -p auth.info "Failed password for invalid user testuser from 192.0.2.1 port 22 ssh2"
logger -p auth.info "sudo: testuser : TTY=pts/0 ; COMMAND=/usr/bin/cat /etc/shadow"

# 2. Wait 10 seconds, then check central received them
sleep 10
grep "testuser" /var/log/remote/$(hostname)/auth.log

# 3. Confirm pipeline is fresh
./check-log-pipeline.sh --minutes 5

# 4. Confirm search works
./search-logs.sh ssh-fails

# 5. Export and verify event count > 0
sudo python3 tools/export-for-ai.py --hours 1 | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print('Events:', d['summary']['total_events'])"
