Here's the **"what each piece actually does"** breakdown — no fluff, just sticky mental models 🧠⚡

---

## 🧩 1. Agent side (runs on EVERY server)

### `install-agent.sh` → "Make this box start talking"

* Installs `rsyslog` if missing
* Enables TLS support (Transport Layer Security = secure pipe 🔒)
* Drops in the forwarding config
* Verifies certs exist (no certs = no trust = no send)

👉 Translation:

"Turn this random Linux box into a secure log streamer."

### `rsyslog-agent.conf` → "What to watch + where to send it"

This is the real brain on the server.

It tells rsyslog:

* *Watch these logs:*

  * `/var/log/auth.log` (logins 🔑)
  * `/var/log/audit/audit.log` (deep system activity)
  * kernel, cron, syslog, daemon stuff

* *Send them here:*

  * Central server over TCP (Transmission Control Protocol)
  * Wrapped in TLS (encrypted)
  * Verify the server's identity (no fake collector)

* *Don't lose logs if stuff breaks:*

  * Disk queue → buffers logs if network dies

👉 Mental model:

"Tail logs → securely ship them → never drop anything."

## 🏢 2. Central collector (the "brain server")

### `install-central.sh` → "Prep the mothership"

* Installs rsyslog
* Sets up TLS certs
* Creates log storage dirs
* Configures log rotation
* Opens firewall (port 6514)

👉 Translation:

"Turn this box into a log intake + storage system."

### `rsyslog-central.conf` → "Sort the chaos"

* Listens on TCP 6514 with TLS
* Accepts logs from all servers
* Splits them cleanly by:

  * hostname
  * log type

Creates structure like:

```
/var/log/remote/web-01/auth.log
/var/log/remote/db-02/syslog.log
```

👉 Mental model:

"Inbox → auto-organized folders instead of one giant mess."

### `generate-certs.sh` → "Issue passports"

Creates:

* CA (the boss trust anchor)
* Server cert (collector identity)
* Client certs (each server identity)

👉 Translation:

"Everyone proves who they are before talking."

This is **mTLS**:

* server verifies client
* client verifies server

No imposters allowed 🚫

## 👀 3. Real-time detection

### `watch-alerts.py` → "Live security radar"

This is the 🔥 part.

It:

* Tails log files in real-time
* Matches lines using regex patterns
* Assigns:

  * severity (INFO → CRITICAL)
  * category (brute force, account change, etc.)

#### Detects stuff like:

* failed SSH logins
* root logins 👀
* sudo usage
* new users
* password changes
* sketchy config edits

#### 🧠 Smart behavior:

* Tracks repeated failed logins by IP
* Only alerts when threshold hit (no spam)

👉 Translation:

"Don't cry wolf — scream only when it matters."

#### 🚨 When triggered:

It can:

* print colored alerts
* write JSON logs
* send emails (high/critical)

#### 🧠 Hidden pro move:

Handles log rotation automatically [inode changes (index node = metadata)]

👉 Mental model:

"Continuously watching, never loses its place."

## 🔍 4. Investigation tools

### `search-logs.sh` → "CLI detective"

Basically a **pre-built grep toolkit**.

You can instantly ask:

* "show failed SSH logins"
* "what did this IP do?"
* "who logged in as root?"
* "who ran sudo?"

👉 Under the hood:

* `grep`
* `find`
* sorting

👉 Mental model:

"Fast answers during panic mode — no thinking required."

## 🧪 5. Pipeline health check

### `check-log-pipeline.sh` → "Who stopped talking?"

* Looks at timestamps of logs per host
* Flags hosts that haven't sent logs recently

👉 Why this matters:  
Silent failure = worst failure

Could mean:

* logging broke ❌
* host is down 💀
* attacker killed logging 😬
* or simply — no activity

👉 Mental model:

"Attendance sheet for your servers."

## 🤖 6. AI export / summarizer

### `export-for-ai.py` → "Turn logs into a briefing"

* Reads past logs (not real-time)
* Uses same detection patterns as watcher
* Extracts recent suspicious events

#### Builds summary:

* total events
* categories
* top attacking IPs
* usernames involved
* critical events

#### Outputs:

* JSON (machines)
* OR prebuilt prompt (for LLMs)

👉 Key insight:  
It **filters + structures FIRST**, then hands to AI

NOT:

"dump raw logs into ChatGPT and pray"

👉 Mental model:

"Analyst prep before handing it to AI."

<br>
