![LogHawk Banner Design](LogHawk-Banner-Design.png)

# LogHawk 🦅

**Real-time security visibility for Linux fleets — without the SIEM headache**

### What It Is

LogHawk is a lightweight, self-hosted system for:

* Centralizing Linux security logs
* Detecting suspicious activity in real time
* Investigating incidents fast using familiar tools

No dashboards. No proprietary query language. No enterprise bloat.

Just signal.

### The Problem

Linux systems already log everything:

* SSH logins (success + failure)
* sudo usage
* user creation / changes
* system activity

But in practice:

* Logs are scattered across hosts
* There's no real-time awareness
* Incident response = manual grep archaeology

LogHawk fixes that.

### How It Works

**1. Secure Log Forwarding**

* Uses `rsyslog` (native, reliable)
* TLS + mutual TLS (mTLS) for trust and encryption
* Built-in queueing (no log loss during outages)

**2. Centralized Storage**

* Clean, filesystem-based layout:

  ```
  /var/log/remote/<host>/auth.log
  ```

* No database required
* Works with standard Linux tools (`grep`, `less`, etc.)

**3. Real-Time Detection**

* Watches logs as they arrive
* Detects:

  * Failed SSH attempts
  * Root logins
  * sudo failures
  * User/account changes
* Severity levels + colorized alerts
* Brute-force detection via pattern tracking

**4. Fast Investigation**

* Prebuilt scripts for common questions:

  * Failed logins
  * Activity by IP
  * Root/sudo usage
* Eliminates ad-hoc command guessing during incidents

**5. Pipeline Health Checks**

* Detects hosts that stop sending logs
* Surfaces visibility gaps early

**6. AI-Ready Exports**

* Extracts and summarizes suspicious events
* Outputs clean JSON or LLM-ready prompts

### Why This Exists

Most logging tools fall into two categories:

* Too simple → no real insight
* Too complex → nobody actually uses them

LogHawk lives in the middle:

* Small enough to understand
* Powerful enough to matter
* Fast enough for real incidents

### Design Philosophy

* Use what already works (rsyslog, filesystem, shell tools)
* Prefer clarity over abstraction
* Optimize for 2am debugging, not demos
* Detect patterns, not just events

### When It's Useful

* You manage multiple Linux servers
* You care about SSH / sudo / account activity
* You want real-time awareness without a SIEM
* You've ever said:

  > "Wait... which server was that on?"

### TL;DR

LogHawk turns this:

> Logs are everywhere and I hope nothing bad is happening

into this:

> I see what's happening, right now, and I know where to look next

## Usage

[USAGE](USAGE.md)

## License

[MIT](LICENSE)

<br>
