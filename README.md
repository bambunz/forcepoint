# fptail

A `tail(1)`-style command-line viewer for [Forcepoint NGFW](https://www.forcepoint.com/product/ngfw-network-security)
logs, backed by the Security Management Center (SMC) Monitoring API.

Instead of parsing syslog exports or clicking through the Log Viewer in the Management
Client, `fptail` connects directly to the SMC's real-time log websocket and prints
records straight to your terminal — the same feed the Management Client uses, but
scriptable, greppable, and pipeable like any other Unix log tool.

```
$ fptail -f --severity high --severity critical
fptail: profile=default domain=Acme-Corp url=https://smc.acme.example:8082
Creation Time       Severity  Action  Node Id      Src Addr      Src Port  Dst Addr        Dst Port  Protocol  Event     Information Message
------------------- --------- ------- ------------ ------------- --------- --------------- --------- --------- --------- -------------------
2026-07-02 09:14:02 High      Discard 10.0.0.1     203.0.113.44  51422     10.0.0.10        443       TCP       Log       Blocked by rule 12
2026-07-02 09:14:03 Critical  Block   10.0.0.1     198.51.100.9  33210     10.0.0.20        22        TCP       Log       Brute force pattern
```

## Features

- **Real-time tail (`-f`)** of live SMC log records over the same websocket the
  Management Client uses, with automatic reconnect and backoff if the connection drops.
- **Historical dump (`-n`)**, just like plain `tail` — shows the last N stored records
  and exits if you don't pass `-f`.
- **Server-side filtering** — severity, action, source/destination IP, service, or a raw
  SMC filter expression copied from the Management Client's "Show Filter Expression".
  Filtering happens on the SMC side, not by pulling everything and grepping locally.
- **Mandatory Admin Domain scoping** — every invocation must specify an SMC
  Administrative Domain. This is deliberate: it stops you from accidentally viewing
  (or mixing) log data across different customers/tenants in a multi-domain SMC.
- **Multiple output formats** — colorized human-readable table (default) or
  newline-delimited JSON (`--json`) for piping into `jq`, a SIEM, or a log pipeline.
- **Config profiles** — store credentials and domain per customer/environment in a
  config file and select with `--profile`, instead of retyping flags every time.

## Requirements

- Python 3.8+
- A Forcepoint NGFW SMC (Security Management Center), version 6.2 or newer, reachable
  over HTTPS from wherever you run this
- An SMC API Client with an API key and appropriate log-viewing privileges (create one
  in the Management Client under **Administration > Access Rights > API Client**)

## Installation

```bash
git clone git@bambunz-github.com:bambunz/fptail.git
cd fptail

python3 -m venv ~/forcepoint
source ~/forcepoint/bin/activate

pip install -e .
```

This installs the `fptail` command into the virtualenv, along with its dependencies:
[`fp-NGFW-SMC-python`](https://github.com/Forcepoint/fp-NGFW-SMC-python) (the official
SMC API client), its `fp-NGFW-SMC-python-monitoring` extension (real-time log/event
monitoring over websocket), and `websocket-client`.

Activate the venv (`source ~/forcepoint/bin/activate`) in any new shell before running
`fptail`.

## Configuration

`fptail` needs four things to connect: the SMC API URL, an API key, the Administrative
Domain to scope the session to, and (optionally) TLS verification settings. These can
come from, in order of precedence:

1. Command-line flags (`--url`, `--api-key`, `--domain`, ...)
2. Environment variables (`FPTAIL_URL`, `FPTAIL_API_KEY`, `FPTAIL_DOMAIN`, `FPTAIL_VERIFY`,
   `FPTAIL_DOMAIN`, `FPTAIL_API_VERSION`, `FPTAIL_TIMEOUT`)
3. A config file, default `~/.forcepoint/forcepoint.conf`

The **domain is mandatory** one way or another — `fptail` refuses to start without one,
to prevent accidentally reading Shared Domain (or the wrong customer's) logs.

### Config file

```ini
# ~/.forcepoint/forcepoint.conf
[smc]
url = https://smc.example.com:8082
api_key = your-api-client-key
domain = Acme-Corp
verify = true
```

Lock it down, since it holds a live API key:

```bash
mkdir -p ~/.forcepoint
chmod 700 ~/.forcepoint
chmod 600 ~/.forcepoint/forcepoint.conf
```

`fptail` warns on startup if the file is group/other-readable.

### Multiple environments / customers

Add one `[smc:<profile>]` section per environment, each with its own URL, key, and
domain:

```ini
[smc:acme]
url = https://smc.acme.example:8082
api_key = acme-api-key
domain = Acme-Corp

[smc:widgets-inc]
url = https://smc.widgets.example:8082
api_key = widgets-api-key
domain = Widgets-Inc
```

Select one with `--profile`:

```bash
fptail --profile acme -f
fptail --profile widgets-inc -n 50
```

`fptail` prints the active profile, domain, and URL at startup so it's always obvious
which environment/customer you're looking at.

## Usage

```bash
# Show the last 10 stored log records and exit (like plain `tail`)
fptail

# Follow new records in real time (like `tail -f`), after an initial dump of 50
fptail -n 50 -f

# Follow only, skip the historical dump
fptail -n 0 -f

# Only high/critical severity events
fptail -f --severity high --severity critical

# Only traffic to/from a specific host
fptail -f --src 203.0.113.44 --dst 10.0.0.20

# Only a specific service, blocked traffic
fptail -f --service TCP/443 --action block

# Raw SMC filter expression (copy from Management Client: Logs view ->
# right-click a filter -> "Show Filter Expression")
fptail -f --expr '$Dport == 22 OR $Dport == 3389'

# Custom columns
fptail -f --fields TIMESTAMP,SRC,DST,ACTION,IPSAPPID

# JSON output, piped into jq
fptail -f --json | jq -c 'select(.Action == "Discard")'

# Client-side regex on top of server-side filters, no color, useful in scripts/cron
fptail -n 200 --grep 'TLS' --no-color

# Point at a specific SMC without a config file at all
fptail -f --url https://smc.example.com:8082 --api-key "$FPTAIL_API_KEY" --domain Acme-Corp

# Self-signed SMC certificate
fptail -f --insecure
```

## CLI reference

| Flag | Description |
|---|---|
| `-n, --lines N` | Show last N stored records (default: 10). `0` skips the historical dump. |
| `-f, --follow` | Keep streaming new records after the initial dump, like `tail -f`. |
| `--profile NAME` | Config profile/section to use (default: `default`, i.e. `[smc]`). |
| `--config PATH` | Path to config file (default: `~/.forcepoint/forcepoint.conf`). |
| `--url URL` | SMC API URL, e.g. `https://smc.example.com:8082`. |
| `--api-key KEY` | SMC API key. |
| `--domain NAME` | SMC Administrative Domain. **Required** (flag, env, or config). |
| `--api-version VER` | SMC API version override. |
| `--insecure` | Disable TLS certificate verification. Only for lab/self-signed setups. |
| `--json` | Emit newline-delimited JSON instead of a colorized table. |
| `--fields LIST` | Comma-separated `LogField` names to display, e.g. `TIMESTAMP,SRC,DST,ACTION`. |
| `--timezone TZ` | Timezone for timestamps, e.g. `CST` or `Europe/Helsinki`. |
| `--severity {info,low,high,critical}` | Filter by alert severity (repeatable). |
| `--action {allow,permit,discard,block,refuse,terminate}` | Filter by rule action (repeatable). |
| `--src IP` | Filter by source IP (repeatable). |
| `--dst IP` | Filter by destination IP (repeatable). |
| `--sender IP` | Filter by the sending engine's IP / Node ID (repeatable). |
| `--service PROTO/PORT` | Filter by service, e.g. `TCP/443` (repeatable). |
| `--expr EXPR` | Raw SMC filter expression (from "Show Filter Expression" in the Management Client). |
| `--grep PATTERN` | Client-side regex applied to each rendered line before printing. |
| `--no-color` | Disable ANSI color output (also respects `NO_COLOR`). |
| `--max-backoff SECONDS` | Max seconds between reconnect attempts in follow mode (default: 30). |

## How it works

`fptail` uses [`smc-python`](https://github.com/Forcepoint/fp-NGFW-SMC-python) to log in
to the SMC API and its `smc_monitoring` extension to open a `LogQuery` against
`/monitoring/log/socket` — the same websocket endpoint the Management Client's Logs view
uses. Filters (severity, action, IPs, service, ...) are compiled into the SMC's native
query filter format and evaluated server-side, so only matching records cross the wire.
Historical (`stored`) queries return a bounded batch and terminate; live (`current`)
queries stream indefinitely, and `fptail` transparently reconnects with exponential
backoff if the socket drops.

## Known limitations

- Long-running `-f` sessions reuse the SMC session established at startup. If that
  session itself expires (per your SMC's session timeout policy), the reconnect logic
  will keep retrying but won't re-authenticate — restart `fptail` if that happens.
- Filtering by engine currently matches on the sending engine's IP (`Node Id`), not by
  engine element name.

## Security notes

- The config file holds a live API key — keep it at `chmod 600`, per-user only.
  `fptail` will warn (not refuse) if it isn't.
- `--domain` is mandatory by design to prevent cross-tenant log exposure in multi-domain
  SMC deployments. Use `--domain 'Shared Domain'` explicitly if that's genuinely what
  you want.
- `--insecure` disables TLS certificate validation entirely. Use it only against SMCs
  with self-signed certificates you already trust out-of-band (e.g. isolated lab/test
  environments), never over an untrusted network.
