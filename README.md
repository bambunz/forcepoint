# fp

Command-line tools for [Forcepoint NGFW](https://www.forcepoint.com/product/ngfw-network-security),
backed by the Security Management Center (SMC) API.

```
fp COMMAND [options]
```

| Command | Purpose |
|---|---|
| `fp logtail` | `tail(1)`-style live/stored log viewer (the former `fptail`) |
| `fp license` / `fp licenses` | License inventory — type, status, binding, expiry — per admin domain |
| `fp changes pending` | Changes pending approval/commit on each engine, per admin domain |
| `fp show domains` | List the admin domains you can pass to `--domain` (including `all`) |

## Requirements

- Python 3.8+
- A Forcepoint NGFW SMC (Security Management Center), version 6.2 or newer, reachable
  over HTTPS from wherever you run this
- An SMC API Client with an API key and appropriate privileges (create one in the
  Management Client under **Administration > Access Rights > API Client**):
  log-viewing rights for `logtail`, license/domain visibility for `license`

## Installation

```bash
git clone git@github.com:bambunz/forcepoint.git
cd forcepoint

python3 -m venv ~/forcepoint
source ~/forcepoint/bin/activate

pip install -e .
```

This installs the `fp` command into the virtualenv, along with its dependencies:
[`fp-NGFW-SMC-python`](https://github.com/Forcepoint/fp-NGFW-SMC-python) (the official
SMC API client), its `fp-NGFW-SMC-python-monitoring` extension (real-time log/event
monitoring over websocket), and `websocket-client`.

Activate the venv (`source ~/forcepoint/bin/activate`) in any new shell before running
`fp`.

## Configuration

`fp` needs the SMC API URL, an API key, and (for `logtail`) the Administrative Domain
to scope the session to. These can come from, in order of precedence:

1. Command-line flags (`--url`, `--api-key`, `--domain`, ...)
2. Environment variables (`FP_URL`, `FP_API_KEY`, `FP_DOMAIN`, `FP_VERIFY`,
   `FP_API_VERSION`, `FP_TIMEOUT`; the legacy `FPTAIL_*` names still work)
3. A config file, default `~/.forcepoint/forcepoint.conf`

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

`fp` warns on startup if the file is group/other-readable.

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
fp logtail --profile acme -f
fp license --profile widgets-inc
```

`fp` prints the active profile and URL at startup so it's always obvious which
environment/customer you're looking at.

## fp logtail

A `tail(1)`-style viewer for NGFW logs. Instead of parsing syslog exports or clicking
through the Log Viewer in the Management Client, `fp logtail` connects directly to the
SMC's real-time log websocket and prints records straight to your terminal — the same
feed the Management Client uses, but scriptable, greppable, and pipeable.

```
$ fp logtail -f --severity high --severity critical
fp logtail: profile=default domain=Acme-Corp url=https://smc.acme.example:8082
Creation Time       Severity  Action  Node Id      Src Addr      Src Port  Dst Addr        Dst Port  Protocol  Event     Information Message
------------------- --------- ------- ------------ ------------- --------- --------------- --------- --------- --------- -------------------
2026-07-02 09:14:02 High      Discard 10.0.0.1     203.0.113.44  51422     10.0.0.10        443       TCP       Log       Blocked by rule 12
2026-07-02 09:14:03 Critical  Block   10.0.0.1     198.51.100.9  33210     10.0.0.20        22        TCP       Log       Brute force pattern
```

Features:

- **Real-time tail (`-f`)** over the same websocket the Management Client uses, with
  automatic reconnect and backoff if the connection drops.
- **Historical dump (`-n`)**, just like plain `tail` — shows the last N stored records
  and exits if you don't pass `-f`.
- **Server-side filtering** — severity, action, source/destination IP, service, or a raw
  SMC filter expression copied from the Management Client's "Show Filter Expression".
- **Mandatory Admin Domain scoping** — `logtail` refuses to start without a domain, to
  stop you from accidentally viewing (or mixing) log data across customers/tenants.
- **Multiple output formats** — colorized table (default) or newline-delimited JSON
  (`--json`) for piping into `jq`, a SIEM, or a log pipeline.

### Examples

```bash
# Show the last 10 stored log records and exit (like plain `tail`)
fp logtail

# Follow new records in real time (like `tail -f`), after an initial dump of 50
fp logtail -n 50 -f

# Follow only, skip the historical dump
fp logtail -n 0 -f

# Only high/critical severity events
fp logtail -f --severity high --severity critical

# Only traffic to/from a specific host
fp logtail -f --src 203.0.113.44 --dst 10.0.0.20

# Only a specific service, blocked traffic
fp logtail -f --service TCP/443 --action block

# Raw SMC filter expression (copy from Management Client: Logs view ->
# right-click a filter -> "Show Filter Expression")
fp logtail -f --expr '$Dport == 22 OR $Dport == 3389'

# Custom columns
fp logtail -f --fields TIMESTAMP,SRC,DST,ACTION,IPSAPPID

# JSON output, piped into jq
fp logtail -f --json | jq -c 'select(.Action == "Discard")'

# Client-side regex on top of server-side filters, no color, useful in scripts/cron
fp logtail -n 200 --grep 'TLS' --no-color

# Point at a specific SMC without a config file at all
fp logtail -f --url https://smc.example.com:8082 --api-key "$FP_API_KEY" --domain Acme-Corp

# Self-signed SMC certificate
fp logtail -f --insecure
```

### logtail flags

| Flag | Description |
|---|---|
| `-n, --lines N` | Show last N stored records (default: 10). `0` skips the historical dump. |
| `-f, --follow` | Keep streaming new records after the initial dump, like `tail -f`. |
| `--profile NAME` | Config profile/section to use (default: `default`, i.e. `[smc]`). |
| `--config PATH` | Path to config file (default: `~/.forcepoint/forcepoint.conf`). |
| `--url URL` | SMC API URL, e.g. `https://smc.example.com:8082`. |
| `--api-key KEY` | SMC API key. |
| `--domain NAME` | SMC Administrative Domain. **Required** (flag, env, or config). `all` streams the Shared Domain view, which spans every domain your permissions allow. |
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

## fp license

License inventory across administrative domains. `license` and `licenses` are
interchangeable.

```
$ fp license
fp license: profile=default url=https://smc.acme.example:8082 domains=all
Domain        License Id  Type     Status  Bound To                     Expires     Maintenance Expires
--------------------------------------------------------------------------------------------------------
Acme-Corp     1000001     SECNODE  Bound   Fw-Node-1                    2027-01-31  2026-12-31
Acme-Corp     1000002     SECNODE  Bound   Fw-Node-2                    2027-01-31  2026-12-31
Widgets-Inc   1000010     Mgmt     Bound   Management Server            2027-06-30  2027-06-30
```

By default all administrative domains visible to the API key are queried (this
requires Shared Domain visibility; if the key can't enumerate domains, `fp` falls
back to the profile's configured domain and says so). Restrict with `--domain`,
repeatable:

```bash
# All domains (explicitly or by omission)
fp licenses
fp license --domain all

# Only two specific domains
fp license --domain Acme-Corp --domain Widgets-Inc

# JSON for scripting
fp license --json | jq -r 'select(.status != "Bound") | .license_id'

# CSV export (header included), e.g. straight into a spreadsheet
fp license --csv > licenses.csv

# Everything the SMC knows about each license, as per-license blocks
fp license --details

# Full detail fields also flow into --json / --csv
fp license --details --csv > licenses-full.csv
fp license --details --json | jq 'select(.bound_to == "<Unknown>")'
```

Unbound/unassigned licenses are highlighted in yellow in table output.

### Licenses bound to `<Unknown>`

`Bound To: <Unknown>` means the SMC could not resolve the bound element *from the
domain you queried* — typically the license is bound to an engine that lives in a
different admin domain, or to an element that has since been deleted. The license
itself is fine; only the name lookup failed in that domain's context. Use
`--details` to see the identifying fields the SMC still has for it — `binding`
(the POS/serial it is bound to), `customer_name`, `features`, `granted_date`,
`proof_of_license` — and match the POS/serial against your engines. The plain
table prints a reminder to stderr whenever `<Unknown>` bindings are present.

### license flags

| Flag | Description |
|---|---|
| `--domain NAME` | Limit to this admin domain (repeatable; `all` or omitted = all visible domains). |
| `--profile NAME` | Config profile/section to use (default: `default`, i.e. `[smc]`). |
| `--config PATH` | Path to config file (default: `~/.forcepoint/forcepoint.conf`). |
| `--url URL` | SMC API URL. |
| `--api-key KEY` | SMC API key. |
| `--api-version VER` | SMC API version override. |
| `--insecure` | Disable TLS certificate verification. Only for lab/self-signed setups. |
| `-d, --details` | Show every field the SMC returns per license (binding serial/POS, features, customer name, ...). Table mode switches to per-license blocks; `--json`/`--csv` gain the extra fields. |
| `--json` | Emit newline-delimited JSON instead of a table (mutually exclusive with `--csv`). |
| `--csv` | Emit CSV with a header row instead of a table. |
| `--no-color` | Disable ANSI color output (also respects `NO_COLOR`). |

## fp changes

Configuration-change inspection. First (and currently only) subcommand:
`pending` — the changes waiting for approval/commit on each engine (what the
Management Client shows as "Pending Changes"; requires SMC >= 6.2).

```
$ fp changes pending
fp changes: profile=default url=https://smc.acme.example:8082 domains=all
Domain     Engine        Changed On                 Event Type               Element    Modifier  Approved On  Approver
------------------------------------------------------------------------------------------------------------------------
Acme-Corp  fw-cluster-1  2026-07-12 15:24:40 (GMT)  stonegate.object.update  Rule @112  admin
Acme-Corp  fw-cluster-1  2026-07-12 15:30:00 (GMT)  stonegate.object.update  DMZ-net    ale       ...          boss
```

Domain selection works exactly like `fp license`: all visible domains by
default, `--domain` (repeatable, `all` accepted) to restrict, and
`fp changes pending show domains` lists the choices. Rows not yet approved are
highlighted in yellow. Engines whose type doesn't support pending changes are
silently skipped.

```bash
# Everything, everywhere
fp changes pending

# One customer domain, CSV for the change-review ticket
fp changes pending --domain Acme-Corp --csv > pending-acme.csv

# Unapproved only, via jq
fp changes pending --json | jq -c 'select(.approved_on == "")'
```

### changes pending flags

| Flag | Description |
|---|---|
| `--domain NAME` | Limit to this admin domain (repeatable; `all` or omitted = all visible domains). |
| `--profile NAME` | Config profile/section to use (default: `default`, i.e. `[smc]`). |
| `--config PATH` | Path to config file (default: `~/.forcepoint/forcepoint.conf`). |
| `--url URL` | SMC API URL. |
| `--api-key KEY` | SMC API key. |
| `--api-version VER` | SMC API version override. |
| `--insecure` | Disable TLS certificate verification. Only for lab/self-signed setups. |
| `--json` | Emit newline-delimited JSON instead of a table (mutually exclusive with `--csv`). |
| `--csv` | Emit CSV with a header row instead of a table. |
| `--no-color` | Disable ANSI color output (also respects `NO_COLOR`). |

## fp show

Lists the values you can pass to other commands. First (and currently only)
subcommand: `domains`.

```
$ fp show domains
fp show: profile=default url=https://smc.acme.example:8082
all
Acme-Corp
Shared Domain
Widgets-Inc
```

The list always starts with the pseudo-domain `all`: `fp license --domain all`
queries every domain, `fp logtail --domain all` streams the Shared Domain view
(which spans all domains your permissions allow).

`show` is also reachable from inside the other commands, so you can check the
choices without leaving the command you're typing:

```bash
fp show domains
fp logtail show domains
fp license show domains
fp changes pending show domains
```

All four are equivalent. `--json` emits the list as a JSON array. Connection
flags (`--profile`, `--url`, `--api-key`, `--insecure`, ...) work as usual.

## How it works

`fp` uses [`smc-python`](https://github.com/Forcepoint/fp-NGFW-SMC-python) to log in to
the SMC API. `logtail` opens a `LogQuery` against `/monitoring/log/socket` — the same
websocket endpoint the Management Client's Logs view uses — with filters compiled into
the SMC's native query filter format and evaluated server-side. `license` and
`changes pending` walk the requested admin domains with `session.switch_domain()`,
reading each domain's `system/licenses` resource and each engine's
`pending_changes` resource respectively.

## Known limitations

- Long-running `logtail -f` sessions reuse the SMC session established at startup. If
  that session itself expires (per your SMC's session timeout policy), the reconnect
  logic will keep retrying but won't re-authenticate — restart `fp logtail` if that
  happens.
- `logtail` filtering by engine currently matches on the sending engine's IP
  (`Node Id`), not by engine element name.
- SMC licenses live in the Shared Domain; depending on SMC version the per-domain
  license view may repeat management-server-wide licenses in each domain rather than
  showing only that domain's bindings.

## Security notes

- The config file holds a live API key — keep it at `chmod 600`, per-user only.
  `fp` will warn (not refuse) if it isn't.
- `logtail --domain` is mandatory by design to prevent cross-tenant log exposure in
  multi-domain SMC deployments. Use `--domain 'Shared Domain'` explicitly if that's
  genuinely what you want.
- `--insecure` disables TLS certificate validation entirely. Use it only against SMCs
  with self-signed certificates you already trust out-of-band (e.g. isolated lab/test
  environments), never over an untrusted network.
