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
| `fp show metrics` | Appliance metrics per firewall node, one row per node |

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
Domain        License Id  Type     Status  Bound To           Expires     Maintenance Expires
------------------------------------------------------------------------------------------------
Acme-Corp     1000001     SECNODE  Bound   Fw-Node-1          2027-01-31  2026-12-31
Acme-Corp     1000002     SECNODE  Bound   Fw-Node-2          2027-01-31  2026-12-31
Widgets-Inc   1000010     Mgmt     Bound   Management Server  2027-06-30  2027-06-30
```

`--show-customer` adds a Customer column (the license's `customer_name`) after
Domain, in both table and CSV output. `--json` always carries the `customer`
field, and `--details` always shows it.

Domain selection (same rules for `fp changes pending` and `fp license cron`):

1. No `--domain` flag → the profile's configured `domain =` is queried.
2. Profile has no `domain =` (or has `domain = all`) → every domain visible to
   the API key is queried (requires Shared Domain visibility; if the key can't
   enumerate domains, `fp` falls back to the profile domain and says so).
3. `--domain all` → every visible domain, regardless of config.
4. `--domain 'domain1,domain2'` → exactly those; comma-separated and/or repeated
   flags both work.

```bash
# Profile domain only (or everything, if the profile has no domain)
fp licenses

# Every visible domain
fp license --domain all

# A specific list: comma-separated, repeated flags, or both
fp license --domain 'Acme-Corp,Widgets-Inc'
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
different admin domain, or to an element that has since been deleted.

`fp license` resolves these across domains automatically: when the same license
shows a real element name in its home domain, the `<Unknown>` rows are filled in
as `name (domain)` — e.g. `Fw-Node-1 (Acme-Corp)`. This works whenever the home
domain is part of the query, so it is most effective with `--domain all` (or a
profile without a `domain =`, which queries everything).

Licenses still showing `<Unknown>` after that are bound to an element this API
key cannot see in any queried domain (a domain outside your permissions, or a
deleted element). Use `--details` to see the identifying fields the SMC still
has — `binding` (the POS/serial it is bound to), `customer_name`, `features`,
`granted_date`, `proof_of_license` — and match the POS/serial against your
engines. The plain table prints a reminder to stderr when unresolved `<Unknown>`
bindings remain.

### fp license cron — expiry alerting by email

`fp license cron` checks every license's expiration date and, when any expire
within N days (default 30, already-expired always included), emails a table like
the normal license output plus **Customer** and **Days Left** columns (the email
always includes the customer). When nothing is close to
expiry it sends nothing and exits 0 — safe to run unattended.

SMTP settings live in an `[smtp]` section of the same config file:

```ini
[smtp]
host = mail.example.com
port = 587
starttls = true
username = fp-alerts
password = secret
from = fp-alerts@example.com
to = noc@example.com, ale@example.com
```

Every key can be overridden with a flag (`--smtp-host`, `--smtp-port`,
`--smtp-user`, `--smtp-password`, `--starttls`, `--from`, `--to`). Port 465
implies implicit TLS. The email is multipart: aligned-text table plus an HTML
table.

```bash
# Preview what would be sent, without sending
fp license cron --dry-run

# Different threshold, one customer only
fp license cron --days 60 --domain Acme-Corp

# Crontab: every Monday 08:00, using the forcepoint venv
0 8 * * 1 /home/ale/forcepoint/bin/fp license cron
```

Rows are sorted most-urgent first (expired, then fewest days left). Licenses
with no expiration date (perpetual) are skipped; unparsable dates are reported
to stderr. Exit code is non-zero on SMC/SMTP errors, so cron's own mail catches
failures.

#### cron flags

| Flag | Description |
|---|---|
| `--days N` | Alert threshold in days (default: 30). |
| `--domain NAME` | Domain(s) to query: repeatable or comma-separated; `all` = every visible domain. Default: profile domain, or all domains if the profile has none. |
| `--to ADDR` | Recipient (repeatable; overrides config `to =`). |
| `--from ADDR` | Sender (overrides config `from =`). |
| `--smtp-host / --smtp-port / --smtp-user / --smtp-password / --starttls` | SMTP overrides. |
| `--dry-run` | Print the email to stdout instead of sending. |
| `--profile / --config / --url / --api-key / --api-version / --insecure` | As in `fp license`. |

### license flags

| Flag | Description |
|---|---|
| `--domain NAME` | Domain(s) to query: repeatable or comma-separated; `all` = every visible domain. Default: profile domain, or all domains if the profile has none. |
| `--profile NAME` | Config profile/section to use (default: `default`, i.e. `[smc]`). |
| `--config PATH` | Path to config file (default: `~/.forcepoint/forcepoint.conf`). |
| `--url URL` | SMC API URL. |
| `--api-key KEY` | SMC API key. |
| `--api-version VER` | SMC API version override. |
| `--insecure` | Disable TLS certificate verification. Only for lab/self-signed setups. |
| `--show-customer` | Add the Customer column to table/CSV output. |
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

Domain selection works exactly like `fp license`: the profile's domain by
default (or every visible domain if the profile has none), `--domain` for an
explicit choice (`all`, comma-separated list, or repeated flags), and
`fp changes pending show domains` lists the choices. Rows not yet approved are
highlighted in yellow. Engines whose type doesn't support pending changes are
silently skipped.

```bash
# Profile domain (or everything, if the profile has no domain)
fp changes pending

# Everything, everywhere
fp changes pending --domain all

# One customer domain, CSV for the change-review ticket
fp changes pending --domain Acme-Corp --csv > pending-acme.csv

# Unapproved only, via jq
fp changes pending --json | jq -c 'select(.approved_on == "")'
```

### changes pending flags

| Flag | Description |
|---|---|
| `--domain NAME` | Domain(s) to query: repeatable or comma-separated; `all` = every visible domain. Default: profile domain, or all domains if the profile has none. |
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

Read-only views of SMC state. Subcommands: `domains` and `metrics`.

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

### fp show metrics

One row per firewall node: Domain, Node, then the utilization metrics. By
default only CPU/load/memory/usage-style columns are shown (matched by name,
so whatever utilization values your SMC version reports appear automatically);
`--details` switches to the full set — every appliance metric (anti-malware
database, filesystem sizes, logging subsystem, GTI/MLC connection, ...) plus
the node status attributes (status, state, version, dyn_up, installed
policy, ...).

```
$ fp show metrics
fp show: profile=default url=https://smc.acme.example:8082 domains=Acme-Corp
Domain     Node         File Systems Data Usage  File Systems Spool Usage  File Systems Tmp Usage  File Systems Swap Usage
---------------------------------------------------------------------------------------------------------------------------
Acme-Corp  fw-1 node 1  11.6%                    2.8%                      0.1%                    28.6%
Acme-Corp  fw-1 node 2  12.9%                    2.9%                      0.1%                    28.7%
```

```bash
# Profile domain (default), compact utilization table
fp show metrics

# All domains, every metric + node status attributes
fp show metrics --domain all --details

# CSV / JSON for monitoring pipelines
fp show metrics --details --csv > metrics.csv
fp show metrics --json | jq 'select(.["File Systems Spool Usage"] // "0" | rtrimstr("%") | tonumber > 80)'
```

Domain selection follows the usual rules (profile domain by default, `--domain`
with `all` or comma-separated lists). Nodes that fail to report (offline,
unsupported) are listed with empty metric cells and the error goes to stderr.

> **Note on CPU/memory/traffic:** the SMC REST API does not expose the
> CPU/memory/throughput counters used by the Management Client's graphs (those
> live in the Log Server's statistical store, which has no public API). If your
> SMC version reports such values through the appliance status resource, they
> appear here automatically; otherwise this table is limited to what the API
> provides.

#### metrics flags

| Flag | Description |
|---|---|
| `--domain NAME` | Domain(s) to query: repeatable or comma-separated; `all` = every visible domain. Default: profile domain, or all domains if the profile has none. |
| `-d, --details` | Show every appliance metric plus node status attributes, instead of only the utilization columns. |
| `--json` | Newline-delimited JSON, one object per node. |
| `--csv` | CSV with header row. |
| `--profile / --config / --url / --api-key / --api-version / --insecure` | As in the other commands. |

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
