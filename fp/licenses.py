import csv
import html
import json
import smtplib
import sys
import warnings
from datetime import date, datetime, timezone
from email.message import EmailMessage

import urllib3
from smc import session
from smc.administration.system import System
from smc.api.exceptions import SMCException

from fp import show
from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config, load_smtp_config
from fp.output import color_enabled, table_lines

PROG = "fp license"

SHARED_DOMAIN = show.SHARED_DOMAIN

COLUMNS = [
    ("domain", "Domain"),
    ("license_id", "License Id"),
    ("type", "Type"),
    ("status", "Status"),
    ("bound_to", "Bound To"),
    ("expiration_date", "Expires"),
    ("maintenance_expires", "Maintenance Expires"),
]

CUSTOMER_COLUMN = ("customer", "Customer")


def _columns(show_customer):
    cols = list(COLUMNS)
    if show_customer:
        cols.insert(1, CUSTOMER_COLUMN)
    return cols


# the cron email always includes the customer
CRON_COLUMNS = _columns(True) + [("days_left", "Days Left")]

RESET = "\x1b[0m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"

# Same vendored SSLAdapter deprecation noise as logtail; see fp/logtail.py.
warnings.filterwarnings("ignore", message=r".*ssl_version.*", category=FutureWarning)


def add_parser(sub):
    p = sub.add_parser(
        "license",
        aliases=["licenses"],
        help="list SMC licenses with type and status, per admin domain",
        description="List SMC licenses (type, status, binding, expiry) for all "
                    "administrative domains or a chosen subset.",
    )
    p.add_argument(
        "--domain", action="append",
        help="administrative domain(s) to query, repeatable or comma-separated "
             "('domain1,domain2'); 'all' = every domain visible to the API key. "
             "Default: the profile's domain, or all domains if the profile has "
             "none. `fp show domains` lists the choices",
    )
    p.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    p.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    p.add_argument("--api-key", help="SMC API key")
    p.add_argument("--api-version", help="SMC API version override")
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    p.add_argument(
        "--show-customer", action="store_true",
        help="add the Customer column to table/CSV output",
    )
    p.add_argument(
        "-d", "--details", action="store_true",
        help="show every field the SMC returns per license (binding serial/POS, "
             "features, customer name, ...) - useful to identify licenses whose "
             "binding shows as <Unknown>",
    )
    p.add_argument(
        "--unassigned", action="store_true",
        help="list only licenses not bound to an engine (binding state "
             "Unassigned/Unbound) - i.e. the spare licenses available to assign",
    )
    p.add_argument(
        "--per-domain", action="store_true",
        help="emit one row per queried domain instead of one row per license. "
             "The SMC license list is management-server-wide, so every domain "
             "returns the same licenses; by default each is reported once, "
             "attributed to the domain owning the bound element",
    )
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit newline-delimited JSON instead of table text")
    fmt.add_argument("--csv", action="store_true", help="emit CSV (with header) instead of table text")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.set_defaults(func=run)

    nested = p.add_subparsers(metavar="", required=False)
    show.attach(nested)
    _add_cron_parser(nested)
    return p


def _add_cron_parser(nested):
    c = nested.add_parser(
        "cron",
        help="email a report of licenses expiring within N days (for crontab)",
        description="Check license expiration dates and email a table (like the "
                    "normal license output) of those expiring within N days. "
                    "The license list is management-server-wide, so each "
                    "license is reported once even when several domains are "
                    "queried. Licenses still bound to <Unknown> are skipped unless "
                    "--include-unknown is given. Sends nothing when no license "
                    "is close to expiry. SMTP settings come from the [smtp] "
                    "section of the config file, overridable with flags.",
    )
    c.add_argument(
        "--days", type=int, default=30,
        help="alert threshold in days (default: %(default)s; already-expired "
             "licenses are always included)",
    )
    c.add_argument(
        "--domain", action="append",
        help="administrative domain(s) to check, repeatable or comma-separated; "
             "'all' = every visible domain. Default: the profile's domain, or "
             "all domains if the profile has none",
    )
    c.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    c.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    c.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    c.add_argument("--api-key", help="SMC API key")
    c.add_argument("--api-version", help="SMC API version override")
    c.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    c.add_argument("--to", action="append", help="recipient address (repeatable; overrides config 'to =')")
    c.add_argument("--from", dest="sender", help="sender address (overrides config 'from =')")
    c.add_argument("--smtp-host", help="SMTP server (overrides config 'host =')")
    c.add_argument("--smtp-port", type=int, help="SMTP port (overrides config 'port ='; 465 implies TLS)")
    c.add_argument("--smtp-user", help="SMTP username (overrides config 'username =')")
    c.add_argument("--smtp-password", help="SMTP password (overrides config 'password =')")
    c.add_argument("--starttls", action="store_true", default=None,
                   help="use STARTTLS (overrides config 'starttls =')")
    c.add_argument(
        "--include-unknown", action="store_true",
        help="also report licenses still bound to <Unknown> after cross-domain "
             "resolution (excluded by default: the bound element is not visible "
             "to this API key, so the alert is not actionable)",
    )
    c.add_argument("--dry-run", action="store_true",
                   help="print the email to stdout instead of sending it")
    c.set_defaults(func=run_cron, details=False)
    return c


# raw License attributes already represented by the standard columns
_MAPPED_ATTRS = {
    "license_id", "type", "binding_state", "bound_to", "customer_name",
    "expiration_date", "maintenance_contract_expires_date",
}


def _flatten(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _license_row(domain, lic, details=False):
    row = {
        "domain": domain,
        "customer": str(lic.customer_name or ""),
        "license_id": str(lic.license_id or ""),
        "type": str(lic.type or ""),
        "status": str(lic.binding_state or ""),
        "bound_to": str(lic.bound_to or ""),
        "expiration_date": str(lic.expiration_date or ""),
        "maintenance_expires": str(lic.maintenance_contract_expires_date or ""),
    }
    if details:
        # everything else the SMC returned for this license, verbatim
        for key in sorted(vars(lic)):
            if key in _MAPPED_ATTRS or key.startswith("_"):
                continue
            row[key] = _flatten(vars(lic)[key])
    return row


def collect(args, config):
    """Log in, walk the requested domains, and return (rows, errors)."""
    rows, errors = [], []

    session.login(
        url=config.url,
        api_key=config.api_key,
        verify=config.verify,
        domain=show.initial_login_domain(args.domain, config),
        api_version=config.api_version,
        timeout=config.timeout,
    )

    try:
        domains = show.select_domains(args.domain, config, PROG)
        for domain in domains:
            try:
                session.switch_domain(domain)
                for lic in System().licenses:
                    rows.append(_license_row(domain, lic, details=args.details))
            except SMCException as exc:
                errors.append("%s: %s" % (domain, exc))
    finally:
        try:
            session.logout()
        except Exception:
            pass

    _resolve_cross_domain(rows)
    rows.sort(key=lambda r: (r["domain"].lower(), r["type"].lower(), r["license_id"]))
    return rows, errors


def _is_unknown(bound_to):
    return "unknown" in bound_to.lower()


def _resolve_cross_domain(rows):
    """Fill <Unknown> bindings with the element name found in another domain.

    The SMC resolves a license's bound element only in that element's home
    domain; everywhere else the same license shows <Unknown>. Since the
    license list is management-server-wide, a multi-domain query usually has
    the real name in the home domain's row - copy it over, annotated with the
    domain it was resolved in.
    """
    known = {}
    for row in rows:
        if row["license_id"] and row["bound_to"] and not _is_unknown(row["bound_to"]):
            known.setdefault(row["license_id"], (row["bound_to"], row["domain"]))
    for row in rows:
        if row["bound_to"] and _is_unknown(row["bound_to"]) and row["license_id"] in known:
            name, domain = known[row["license_id"]]
            row["bound_to"] = "%s (%s)" % (name, domain)


def _is_unassigned(status):
    """True for a license not bound to an engine. The SMC reports this as
    'Unassigned'; 'Unbound' is accepted too, matching how _status_color
    already groups the two."""
    status = status.lower()
    return "unassigned" in status or "unbound" in status


def dedupe_licenses(rows):
    """Collapse the per-domain copies of each license into one row.

    System().licenses is management-server-wide, not per-domain: querying N
    domains returns every license N times (15 domains x 63 licenses = 945
    rows here). Keep one row per license id.

    Prefer the row from the domain that owns the bound element, which is the
    one the SMC resolved natively - _resolve_cross_domain only ever appends
    " (domain)" to the other copies, so the owning domain's binding is the
    strictly shortest. Domain name breaks ties (unbound licenses, which have
    no owning domain and an empty binding everywhere).
    """
    best, bindings, copies = {}, {}, {}
    for row in rows:
        key = row["license_id"] or id(row)  # unidentified rows never collapse
        bindings.setdefault(key, set()).add(row["bound_to"])
        copies[key] = copies.get(key, 0) + 1
        current = best.get(key)
        if current is None or (len(row["bound_to"]), row["domain"]) < (
                len(current["bound_to"]), current["domain"]):
            best[key] = row

    collapsed = []
    for key, row in best.items():
        # Only a license whose binding resolved differently per domain has an
        # identifiable owner. When every copy reads the same the domain we kept
        # is just the first one queried - true for unbound licenses (empty
        # everywhere) and for elements visible from every domain, such as the
        # Management Server - so do not imply the license belongs to it.
        if copies[key] > 1 and len(bindings[key]) < 2:
            row = dict(row, domain="")
        collapsed.append(row)

    collapsed.sort(key=lambda r: (r["domain"].lower(), r["type"].lower(), r["license_id"]))
    return collapsed


def _status_color(row):
    status = row["status"].lower()
    if "bound" in status and "unbound" not in status:
        return None
    if "unassigned" in status or "unbound" in status:
        return YELLOW
    return None


def _all_fieldnames(rows, columns, details):
    """Selected columns first, then every extra detail field seen in any row.
    Without --details the customer field only appears via --show-customer."""
    names = [k for k, _ in columns]
    extras = {k for r in rows for k in r} - set(names)
    if not details:
        extras.discard("customer")
    return names + sorted(extras)


def output_csv(rows, columns, details):
    writer = csv.DictWriter(sys.stdout, fieldnames=_all_fieldnames(rows, columns, details),
                            restval="", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)


def output_details(rows, use_color):
    for i, row in enumerate(rows):
        if i:
            print()
        title = "%s / %s (%s)" % (row["domain"], row["license_id"], row["type"])
        color = _status_color(row) if use_color else None
        print((color + title + RESET) if color else title)
        print("-" * len(title))
        width = max(len(k) for k in row)
        for key, value in row.items():
            print("  %-*s  %s" % (width + 1, key + ":", value))


def output_table(rows, use_color, columns=None):
    lines = table_lines(rows, columns or COLUMNS)
    print(lines[0])
    print(lines[1])
    for row, line in zip(rows, lines[2:]):
        color = _status_color(row) if use_color else None
        print((color + line + RESET) if color else line)


def _days_left(datestr, today):
    """Parse an SMC expiration date and return days until expiry, or None if
    the value is empty/unparsable (e.g. perpetual licenses)."""
    s = (datestr or "").strip()
    if not s:
        return None
    if s.isdigit() and len(s) >= 12:  # epoch milliseconds
        d = datetime.fromtimestamp(int(s) / 1000, tz=timezone.utc).date()
        return (d - today).days
    try:
        d = datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
    return (d - today).days


def expiring_rows(rows, days, today=None):
    """Annotate rows with days_left and return those expiring within `days`
    (including already expired), plus the count of unparsable dates."""
    today = today or date.today()
    hits, unparsable = [], 0
    for row in rows:
        left = _days_left(row["expiration_date"], today)
        if left is None:
            if row["expiration_date"].strip():
                unparsable += 1
            continue
        if left <= days:
            row = dict(row)
            row["days_left"] = "EXPIRED (%d)" % left if left < 0 else str(left)
            hits.append(row)
    hits.sort(key=lambda r: (int(r["days_left"].split("(")[-1].rstrip(")"))
                             if r["days_left"].startswith("EXPIRED") else int(r["days_left"])))
    return hits, unparsable


def build_email(smtp_cfg, hits, days, url):
    subject = "[fp] %d Forcepoint license(s) expiring within %d days" % (len(hits), days)
    intro = (
        "The following Forcepoint licenses on %s expire within %d days "
        "(or are already expired):" % (url, days)
    )
    lines = table_lines(hits, CRON_COLUMNS)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.sender
    msg["To"] = ", ".join(smtp_cfg.to)
    msg.set_content(intro + "\n\n" + "\n".join(lines) + "\n\n-- \nfp license cron\n")

    cells = "".join(
        "<tr>%s</tr>" % "".join("<td>%s</td>" % html.escape(r.get(k, "")) for k, _ in CRON_COLUMNS)
        for r in hits
    )
    header = "".join("<th align=\"left\">%s</th>" % html.escape(h) for _, h in CRON_COLUMNS)
    msg.add_alternative(
        "<p>%s</p><table border=\"1\" cellpadding=\"4\" cellspacing=\"0\">"
        "<tr>%s</tr>%s</table><p>-- <br>fp license cron</p>"
        % (html.escape(intro), header, cells),
        subtype="html",
    )
    return msg


def send_email(smtp_cfg, msg):
    if smtp_cfg.port == 465:
        server = smtplib.SMTP_SSL(smtp_cfg.host, smtp_cfg.port, timeout=30)
    else:
        server = smtplib.SMTP(smtp_cfg.host, smtp_cfg.port, timeout=30)
    try:
        if smtp_cfg.starttls and smtp_cfg.port != 465:
            server.starttls()
        if smtp_cfg.username:
            server.login(smtp_cfg.username, smtp_cfg.password or "")
        server.send_message(msg)
    finally:
        server.quit()


def run_cron(args):
    try:
        config = load_config(
            profile=args.profile,
            config_path=args.config,
            cli_overrides={
                "url": args.url,
                "api_key": args.api_key,
                "api_version": args.api_version,
                "verify": False if args.insecure else None,
            },
            require_domain=False,
        )
        smtp_cfg = load_smtp_config(
            config_path=args.config,
            cli_overrides={
                "host": args.smtp_host,
                "port": args.smtp_port,
                "username": args.smtp_user,
                "password": args.smtp_password,
                "starttls": args.starttls,
                "from": args.sender,
                "to": args.to,
            },
        )
    except ConfigError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2

    if config.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        rows, errors = collect(args, config)
    except ConfigError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2
    except SMCException as exc:
        print("%s: could not log in to %s: %s" % (PROG, config.url, exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    for err in errors:
        print("%s: error: %s" % (PROG, err), file=sys.stderr)

    rows = dedupe_licenses(rows)

    hits, unparsable = expiring_rows(rows, args.days)
    if unparsable:
        print(
            "%s: warning: %d license(s) have unparsable expiration dates and "
            "were not checked" % (PROG, unparsable),
            file=sys.stderr,
        )

    if not args.include_unknown:
        kept = [h for h in hits if not _is_unknown(h["bound_to"])]
        skipped = len(hits) - len(kept)
        if skipped:
            print(
                "%s: skipped %d expiring license(s) still bound to <Unknown> - "
                "the bound element is not visible to this API key in any queried "
                "domain; pass --include-unknown to report them" % (PROG, skipped),
                file=sys.stderr,
            )
        hits = kept

    if not hits:
        print(
            "%s: %d license(s) checked, none expiring within %d days - no email sent"
            % (PROG, len(rows), args.days),
            file=sys.stderr,
        )
        return 1 if errors else 0

    msg = build_email(smtp_cfg, hits, args.days, config.url)

    if args.dry_run:
        print(msg)
        return 1 if errors else 0

    try:
        send_email(smtp_cfg, msg)
    except (smtplib.SMTPException, OSError) as exc:
        print("%s: sending mail via %s:%s failed: %s"
              % (PROG, smtp_cfg.host, smtp_cfg.port, exc), file=sys.stderr)
        return 1

    print(
        "%s: emailed %d expiring license(s) to %s"
        % (PROG, len(hits), ", ".join(smtp_cfg.to)),
        file=sys.stderr,
    )
    return 1 if errors else 0


def run(args):
    try:
        config = load_config(
            profile=args.profile,
            config_path=args.config,
            cli_overrides={
                "url": args.url,
                "api_key": args.api_key,
                "api_version": args.api_version,
                "verify": False if args.insecure else None,
            },
            require_domain=False,
        )
    except ConfigError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2

    if config.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    requested = show.normalize_domains(args.domain)
    domains_label = ",".join(requested) if requested else (config.domain or "all")
    print(
        "%s: profile=%s url=%s domains=%s" % (PROG, args.profile, config.url, domains_label),
        file=sys.stderr,
    )

    try:
        rows, errors = collect(args, config)
    except ConfigError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2
    except SMCException as exc:
        print("%s: could not log in to %s: %s" % (PROG, config.url, exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    for err in errors:
        print("%s: error: %s" % (PROG, err), file=sys.stderr)

    if not args.per_domain:
        rows = dedupe_licenses(rows)
    if args.unassigned:
        rows = [r for r in rows if _is_unassigned(r["status"])]

    if rows:
        cols = _columns(args.show_customer)
        if args.json:
            for row in rows:
                print(json.dumps(row, separators=(",", ":")))
        elif args.csv:
            output_csv(rows, cols, args.details)
        elif args.details:
            output_details(rows, color_enabled(args.no_color))
        else:
            output_table(rows, color_enabled(args.no_color), cols)
            unknown = sum(1 for r in rows if _is_unknown(r["bound_to"]))
            if unknown:
                print(
                    "%s: %d license(s) still bound to <Unknown> after cross-domain "
                    "resolution - the bound element is not visible to this API key "
                    "in any queried domain (restricted domain, or deleted element). "
                    "Re-run with --details to see the binding serial/POS and other "
                    "identifying fields." % (PROG, unknown),
                    file=sys.stderr,
                )
    elif not errors:
        print("%s: no %slicenses found" % (PROG, "unassigned " if args.unassigned else ""),
              file=sys.stderr)

    return 1 if errors else 0
