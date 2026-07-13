import csv
import json
import sys
import warnings

import urllib3
from smc import session
from smc.administration.system import System
from smc.api.exceptions import SMCException

from fp import show
from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from fp.output import color_enabled, strip_trailing_padding

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
        help="limit to this administrative domain (repeatable; 'all' or omitted = "
             "all domains visible to the API key; `fp show domains` lists the choices)",
    )
    p.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    p.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    p.add_argument("--api-key", help="SMC API key")
    p.add_argument("--api-version", help="SMC API version override")
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    p.add_argument(
        "-d", "--details", action="store_true",
        help="show every field the SMC returns per license (binding serial/POS, "
             "features, customer name, ...) - useful to identify licenses whose "
             "binding shows as <Unknown>",
    )
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit newline-delimited JSON instead of table text")
    fmt.add_argument("--csv", action="store_true", help="emit CSV (with header) instead of table text")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.set_defaults(func=run)

    nested = p.add_subparsers(metavar="", required=False)
    show.attach(nested)
    return p


# raw License attributes already represented by the standard columns
_MAPPED_ATTRS = {
    "license_id", "type", "binding_state", "bound_to",
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

    rows.sort(key=lambda r: (r["domain"].lower(), r["type"].lower(), r["license_id"]))
    return rows, errors


def _status_color(row):
    status = row["status"].lower()
    if "bound" in status and "unbound" not in status:
        return None
    if "unassigned" in status or "unbound" in status:
        return YELLOW
    return None


def _all_fieldnames(rows):
    """Standard columns first, then every extra detail field seen in any row."""
    names = [k for k, _ in COLUMNS]
    extras = sorted({k for r in rows for k in r} - set(names))
    return names + extras


def output_csv(rows):
    writer = csv.DictWriter(sys.stdout, fieldnames=_all_fieldnames(rows), restval="")
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


def output_table(rows, use_color):
    keys = [k for k, _ in COLUMNS]
    headers = {k: h for k, h in COLUMNS}
    widths = {k: max(len(headers[k]), *(len(r[k]) for r in rows)) for k in keys}

    header_line = "  ".join(headers[k].ljust(widths[k]) for k in keys)
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        line = "  ".join(row[k].ljust(widths[k]) for k in keys)
        color = _status_color(row) if use_color else None
        if color:
            line = color + line.rstrip() + RESET
        print(strip_trailing_padding(line))


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

    print(
        "%s: profile=%s url=%s domains=%s"
        % (PROG, args.profile, config.url, ",".join(args.domain) if args.domain else "all"),
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

    if rows:
        if args.json:
            for row in rows:
                print(json.dumps(row, separators=(",", ":")))
        elif args.csv:
            output_csv(rows)
        elif args.details:
            output_details(rows, color_enabled(args.no_color))
        else:
            output_table(rows, color_enabled(args.no_color))
            unknown = sum(1 for r in rows if "unknown" in r["bound_to"].lower())
            if unknown:
                print(
                    "%s: %d license(s) bound to <Unknown> - the bound element is "
                    "not visible from that domain (bound in another domain, or "
                    "deleted). Re-run with --details to see the binding serial/POS "
                    "and other identifying fields." % (PROG, unknown),
                    file=sys.stderr,
                )
    elif not errors:
        print("%s: no licenses found" % PROG, file=sys.stderr)

    return 1 if errors else 0
