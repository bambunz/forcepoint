import json
import sys
import warnings

import urllib3
from smc import session
from smc.administration.system import AdminDomain, System
from smc.api.exceptions import SMCException

from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from fp.output import color_enabled, strip_trailing_padding

PROG = "fp license"

SHARED_DOMAIN = "Shared Domain"

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
        help="limit to this administrative domain (repeatable; default: all domains "
             "visible to the API key)",
    )
    p.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    p.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    p.add_argument("--api-key", help="SMC API key")
    p.add_argument("--api-version", help="SMC API version override")
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    p.add_argument("--json", action="store_true", help="emit newline-delimited JSON instead of table text")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.set_defaults(func=run)
    return p


def _license_row(domain, lic):
    return {
        "domain": domain,
        "license_id": str(lic.license_id or ""),
        "type": str(lic.type or ""),
        "status": str(lic.binding_state or ""),
        "bound_to": str(lic.bound_to or ""),
        "expiration_date": str(lic.expiration_date or ""),
        "maintenance_expires": str(lic.maintenance_contract_expires_date or ""),
    }


def _domains_to_query(args, config):
    """Return the list of domain names to inspect.

    Explicit --domain flags win. Otherwise enumerate every AdminDomain the
    API key can see (requires Shared Domain visibility); if that enumeration
    is not permitted, fall back to the profile's configured domain.
    """
    if args.domain:
        return args.domain

    try:
        names = sorted((d.name for d in AdminDomain.objects.all()), key=str.lower)
        if names:
            return names
    except SMCException as exc:
        print(
            "%s: cannot enumerate admin domains (%s) - falling back to the "
            "profile domain; pass --domain to be explicit" % (PROG, exc),
            file=sys.stderr,
        )

    if config.domain:
        return [config.domain]
    raise ConfigError(
        "could not determine which domains to query - the API key cannot "
        "enumerate domains and no domain is set in the profile; pass --domain"
    )


def collect(args, config):
    """Log in, walk the requested domains, and return (rows, errors)."""
    rows, errors = [], []

    initial_domain = args.domain[0] if args.domain else (config.domain or SHARED_DOMAIN)
    session.login(
        url=config.url,
        api_key=config.api_key,
        verify=config.verify,
        domain=initial_domain,
        api_version=config.api_version,
        timeout=config.timeout,
    )

    try:
        domains = _domains_to_query(args, config)
        for domain in domains:
            try:
                session.switch_domain(domain)
                for lic in System().licenses:
                    rows.append(_license_row(domain, lic))
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
        else:
            output_table(rows, color_enabled(args.no_color))
    elif not errors:
        print("%s: no licenses found" % PROG, file=sys.stderr)

    return 1 if errors else 0
