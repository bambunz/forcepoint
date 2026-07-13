import csv
import json
import sys
import warnings

import urllib3
from smc import session
from smc.core.engine import Engine
from smc.api.exceptions import SMCException, UnsupportedEngineFeature

from fp import show
from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from fp.output import color_enabled, strip_trailing_padding

PROG = "fp changes"

COLUMNS = [
    ("domain", "Domain"),
    ("engine", "Engine"),
    ("changed_on", "Changed On"),
    ("event_type", "Event Type"),
    ("element", "Element"),
    ("modifier", "Modifier"),
    ("approved_on", "Approved On"),
    ("approver", "Approver"),
]

RESET = "\x1b[0m"
YELLOW = "\x1b[33m"

# Same vendored SSLAdapter deprecation noise as logtail; see fp/logtail.py.
warnings.filterwarnings("ignore", message=r".*ssl_version.*", category=FutureWarning)


def add_parser(sub):
    p = sub.add_parser(
        "changes",
        help="inspect configuration changes on the SMC",
        description="Inspect configuration changes on the SMC.",
    )
    ssub = p.add_subparsers(dest="changes_what", metavar="WHAT", required=True)

    pending = ssub.add_parser(
        "pending",
        help="show changes pending approval/commit on each engine, per admin domain",
        description="Show configuration changes that are pending (not yet "
                    "approved/committed) on each engine, for all administrative "
                    "domains or a chosen subset. Requires SMC >= 6.2.",
    )
    pending.add_argument(
        "--domain", action="append",
        help="administrative domain(s) to query, repeatable or comma-separated "
             "('domain1,domain2'); 'all' = every domain visible to the API key. "
             "Default: the profile's domain, or all domains if the profile has "
             "none. `fp show domains` lists the choices",
    )
    pending.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    pending.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    pending.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    pending.add_argument("--api-key", help="SMC API key")
    pending.add_argument("--api-version", help="SMC API version override")
    pending.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    fmt = pending.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit newline-delimited JSON instead of table text")
    fmt.add_argument("--csv", action="store_true", help="emit CSV (with header) instead of table text")
    pending.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    pending.set_defaults(func=run_pending)

    nested = pending.add_subparsers(metavar="", required=False)
    show.attach(nested)
    return p


def _change_row(domain, engine_name, record):
    return {
        "domain": domain,
        "engine": engine_name,
        "changed_on": str(record.changed_on or ""),
        "event_type": str(record.event_type or ""),
        "element": str(record.element_name or record.element or ""),
        "modifier": str(record.modifier or ""),
        "approved_on": str(record.approved_on or ""),
        "approver": str(record.approver or ""),
    }


def collect(args, config):
    """Log in, walk the requested domains and their engines, and return
    (rows, errors)."""
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
                for engine in Engine.objects.all():
                    try:
                        for record in engine.pending_changes:
                            rows.append(_change_row(domain, engine.name, record))
                    except UnsupportedEngineFeature:
                        continue  # engine type predates pending changes (SMC < 6.2)
                    except SMCException as exc:
                        errors.append("%s/%s: %s" % (domain, engine.name, exc))
            except SMCException as exc:
                errors.append("%s: %s" % (domain, exc))
    finally:
        try:
            session.logout()
        except Exception:
            pass

    rows.sort(key=lambda r: (r["domain"].lower(), r["engine"].lower(), r["changed_on"]))
    return rows, errors


def output_csv(rows):
    writer = csv.DictWriter(sys.stdout, fieldnames=[k for k, _ in COLUMNS])
    writer.writeheader()
    writer.writerows(rows)


def output_table(rows, use_color):
    keys = [k for k, _ in COLUMNS]
    headers = {k: h for k, h in COLUMNS}
    widths = {k: max(len(headers[k]), *(len(r[k]) for r in rows)) for k in keys}

    header_line = "  ".join(headers[k].ljust(widths[k]) for k in keys)
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        line = "  ".join(row[k].ljust(widths[k]) for k in keys)
        if use_color and not row["approved_on"]:
            line = YELLOW + line.rstrip() + RESET
        print(strip_trailing_padding(line))


def run_pending(args):
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

    if rows:
        if args.json:
            for row in rows:
                print(json.dumps(row, separators=(",", ":")))
        elif args.csv:
            output_csv(rows)
        else:
            output_table(rows, color_enabled(args.no_color))
    elif not errors:
        print("%s: no pending changes" % PROG, file=sys.stderr)

    return 1 if errors else 0
