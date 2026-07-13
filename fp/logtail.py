import json
import re
import signal
import sys
import time
import warnings

import urllib3
from smc import session
from smc.api.exceptions import SMCException
from smc_monitoring.models.constants import LogField
from smc_monitoring.models.formatters import RawDictFormat, TableFormat
from smc_monitoring.monitors.logs import LogQuery

from fp import show
from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from fp.filters import FilterError, apply_filters, build_filters
from fp.output import color_enabled, colorize, grep_lines, strip_trailing_padding

PROG = "fp logtail"
DEFAULT_LINES = 10

# fp-NGFW-SMC-python's SSLAdapter hardcodes urllib3's deprecated ssl_version=
# kwarg on every connection; this is inside the vendored dependency, not
# something we or the user can configure away.
warnings.filterwarnings("ignore", message=r".*ssl_version.*", category=FutureWarning)

# The vendored smc_monitoring websocket protocol catches KeyboardInterrupt itself
# and just ends the stream generator cleanly, so it never reaches our code as an
# exception. We register our own SIGINT handler and poll this flag instead of
# relying on KeyboardInterrupt propagating out of the library.
_stop_requested = False


def _handle_sigint(signum, frame):
    global _stop_requested
    _stop_requested = True


def add_parser(sub):
    p = sub.add_parser(
        "logtail",
        help="tail(1)-style viewer for SMC logs (live or stored)",
        description="tail(1)-style viewer for Forcepoint NGFW SMC logs",
    )
    p.add_argument(
        "-n", "--lines", type=int, default=DEFAULT_LINES,
        help="show last N stored records (default: %(default)s; 0 skips the historical dump)",
    )
    p.add_argument(
        "-f", "--follow", action="store_true",
        help="keep streaming new records after the initial dump, like tail -f",
    )
    p.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    p.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    p.add_argument("--api-key", help="SMC API key")
    p.add_argument(
        "--domain",
        help="SMC administrative domain (required - via flag, FP_DOMAIN, or config 'domain ='; "
             "prevents accidentally mixing logs across customers/domains). "
             "'all' streams the Shared Domain view, which spans every domain "
             "your permissions allow; `fp show domains` lists the choices",
    )
    p.add_argument("--api-version", help="SMC API version override")
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    p.add_argument("--json", action="store_true", help="emit newline-delimited JSON instead of table text")
    p.add_argument("--fields", help="comma-separated LogField names to display, e.g. TIMESTAMP,SRC,DST,ACTION")
    p.add_argument("--timezone", help="timezone for timestamps, e.g. CST or Europe/Helsinki")
    p.add_argument(
        "--severity", action="append", choices=["info", "low", "high", "critical"],
        help="filter by alert severity (repeatable)",
    )
    p.add_argument(
        "--action", action="append",
        choices=["allow", "permit", "discard", "block", "refuse", "terminate"],
        help="filter by rule action (repeatable)",
    )
    p.add_argument("--src", action="append", help="filter by source IP (repeatable)")
    p.add_argument("--dst", action="append", help="filter by destination IP (repeatable)")
    p.add_argument("--sender", action="append", help="filter by sending engine IP / NODEID (repeatable)")
    p.add_argument("--service", action="append", help="filter by service, e.g. TCP/443 (repeatable)")
    p.add_argument(
        "--expr",
        help="raw SMC filter expression (Logs view -> right click a field -> Show Filter Expression)",
    )
    p.add_argument("--grep", help="client-side regex applied to each output line before printing")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.add_argument(
        "--max-backoff", type=int, default=30,
        help="max seconds between reconnect attempts in follow mode (default: %(default)s)",
    )
    p.set_defaults(func=run)

    nested = p.add_subparsers(metavar="", required=False)
    show.attach(nested)
    return p


def build_query(args):
    query = LogQuery(fetch_size=args.lines if args.lines > 0 else None)

    if args.timezone:
        query.format.timezone(args.timezone)

    if args.fields:
        try:
            ids = [getattr(LogField, name.strip().upper()) for name in args.fields.split(",")]
        except AttributeError as exc:
            raise FilterError("unknown field name in --fields (%s)" % exc)
        query.format.field_ids(ids)

    if args.json:
        query.format.field_format("name")

    apply_filters(query, build_filters(args))
    return query


def render_stored(query, records, args):
    if not records:
        return ""

    if args.json:
        lines = [json.dumps(r, separators=(",", ":")) for r in records]
        text = "\n".join(lines) + ("\n" if lines else "")
    else:
        text = TableFormat(query).formatted(list(records))

    if not args.json:
        text = strip_trailing_padding(text)
    if args.grep:
        text = grep_lines(text, re.compile(args.grep))
    if not args.json and color_enabled(args.no_color):
        text = colorize(text)
    return text


def print_stored(query, args):
    if args.lines <= 0:
        return
    records = []
    for batch in query.fetch_raw():
        records.extend(batch)
        if _stop_requested:
            break
    records.reverse()  # SMC returns newest-first; tail shows oldest-to-newest
    text = render_stored(query, records, args)
    if text:
        sys.stdout.write(text)
        sys.stdout.flush()


def follow(query, args):
    grep_re = re.compile(args.grep) if args.grep else None
    use_color = color_enabled(args.no_color)
    backoff = 1

    while not _stop_requested:
        try:
            if args.json:
                for batch in query.fetch_live(formatter=RawDictFormat):
                    backoff = 1
                    for record in batch:
                        line = json.dumps(record, separators=(",", ":"))
                        if grep_re and not grep_re.search(line):
                            continue
                        print(line, flush=True)
                    if _stop_requested:
                        break
            else:
                for text in query.fetch_live(formatter=TableFormat):
                    backoff = 1
                    text = strip_trailing_padding(text)
                    if grep_re:
                        text = grep_lines(text, grep_re)
                    if use_color:
                        text = colorize(text)
                    if text:
                        sys.stdout.write(text)
                        sys.stdout.flush()
                    if _stop_requested:
                        break
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if _stop_requested:
                break
            print("%s: stream error (%s), reconnecting in %ss..." % (PROG, exc, backoff), file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, args.max_backoff)


def _connection_hint(exc):
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "SSLError" in text:
        return (
            "TLS certificate verification failed. If this SMC uses a self-signed or "
            "internal CA certificate, either set 'verify = /path/to/ca-bundle.pem' in "
            "the config file, or pass --insecure (only on a trusted network)."
        )
    return None


def run(args):
    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        config = load_config(
            profile=args.profile,
            config_path=args.config,
            cli_overrides={
                "url": args.url,
                "api_key": args.api_key,
                "domain": args.domain,
                "api_version": args.api_version,
                "verify": False if args.insecure else None,
            },
        )
    except ConfigError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2

    if config.domain and config.domain.lower() == show.ALL:
        config.domain = show.SHARED_DOMAIN
        print(
            "%s: --domain all -> streaming the %s view, which spans every "
            "domain your permissions allow" % (PROG, show.SHARED_DOMAIN),
            file=sys.stderr,
        )

    if config.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        query = build_query(args)
    except FilterError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2

    print(
        "%s: profile=%s domain=%s url=%s" % (PROG, args.profile, config.domain, config.url),
        file=sys.stderr,
    )

    try:
        session.login(
            url=config.url,
            api_key=config.api_key,
            verify=config.verify,
            domain=config.domain,
            api_version=config.api_version,
            timeout=config.timeout,
        )
    except SMCException as exc:
        print("%s: could not log in to %s: %s" % (PROG, config.url, exc), file=sys.stderr)
        hint = _connection_hint(exc)
        if hint:
            print("%s: %s" % (PROG, hint), file=sys.stderr)
        return 1
    except Exception as exc:
        print("%s: unexpected error connecting to %s: %s" % (PROG, config.url, exc), file=sys.stderr)
        return 1

    try:
        print_stored(query, args)
        if args.follow:
            follow(query, args)
    except KeyboardInterrupt:
        pass
    except SMCException as exc:
        print("%s: SMC error: %s" % (PROG, exc), file=sys.stderr)
        return 1
    finally:
        session.logout()

    return 0
