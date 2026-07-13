import json
import sys
import warnings

import urllib3
from smc import session
from smc.administration.system import AdminDomain
from smc.api.exceptions import SMCException

from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config

PROG = "fp show"

SHARED_DOMAIN = "Shared Domain"

# Pseudo-domain accepted by `--domain` in the other subcommands: licenses
# expands it to every enumerable domain, logtail maps it to Shared Domain
# (whose log view spans all domains, permissions allowing).
ALL = "all"

# Same vendored SSLAdapter deprecation noise as logtail; see fp/logtail.py.
warnings.filterwarnings("ignore", message=r".*ssl_version.*", category=FutureWarning)


def _add_connection_flags(p):
    p.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    p.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    p.add_argument("--api-key", help="SMC API key")
    p.add_argument("--api-version", help="SMC API version override")
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    p.add_argument("--json", action="store_true", help="emit a JSON array instead of one name per line")


def attach(sub):
    """Add the `show` subcommand (with its own subcommands) to any subparsers
    object — used at top level (`fp show`) and nested under logtail/license
    (`fp logtail show ...`, `fp license show ...`)."""
    p = sub.add_parser(
        "show",
        help="show selectable values (e.g. domains you can pass to --domain)",
        description="Show selectable values for other fp commands.",
    )
    ssub = p.add_subparsers(dest="show_what", metavar="WHAT", required=True)

    d = ssub.add_parser(
        "domains",
        help="list administrative domains selectable with --domain (includes '%s')" % ALL,
        description="List the administrative domains this API key can use with "
                    "--domain, plus the pseudo-domain '%s'." % ALL,
    )
    _add_connection_flags(d)
    d.set_defaults(func=run_domains)
    return p


def enumerate_domains():
    """Return the sorted list of admin domain names visible to the session."""
    return sorted((d.name for d in AdminDomain.objects.all()), key=str.lower)


def select_domains(requested, config, prog):
    """Shared --domain resolution for the multi-domain subcommands.

    Explicit --domain values win, except that 'all' (alone or mixed in, or no
    --domain at all) means enumerate every AdminDomain the API key can see
    (requires Shared Domain visibility). If enumeration is not permitted,
    fall back to the profile's configured domain.
    """
    if requested and not any(d.lower() == ALL for d in requested):
        return list(requested)

    try:
        names = enumerate_domains()
        if names:
            return names
    except SMCException as exc:
        print(
            "%s: cannot enumerate admin domains (%s) - falling back to the "
            "profile domain; pass --domain to be explicit" % (prog, exc),
            file=sys.stderr,
        )

    if config.domain:
        return [config.domain]
    raise ConfigError(
        "could not determine which domains to query - the API key cannot "
        "enumerate domains and no domain is set in the profile; pass --domain"
    )


def initial_login_domain(requested, config):
    """Domain to open the first session in, before select_domains() runs."""
    explicit = [d for d in (requested or []) if d.lower() != ALL]
    if requested and not explicit:
        # only 'all' was given: enumeration needs Shared Domain
        return SHARED_DOMAIN
    return explicit[0] if explicit else (config.domain or SHARED_DOMAIN)


def run_domains(args):
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

    print("%s: profile=%s url=%s" % (PROG, args.profile, config.url), file=sys.stderr)

    try:
        session.login(
            url=config.url,
            api_key=config.api_key,
            verify=config.verify,
            domain=config.domain or SHARED_DOMAIN,
            api_version=config.api_version,
            timeout=config.timeout,
        )
    except SMCException as exc:
        print("%s: could not log in to %s: %s" % (PROG, config.url, exc), file=sys.stderr)
        return 1

    try:
        try:
            names = enumerate_domains()
        except SMCException as exc:
            print(
                "%s: cannot enumerate admin domains (%s) - the API key likely "
                "lacks Shared Domain visibility" % (PROG, exc),
                file=sys.stderr,
            )
            names = [config.domain] if config.domain else []
    finally:
        try:
            session.logout()
        except Exception:
            pass

    names = [ALL] + names
    if args.json:
        print(json.dumps(names))
    else:
        for name in names:
            print(name)
    return 0
