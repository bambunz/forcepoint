import csv
import json
import re
import sys
import warnings

import urllib3
from smc import session
from smc.administration.system import AdminDomain
from smc.administration.user_auth.servers import ActiveDirectoryServer, LDAPServer
from smc.api.exceptions import SMCException

from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from fp.output import table_lines

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
    p.add_argument("--json", action="store_true", help="emit JSON instead of text output")


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

    m = ssub.add_parser(
        "metrics",
        help="per-node utilization metrics, one row per firewall node",
        description="Show one row per firewall node. By default only "
                    "utilization metrics (CPU/load/memory/usage-style values, "
                    "as far as the SMC version reports them); --details shows "
                    "every appliance metric plus the node status attributes.",
    )
    m.add_argument(
        "--domain", action="append",
        help="administrative domain(s) to query, repeatable or comma-separated "
             "('domain1,domain2'); 'all' = every domain visible to the API key. "
             "Default: the profile's domain, or all domains if the profile has none",
    )
    m.add_argument(
        "-d", "--details", action="store_true",
        help="show every appliance metric plus node status attributes (status, "
             "state, version, dynamic update package, installed policy, ...) "
             "instead of only the utilization columns",
    )
    _add_connection_flags(m)
    m.add_argument("--csv", action="store_true", help="emit CSV (with header) instead of table text")
    m.set_defaults(func=run_metrics)

    l = ssub.add_parser(
        "ldap",
        help="LDAP / Active Directory servers (name and IP) across all domains",
        description="List the LDAP and Active Directory server elements defined "
                    "in the SMC, with their name and IP address. Queries every "
                    "domain by default. Elements owned by the Shared Domain are "
                    "inherited by every other domain, so they are listed once "
                    "under the domain that owns them. Passwords and shared "
                    "secrets are never displayed.",
    )
    l.add_argument(
        "--domain", action="append",
        help="administrative domain(s) to query, repeatable or comma-separated "
             "('domain1,domain2'); 'all' = every domain visible to the API key. "
             "Default: all domains",
    )
    l.add_argument(
        "-d", "--details", action="store_true",
        help="show connection detail columns (bind user, base DN, timeouts, "
             "object classes, IAS/NPS settings) instead of only name/address",
    )
    _add_connection_flags(l)
    l.add_argument("--csv", action="store_true", help="emit CSV (with header) instead of table text")
    l.set_defaults(func=run_ldap)
    return p


def enumerate_domains():
    """Return the sorted list of admin domain names visible to the session."""
    return sorted((d.name for d in AdminDomain.objects.all()), key=str.lower)


def normalize_domains(requested):
    """Split repeated and comma-separated --domain values into a flat list:
    --domain 'a,b' --domain c -> ['a', 'b', 'c']."""
    names = []
    for value in requested or []:
        names.extend(n.strip() for n in value.split(",") if n.strip())
    return names


def select_domains(requested, config, prog):
    """Shared --domain resolution for the multi-domain subcommands.

    Priority: explicit --domain values (repeatable and/or comma-separated)
    win; without the flag, the profile's configured domain is used; a profile
    without a domain means every AdminDomain the API key can see. 'all'
    (as flag value or config domain) forces the enumerate-everything path,
    which requires Shared Domain visibility; if enumeration is not permitted,
    fall back to the profile's configured domain.
    """
    names = normalize_domains(requested)
    if names and not any(n.lower() == ALL for n in names):
        return names

    if not names:  # no --domain given: config decides
        if config.domain and config.domain.lower() != ALL:
            return [config.domain]

    try:
        all_names = enumerate_domains()
        if all_names:
            return all_names
    except SMCException as exc:
        print(
            "%s: cannot enumerate admin domains (%s) - falling back to the "
            "profile domain; pass --domain to be explicit" % (prog, exc),
            file=sys.stderr,
        )

    if config.domain and config.domain.lower() != ALL:
        return [config.domain]
    raise ConfigError(
        "could not determine which domains to query - the API key cannot "
        "enumerate domains and no domain is set in the profile; pass --domain"
    )


def initial_login_domain(requested, config):
    """Domain to open the first session in, before select_domains() runs."""
    names = normalize_domains(requested)
    explicit = [n for n in names if n.lower() != ALL]
    if explicit:
        return explicit[0]
    if names:
        # only 'all' was given: enumeration needs Shared Domain
        return SHARED_DOMAIN
    if config.domain and config.domain.lower() != ALL:
        return config.domain
    return SHARED_DOMAIN


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


# fixed leading columns of `show metrics`; metric columns are dynamic
METRICS_BASE = [("domain", "Domain"), ("node", "Node")]

# default (non --details) view: only utilization-style metrics. Matched with
# word boundaries so e.g. 'Upload' does not hit 'load'. If a future SMC starts
# reporting CPU/memory through appliance_status, they show up automatically.
_COMPACT_RE = re.compile(r"\b(cpu|load|memory|mem|usage)\b", re.IGNORECASE)

# preferred ordering for --details node status attributes; anything else the
# SMC returns is appended alphabetically
_STATUS_ATTR_ORDER = [
    "status", "state", "version", "dyn_up", "platform",
    "configuration_status", "installed_policy",
]


def _flatten_hardware(raw):
    """Flatten an appliance_status response into {'SubSystem Label Param': value}.

    Real-world payloads vary by SMC version: the subsystem list may sit
    directly under 'hardware_statuses' or be nested one level deeper
    ('hardware_statuses.hardware_statuses'), and each item is either flat
    ({'name': ..., 'value': ...}) or carries a 'statuses' list of
    label/param/value entries.
    """
    outer = raw.get("hardware_statuses", [])
    if isinstance(outer, dict):
        subsystems = outer.get("hardware_statuses", [])
    else:
        subsystems = outer

    metrics = {}
    for subsys in subsystems:
        if not isinstance(subsys, dict):
            continue
        subsys_name = subsys.get("name", "")
        for item in subsys.get("items", []):
            if not isinstance(item, dict):
                continue
            statuses = item.get("statuses")
            if statuses:
                for status in statuses:
                    parts = [status.get("sub_system") or subsys_name,
                             status.get("label"), status.get("param")]
                    key = " ".join(str(part) for part in parts if part)
                    metrics[key] = str(status.get("value", ""))
            elif "value" in item:
                key = " ".join(part for part in (subsys_name, item.get("name")) if part)
                metrics[key] = str(item.get("value", ""))
    return metrics


def _node_status_attrs(node):
    """Node status attributes as {key: str}, in a stable display order."""
    data = dict(node.health)
    data.pop("name", None)  # already the Node column
    ordered = {}
    for key in _STATUS_ATTR_ORDER:
        if key in data:
            ordered[key] = str(data.pop(key) or "")
    for key in sorted(data):
        ordered[key] = str(data[key] or "")
    return ordered


def collect_metrics(args, config):
    """Walk domains/engines/nodes; return (rows, metric_keys, errors)."""
    from smc.core.engine import Engine

    rows, errors = [], []
    metric_keys = []  # first-seen order across all nodes

    session.login(
        url=config.url,
        api_key=config.api_key,
        verify=config.verify,
        domain=initial_login_domain(args.domain, config),
        api_version=config.api_version,
        timeout=config.timeout,
    )
    try:
        domains = select_domains(args.domain, config, PROG)
        for domain in domains:
            try:
                session.switch_domain(domain)
                for engine in Engine.objects.all():
                    for node in engine.nodes:
                        row = {"domain": domain, "node": node.name}
                        try:
                            if args.details:
                                row.update(_node_status_attrs(node))
                            raw = node.make_request(resource="appliance_status")
                            row.update(_flatten_hardware(raw))
                        except SMCException as exc:
                            errors.append("%s/%s: %s" % (domain, node.name, exc))
                        for key in row:
                            if key not in ("domain", "node") and key not in metric_keys:
                                metric_keys.append(key)
                        rows.append(row)
            except SMCException as exc:
                errors.append("%s: %s" % (domain, exc))
    finally:
        try:
            session.logout()
        except Exception:
            pass

    rows.sort(key=lambda r: (r["domain"].lower(), r["node"].lower()))
    return rows, metric_keys, errors


# `show ldap` columns. Base view answers "what is it and where does it live";
# --details adds the connection settings. Credential fields are deliberately
# absent from both - see _SECRET_KEYS.
LDAP_BASE = [
    ("domain", "Domain"),
    ("name", "Name"),
    ("type", "Type"),
    ("address", "Address"),
    ("port", "Port"),
    ("protocol", "Protocol"),
]

LDAP_DETAILS = [
    ("base_dn", "Base DN"),
    ("bind_user_id", "Bind User"),
    ("timeout", "Timeout"),
    ("max_search_result", "Max Results"),
    ("page_size", "Page Size"),
    ("ias", "IAS"),
    ("auth_ipaddress", "IAS Address"),
    ("auth_port", "IAS Port"),
    ("user_object_class", "User Classes"),
    ("group_object_class", "Group Classes"),
]

# Never render these, in any view or output format: the SMC hands back the
# bind credential and RADIUS/NPS shared secret with the rest of the element.
_SECRET_KEYS = ("bind_password", "shared_secret")

_LDAP_TYPES = [(ActiveDirectoryServer, "active-directory"), (LDAPServer, "ldap")]


def _domain_name_map():
    """{admin_domain href: domain name}, for attributing an element to the
    domain that owns it rather than a domain that merely inherits it."""
    try:
        return {d.href: d.name for d in AdminDomain.objects.all()}
    except SMCException:
        return {}


def _ldap_row(element, kind, owner, details):
    data = element.data
    row = {
        "domain": owner,
        "name": element.name,
        "type": kind,
        "address": str(data.get("address") or ""),
        "port": str(data.get("port") or ""),
        "protocol": str(data.get("protocol") or ""),
    }
    if details:
        row.update({
            "base_dn": str(data.get("base_dn") or ""),
            "bind_user_id": str(data.get("bind_user_id") or ""),
            "timeout": str(data.get("timeout") or ""),
            "max_search_result": str(data.get("max_search_result") or ""),
            "page_size": str(data.get("page_size") or ""),
            "ias": "yes" if data.get("internet_auth_service_enabled") else "no",
            "auth_ipaddress": str(data.get("auth_ipaddress") or ""),
            "auth_port": str(data.get("auth_port") or ""),
            "user_object_class": ",".join(data.get("user_object_class") or []),
            "group_object_class": ",".join(data.get("group_object_class") or []),
        })
    return row


def _domain_controller_rows(element, owner, details):
    """Extra domain controllers configured on an AD element carry their own
    IP, so surface them as their own rows."""
    rows = []
    for dc in element.data.get("domain_controller", []) or []:
        if not isinstance(dc, dict):
            continue
        row = {
            "domain": owner,
            "name": "%s / %s" % (element.name, dc.get("ipaddress") or "?"),
            "type": "ad-domain-controller",
            "address": str(dc.get("ipaddress") or ""),
            "port": str(dc.get("port") or ""),
            "protocol": str(dc.get("server_type") or ""),
        }
        if details:
            row.update({
                "bind_user_id": str(dc.get("user") or ""),
                "timeout": str(dc.get("expiration_time") or ""),
            })
        rows.append(row)
    return rows


def collect_ldap(args, config):
    """Walk domains collecting LDAP/AD server elements; return (rows, errors).

    Shared Domain elements are visible from every domain with the same href,
    so dedupe on href and attribute each element to its owning admin_domain.
    """
    rows, errors = [], []
    seen = set()

    session.login(
        url=config.url,
        api_key=config.api_key,
        verify=config.verify,
        domain=initial_login_domain(args.domain or [ALL], config),
        api_version=config.api_version,
        timeout=config.timeout,
    )
    try:
        domain_names = _domain_name_map()
        for domain in select_domains(args.domain or [ALL], config, PROG):
            try:
                session.switch_domain(domain)
                for cls, kind in _LDAP_TYPES:
                    for element in cls.objects.all():
                        try:
                            if element.href in seen:
                                continue
                            seen.add(element.href)
                            owner = domain_names.get(
                                element.data.get("admin_domain"), domain)
                            rows.append(_ldap_row(element, kind, owner, args.details))
                            rows.extend(
                                _domain_controller_rows(element, owner, args.details))
                        except SMCException as exc:
                            errors.append("%s/%s: %s" % (domain, cls.__name__, exc))
            except SMCException as exc:
                errors.append("%s: %s" % (domain, exc))
    finally:
        try:
            session.logout()
        except Exception:
            pass

    rows.sort(key=lambda r: (r["domain"].lower(), r["name"].lower()))
    return rows, errors


def run_ldap(args):
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

    requested = normalize_domains(args.domain)
    print(
        "%s: profile=%s url=%s domains=%s"
        % (PROG, args.profile, config.url, ",".join(requested) if requested else ALL),
        file=sys.stderr,
    )

    try:
        rows, errors = collect_ldap(args, config)
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
        columns = LDAP_BASE + (LDAP_DETAILS if args.details else [])
        keys = [k for k, _ in columns]
        if args.json:
            for row in rows:
                print(json.dumps({k: row[k] for k in keys if k in row},
                                 separators=(",", ":")))
        elif args.csv:
            writer = csv.DictWriter(sys.stdout, fieldnames=keys, restval="",
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        else:
            for line in table_lines(rows, columns):
                print(line)
    elif not errors:
        print("%s: no LDAP or Active Directory servers found" % PROG, file=sys.stderr)

    return 1 if errors else 0


def run_metrics(args):
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

    requested = normalize_domains(args.domain)
    domains_label = ",".join(requested) if requested else (config.domain or "all")
    print(
        "%s: profile=%s url=%s domains=%s" % (PROG, args.profile, config.url, domains_label),
        file=sys.stderr,
    )

    try:
        rows, metric_keys, errors = collect_metrics(args, config)
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
        if not args.details:
            metric_keys = [k for k in metric_keys if _COMPACT_RE.search(k)]
        columns = METRICS_BASE + [(k, k) for k in metric_keys]
        keys = [k for k, _ in columns]
        if args.json:
            for row in rows:
                print(json.dumps({k: row[k] for k in keys if k in row},
                                 separators=(",", ":")))
        elif args.csv:
            writer = csv.DictWriter(sys.stdout, fieldnames=keys, restval="",
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        else:
            for line in table_lines(rows, columns):
                print(line)
    elif not errors:
        print("%s: no firewall nodes found" % PROG, file=sys.stderr)

    return 1 if errors else 0
