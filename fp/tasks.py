import json
import sys
import warnings
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import urllib3
from smc import session
from smc.administration.scheduled_tasks import RefreshPolicyTask
from smc.api.exceptions import ActionCommandFailed, SMCException

from fp import show
from fp.config import DEFAULT_CONFIG_PATH, ConfigError, load_config

PROG = "fp tasks"

# Same vendored SSLAdapter deprecation noise as logtail; see fp/logtail.py.
warnings.filterwarnings("ignore", message=r".*ssl_version.*", category=FutureWarning)

# fp owns every refresh task whose name starts with this prefix: one per
# (domain, engine timezone), e.g. "fp - Refresh Policy (Europe/Rome)".
# Re-running updates them in place; fp tasks that no longer match a timezone
# group (including the earlier per-domain "(all engines)" task) are removed.
# Hand-made refresh tasks are never modified unless --disable-overlapping.
TASK_PREFIX = "fp - Refresh Policy"

RUN_AT = (4, 30)  # 04:30 wall-clock in each engine's own timezone
DEFAULT_TZ = "UTC"  # for engines with no timezone set

# Engine types a RefreshPolicyTask accepts. Master/virtual engines need
# RefreshMasterEnginePolicyTask instead, so they are reported and skipped.
REFRESHABLE_TYPES = {"single_fw", "fw_cluster", "single_layer2", "layer2_cluster",
                     "single_ips", "ips_cluster"}

SUNDAY_MASK = 2  # day masks: sun=2 mon=4 tue=8 wed=16 thu=32 fri=64 sat=128

# How the SMC itself stores these schedules (read back from tasks created in
# the Management Client). Note smc-python's add_schedule() is not used: for
# day_period='daily' it rewrites minute_period 'one_time' to 'hourly', which
# would refresh policy on every engine every hour.
SCHEDULES = {
    "daily": {"day_period": "daily", "minute_period": "1440", "day_mask": 0},
    "weekly": {"day_period": "weekly", "minute_period": "one_time", "day_mask": SUNDAY_MASK},
}


def add_parser(sub):
    p = sub.add_parser(
        "tasks",
        help="manage SMC scheduled tasks",
        description="Manage SMC scheduled tasks.",
    )
    tsub = p.add_subparsers(dest="tasks_what", metavar="WHAT", required=True)

    pol = tsub.add_parser(
        "policies",
        help="policy-related scheduled tasks",
        description="Policy-related scheduled tasks.",
    )
    psub = pol.add_subparsers(dest="policies_what", metavar="ACTION", required=True)

    r = psub.add_parser(
        "set-refresh",
        help="schedule a policy refresh of every engine at 04:30 in the engine's own timezone",
        description="Schedule a policy refresh of every engine, daily (every 24 hours) "
                    "or weekly (Sunday), at 04:30 in each engine's own configured "
                    "timezone - engines without one use --timezone (default UTC). "
                    "Creates one task per domain and timezone, named '%s (<timezone>)'. "
                    "Re-running updates those tasks in place and removes fp tasks that "
                    "no longer match a timezone group; other refresh tasks are left "
                    "untouched (unless --disable-overlapping) but reported when they "
                    "cover the same engines." % TASK_PREFIX,
    )
    r.add_argument(
        "--when", required=True, choices=sorted(SCHEDULES),
        help="daily = every 24 hours from 04:30; weekly = Sunday at 04:30 "
             "(04:30 in each engine's timezone)",
    )
    r.add_argument(
        "--domain", action="append",
        help="administrative domain(s), repeatable or comma-separated "
             "('domain1,domain2'); 'all' = every domain visible to the API key. "
             "Default: the profile's domain, or all domains if the profile has none",
    )
    r.add_argument(
        "--timezone", default=DEFAULT_TZ,
        help="IANA timezone for engines that have none configured, or an invalid "
             "one (default: %(default)s). The SMC stores the start in UTC",
    )
    r.add_argument(
        "--disable-overlapping", action="store_true",
        help="suspend the schedules of other refresh tasks in the same domain whose "
             "engines are ALL covered by fp tasks (suspend, not delete - "
             "reversible). Tasks that also refresh engines outside the fp tasks are "
             "left running and reported",
    )
    r.add_argument(
        "--validate", action="store_true",
        help="validate the policy before each refresh. Off by default: an unattended "
             "task aborts the upload on any validation WARNING (which the Management "
             "Client lets an admin click through), so an engine with a harmless warning "
             "would silently never be refreshed. Errors still block the upload either "
             "way. Changing this on an existing fp task recreates the task",
    )
    r.add_argument("--dry-run", action="store_true",
                   help="show what would be created or changed without touching the SMC")
    r.add_argument("--profile", default="default", help="config profile/section name (default: %(default)s)")
    r.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="path to config file (default: %(default)s)")
    r.add_argument("--url", help="SMC API url, e.g. https://smc.example.com:8082")
    r.add_argument("--api-key", help="SMC API key")
    r.add_argument("--api-version", help="SMC API version override")
    r.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (dangerous)")
    r.add_argument("--json", action="store_true", help="emit one JSON object per domain instead of text")
    r.set_defaults(func=run_set_refresh)
    return p


def next_activation(when, tz, now=None):
    """First future 04:30 in `tz` (the next Sunday's for weekly), as an aware
    datetime. Computed in `tz` so the wall-clock time is right for the current
    UTC offset, then handed to the SMC as UTC."""
    now = (now or datetime.now(timezone.utc)).astimezone(tz)
    start = now.replace(hour=RUN_AT[0], minute=RUN_AT[1], second=0, microsecond=0)
    if when == "weekly":
        start += timedelta(days=(6 - start.weekday()) % 7)  # Monday=0 .. Sunday=6
        if start <= now:
            start += timedelta(days=7)
    elif start <= now:
        start += timedelta(days=1)
    return start


def _to_ms(dt):
    return int(dt.timestamp() * 1000)


def _utc_offset(tz_name):
    offset = datetime.now(ZoneInfo(tz_name)).utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    return "UTC%s%02d:%02d" % ("-" if minutes < 0 else "+", abs(minutes) // 60, abs(minutes) % 60)


def engine_timezone(engine, fallback):
    """(timezone name, warning or None) for an engine. Unset or unknown
    timezones use the fallback; Etc/GMT+N zones are flagged because their sign
    is inverted (Etc/GMT+1 is UTC-01:00) and they are usually set by mistake
    for CET."""
    raw = (engine.data.get("timezone") or "").strip()
    if not raw:
        return fallback, None
    try:
        ZoneInfo(raw)
    except (ZoneInfoNotFoundError, ValueError):
        return fallback, "%s: unknown timezone %r, using %s" % (engine.name, raw, fallback)
    if raw.startswith("Etc/GMT") and raw not in ("Etc/GMT", "Etc/GMT+0", "Etc/GMT-0", "Etc/GMT0"):
        return raw, ("%s: timezone %s is %s (Etc/GMT signs are inverted) - honoured "
                     "as configured; if CET/CEST was meant, set Europe/Zurich or "
                     "Europe/Rome on the engine" % (engine.name, raw, _utc_offset(raw)))
    return raw, None


def task_name(tz_name):
    return "%s (%s)" % (TASK_PREFIX, tz_name)


def _fp_tasks(domain_href):
    """fp-owned refresh tasks of this domain, by name. Same-named tasks
    inherited from another domain are ignored."""
    tasks = {}
    for task in RefreshPolicyTask.objects.all():
        if not task.name.startswith(TASK_PREFIX):
            continue
        # without the domain href (key cannot list domains) fall back to the
        # name alone rather than creating duplicates on every run
        if domain_href is None or task.data.get("admin_domain") == domain_href:
            tasks[task.name] = task
    return tasks


def _overlapping_tasks(engine_hrefs, fp_hrefs, domain_href):
    """Other refresh tasks owned by this domain that cover any of these
    engines - they would refresh the same engines on their own schedule.

    `covered` is True only when every engine the task refreshes is also in an
    fp task; only those are safe to suspend, otherwise an engine would
    silently stop being refreshed."""
    overlaps = []
    for task in RefreshPolicyTask.objects.all():
        if task.href in fp_hrefs or task.name.startswith(TASK_PREFIX):
            continue
        if domain_href and task.data.get("admin_domain") not in (None, domain_href):
            continue  # inherited from another domain - not ours to change
        resources = set(task.data.get("resources") or [])
        shared = engine_hrefs & resources
        if shared:
            overlaps.append({
                "task": task.name,
                "engines": len(shared),
                "covered": resources <= engine_hrefs,
                "uncovered": len(resources - engine_hrefs),
                "disabled": 0,
                "_obj": task,
            })
    return overlaps


def _disable_overlapping(overlaps, dry_run):
    """Suspend the active schedules of fully covered hand-made tasks. Suspend,
    not delete: reversible from the Management Client or the API."""
    for ov in overlaps:
        if not ov["covered"]:
            continue
        # a refusal on one task (the SMC rejects updates to tasks it considers
        # to reference trashed elements) must not stop the others
        try:
            for schedule in ov["_obj"].task_schedule:
                if schedule.data.get("activated"):
                    if not dry_run:
                        schedule.suspend()
                    ov["disabled"] += 1
        except SMCException as exc:
            ov["error"] = " ".join(str(exc).split())


def _add_schedule(task, name, when, activation):
    """POST the schedule directly, in the shape the SMC uses itself."""
    body = dict(SCHEDULES[when])
    body.update({
        "name": "%s - %s" % (name, when),
        "activation_date": _to_ms(activation),
        "activated": True,
        "final_action": "ALERT_FAILURE",
        "repeat_until_date": None,
        "comment": "managed by fp tasks policies set-refresh",
    })
    task.make_request(ActionCommandFailed, method="create", resource="task_schedule", json=body)


def _validates(task):
    """True when the task validates the policy before uploading. smc-python
    only sends validation_settings at creation, so the setting cannot be
    changed on an existing task - it has to be recreated."""
    return bool(task.data.get("validation_settings"))


def _sync_task(task, name, engines, when, activation, dry_run, validate=False):
    """Create or update one fp task; return a description of the change."""
    engine_hrefs = {e.href for e in engines}
    recreated = task is not None and _validates(task) != validate
    if recreated:
        if not dry_run:
            task.delete()
        task = None
    if task is None:
        if not dry_run:
            task = RefreshPolicyTask.create(
                name=name,
                engines=engines,
                comment="Refresh policy at 04:30 local engine time - managed by fp",
                validate_policy=validate,
                preserve_connections=True,
                snapshot_creation=True,
            )
            _add_schedule(task, name, when, activation)
        if recreated:
            return "recreate (policy validation %s)" % ("on" if validate else "off")
        return "create"

    changes = []
    if set(task.data.get("resources") or []) != engine_hrefs:
        changes.append("engine list")
        if not dry_run:
            task.update(resources=sorted(engine_hrefs))
    old = list(task.task_schedule)
    changes.append("replace %d schedule(s)" % len(old) if old else "add schedule")
    if not dry_run:
        for schedule in old:
            schedule.delete()
        _add_schedule(task, name, when, activation)
    return "update: " + ", ".join(changes)


def configure_domain(domain, domain_href, when, fallback_tz, dry_run, disable_overlapping=False,
                     validate=False):
    """Create/update one fp task per engine timezone in the current session
    domain; return a result dict describing what was (or would be) done."""
    from smc.core.engine import Engine

    result = {"domain": domain, "groups": [], "removed": [], "skipped": [],
              "warnings": [], "overlaps": []}

    groups = OrderedDict()  # timezone -> [engines]
    for engine in Engine.objects.all():
        # engines inherited from another domain are that domain's business
        owner = engine.data.get("admin_domain")
        if domain_href and owner and owner != domain_href:
            continue
        if engine.type not in REFRESHABLE_TYPES:
            result["skipped"].append("%s (type %s)" % (engine.name, engine.type))
            continue
        try:
            policy = engine.installed_policy
        except SMCException:
            policy = None
        if not policy:
            result["skipped"].append("%s (no policy installed)" % engine.name)
            continue
        tz_name, warning = engine_timezone(engine, fallback_tz)
        if warning:
            result["warnings"].append(warning)
        groups.setdefault(tz_name, []).append(engine)

    existing = _fp_tasks(domain_href)
    all_engine_hrefs = set()

    for tz_name in sorted(groups):
        engines = sorted(groups[tz_name], key=lambda e: e.name.lower())
        all_engine_hrefs.update(e.href for e in engines)
        name = task_name(tz_name)
        activation = next_activation(when, ZoneInfo(tz_name))
        action = _sync_task(existing.pop(name, None), name, engines, when, activation, dry_run,
                            validate)
        result["groups"].append({
            "timezone": tz_name,
            "task": name,
            "action": action,
            "engines": [e.name for e in engines],
            "first_run_local": activation.strftime("%a %Y-%m-%d %H:%M %Z"),
            "first_run_utc": activation.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        })

    # fp tasks whose timezone group is gone (engine moved/retimezoned, or the
    # earlier one-task-per-domain layout): ours to remove
    for name, task in sorted(existing.items()):
        if not dry_run:
            task.delete()
        result["removed"].append(name)

    fp_hrefs = {t.href for t in _fp_tasks(domain_href).values()} if not dry_run else set()
    result["overlaps"] = _overlapping_tasks(all_engine_hrefs, fp_hrefs, domain_href)
    # only once the fp tasks and their schedules are in place
    if disable_overlapping and groups:
        _disable_overlapping(result["overlaps"], dry_run)
    return result


def run_set_refresh(args):
    try:
        ZoneInfo(args.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        print("%s: unknown timezone %r" % (PROG, args.timezone), file=sys.stderr)
        return 2

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
    print(
        "%s: profile=%s url=%s domains=%s when=%s at 04:30 engine-local time "
        "(engines without a timezone: %s) policy validation=%s%s"
        % (PROG, config.display(args.profile), config.url,
           ",".join(requested) if requested else (config.domain or show.ALL),
           args.when, args.timezone, "on" if args.validate else "off",
           " [dry run]" if args.dry_run else ""),
        file=sys.stderr,
    )

    results, errors = [], []
    try:
        session.login(
            url=config.url,
            api_key=config.api_key,
            verify=config.verify,
            domain=show.initial_login_domain(args.domain, config),
            api_version=config.api_version,
            timeout=config.timeout,
        )
    except SMCException as exc:
        print("%s: could not log in to %s: %s" % (PROG, config.url, exc), file=sys.stderr)
        return 1

    try:
        domain_hrefs = {name: href for href, name in show._domain_name_map().items()}
        domains = show.select_domains(args.domain, config, PROG)
        for domain in domains:
            try:
                session.switch_domain(domain)
                results.append(configure_domain(
                    domain, domain_hrefs.get(domain), args.when, args.timezone,
                    args.dry_run, args.disable_overlapping, args.validate))
            except SMCException as exc:
                errors.append("%s: %s" % (domain, exc))
    except ConfigError as exc:
        print("%s: %s" % (PROG, exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        try:
            session.logout()
        except Exception:
            pass

    suspend_verb = "would suspend" if args.dry_run else "suspended"
    remove_verb = "would remove" if args.dry_run else "removed"
    for res in results:
        for ov in res["overlaps"]:
            ov.pop("_obj", None)  # SMC element, not serialisable/printable
        if args.json:
            print(json.dumps(res, separators=(",", ":")))
            continue
        if not res["groups"]:
            print("%s: none (no refreshable engines)" % res["domain"])
        else:
            print("%s:" % res["domain"])
        for grp in res["groups"]:
            print("    %s %r - first run %s (%s UTC)"
                  % (grp["action"], grp["task"], grp["first_run_local"], grp["first_run_utc"][11:]))
            print("        engines (%d): %s" % (len(grp["engines"]), ", ".join(grp["engines"])))
        for name in res["removed"]:
            print("    %s superseded fp task %r" % (remove_verb, name))
        for skipped in res["skipped"]:
            print("    skipped: %s" % skipped)
        for warning in res["warnings"]:
            print("    WARNING: %s" % warning)
        for ov in res["overlaps"]:
            if args.disable_overlapping and ov.get("error"):
                print("    ERROR: could not suspend existing task %r - still running: %s"
                      % (ov["task"], ov["error"]))
            elif args.disable_overlapping and ov["covered"]:
                if ov["disabled"]:
                    print("    %s existing task %r (%d schedule(s); all its engines "
                          "are in fp tasks)" % (suspend_verb, ov["task"], ov["disabled"]))
                else:
                    print("    existing task %r already suspended" % ov["task"])
            elif args.disable_overlapping:
                print("    WARNING: existing task %r left running - it also refreshes %d "
                      "engine(s) not in the fp tasks" % (ov["task"], ov["uncovered"]))
            else:
                print("    WARNING: existing task %r also refreshes %d of these engines "
                      "(--disable-overlapping to suspend it)" % (ov["task"], ov["engines"]))

    for err in errors:
        print("%s: error: %s" % (PROG, err), file=sys.stderr)
    failed = any(ov.get("error") for res in results for ov in res["overlaps"])
    return 1 if errors or failed else 0
