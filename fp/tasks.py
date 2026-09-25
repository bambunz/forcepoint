import json
import sys
import warnings
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

# One task per domain, owned by fp: re-running updates it in place instead of
# stacking duplicates, and hand-made refresh tasks are never touched.
TASK_NAME = "fp - Refresh Policy (all engines)"

RUN_AT = (4, 30)  # 04:30 in --timezone
DEFAULT_TZ = "UTC"

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
        help="schedule a policy refresh of every engine, daily or weekly at 04:30 UTC",
        description="Create or update one refresh-policy task per domain, named "
                    "'%s', covering every engine in the domain, and schedule it "
                    "daily (every 24 hours from 04:30 UTC) or weekly (Sunday 04:30 UTC). "
                    "Re-running replaces that task's schedule and engine list; "
                    "other refresh tasks are left untouched but reported when they "
                    "cover the same engines." % TASK_NAME,
    )
    r.add_argument(
        "--when", required=True, choices=sorted(SCHEDULES),
        help="daily = every 24 hours starting at 04:30 UTC; weekly = Sunday at 04:30 UTC",
    )
    r.add_argument(
        "--domain", action="append",
        help="administrative domain(s), repeatable or comma-separated "
             "('domain1,domain2'); 'all' = every domain visible to the API key. "
             "Default: the profile's domain, or all domains if the profile has none",
    )
    r.add_argument(
        "--timezone", default=DEFAULT_TZ,
        help="IANA timezone the 04:30 start time is read in (default: %(default)s, "
             "which also sidesteps DST shifts). The SMC stores the start in UTC",
    )
    r.add_argument(
        "--disable-overlapping", action="store_true",
        help="suspend the schedules of other refresh tasks in the same domain whose "
             "engines are ALL covered by the fp task (suspend, not delete - "
             "reversible). Tasks that also refresh engines outside the fp task are "
             "left running and reported",
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
    datetime. Computed in `tz` so a non-UTC wall-clock time stays right across
    DST, then handed to the SMC as UTC."""
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


def _own_task(domain_href):
    """This domain's fp-managed task, ignoring a same-named one inherited from
    another domain (Shared Domain elements are visible everywhere)."""
    for task in RefreshPolicyTask.objects.filter(TASK_NAME, exact_match=True):
        if task.name != TASK_NAME:
            continue
        # without the domain href (key cannot list domains) fall back to the
        # name alone rather than creating a duplicate on every run
        if domain_href is None or task.data.get("admin_domain") == domain_href:
            return task
    return None


def _overlapping_tasks(engine_hrefs, own_href, domain_href):
    """Other refresh tasks owned by this domain that cover any of these
    engines - they would refresh the same engines on their own schedule.

    `covered` is True only when every engine the task refreshes is also in
    the fp task; only those are safe to suspend, otherwise an engine would
    silently stop being refreshed."""
    overlaps = []
    for task in RefreshPolicyTask.objects.all():
        if task.href == own_href:
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


def _add_schedule(task, when, activation):
    """POST the schedule directly, in the shape the SMC uses itself."""
    body = dict(SCHEDULES[when])
    body.update({
        "name": "%s - %s" % (TASK_NAME, when),
        "activation_date": _to_ms(activation),
        "activated": True,
        "final_action": "ALERT_FAILURE",
        "repeat_until_date": None,
        "comment": "managed by fp tasks policies set-refresh",
    })
    task.make_request(ActionCommandFailed, method="create", resource="task_schedule", json=body)


def configure_domain(domain, domain_href, when, activation, dry_run, disable_overlapping=False):
    """Create/update the fp task in the current session domain; return a
    result dict describing what was (or would be) done."""
    from smc.core.engine import Engine

    result = {"domain": domain, "action": "", "engines": [], "skipped": [], "overlaps": []}

    engines = []
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
        engines.append(engine)

    engines.sort(key=lambda e: e.name.lower())
    result["engines"] = [e.name for e in engines]
    engine_hrefs = {e.href for e in engines}

    task = _own_task(domain_href)
    result["overlaps"] = _overlapping_tasks(engine_hrefs, task.href if task else None, domain_href)

    if not engines:
        result["action"] = "none (no refreshable engines)"
        return result

    if task is None:
        result["action"] = "create task"
        if not dry_run:
            task = RefreshPolicyTask.create(
                name=TASK_NAME,
                engines=engines,
                comment="Refresh policy on every engine in the domain - managed by fp",
                validate_policy=True,
                preserve_connections=True,
                snapshot_creation=True,
            )
    else:
        changes = []
        if set(task.data.get("resources") or []) != engine_hrefs:
            changes.append("engine list")
            if not dry_run:
                task.update(resources=sorted(engine_hrefs))
        old = list(task.task_schedule)
        if old:
            changes.append("replace %d schedule(s)" % len(old))
            if not dry_run:
                for schedule in old:
                    schedule.delete()
        else:
            changes.append("add schedule")
        result["action"] = "update task: " + ", ".join(changes)

    if not dry_run:
        _add_schedule(task, when, activation)
    # only once the fp task and its schedule are in place
    if disable_overlapping:
        _disable_overlapping(result["overlaps"], dry_run)
    return result


def run_set_refresh(args):
    try:
        tz = ZoneInfo(args.timezone)
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

    activation = next_activation(args.when, tz)
    requested = show.normalize_domains(args.domain)
    print(
        "%s: profile=%s url=%s domains=%s when=%s first run=%s (%s UTC)%s"
        % (PROG, args.profile, config.url,
           ",".join(requested) if requested else (config.domain or show.ALL),
           args.when, activation.strftime("%a %Y-%m-%d %H:%M %Z"),
           activation.astimezone(timezone.utc).strftime("%H:%M"),
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
                    domain, domain_hrefs.get(domain), args.when, activation, args.dry_run,
                    args.disable_overlapping))
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

    verb = "would suspend" if args.dry_run else "suspended"
    for res in results:
        for ov in res["overlaps"]:
            ov.pop("_obj", None)  # SMC element, not serialisable/printable
        if args.json:
            print(json.dumps(res, separators=(",", ":")))
            continue
        print("%s: %s" % (res["domain"], res["action"]))
        if res["engines"]:
            print("    engines (%d): %s" % (len(res["engines"]), ", ".join(res["engines"])))
        for skipped in res["skipped"]:
            print("    skipped: %s" % skipped)
        for ov in res["overlaps"]:
            if args.disable_overlapping and ov.get("error"):
                print("    ERROR: could not suspend existing task %r - still running: %s"
                      % (ov["task"], ov["error"]))
            elif args.disable_overlapping and ov["covered"]:
                if ov["disabled"]:
                    print("    %s existing task %r (%d schedule(s); all its engines "
                          "are in the fp task)" % (verb, ov["task"], ov["disabled"]))
                else:
                    print("    existing task %r already suspended" % ov["task"])
            elif args.disable_overlapping:
                print("    WARNING: existing task %r left running - it also refreshes %d "
                      "engine(s) not in the fp task" % (ov["task"], ov["uncovered"]))
            else:
                print("    WARNING: existing task %r also refreshes %d of these engines "
                      "(--disable-overlapping to suspend it)" % (ov["task"], ov["engines"]))

    for err in errors:
        print("%s: error: %s" % (PROG, err), file=sys.stderr)
    failed = any(ov.get("error") for res in results for ov in res["overlaps"])
    return 1 if errors or failed else 0
