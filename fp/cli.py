import argparse
import configparser
import sys

from fp import changes, licenses, logtail, show, tasks
from fp.config import DEFAULT_CONFIG_PATH, new_parser


def _profiles_epilog(config_path=DEFAULT_CONFIG_PATH):
    """Help text explaining SMC selection, listing the profiles actually
    configured (url and domain only - never credentials)."""
    lines = [
        "choosing the SMC:",
        "  Every SMC is a profile in %s:" % config_path,
        "  [smc] is the 'default' profile, [smc:NAME] is profile NAME; an optional",
        "  'name = ...' line gives it a display name shown in help and in each",
        "  command's startup line.",
        "  Pick one per command with --profile NAME (after the subcommand):",
        "    fp license --profile ch",
        "    fp tasks policies set-refresh --when daily --domain all --profile ch",
        "",
    ]
    parser = new_parser()
    try:
        parser.read(config_path)
    except configparser.Error:
        parser = None

    profiles = []
    for section in (parser.sections() if parser else []):
        if section == "smc":
            name = "default"
        elif section.startswith("smc:"):
            name = section[4:]
        else:
            continue
        profiles.append((name, parser[section].get("url", "?"),
                         parser[section].get("domain", "-"),
                         parser[section].get("name", "").strip()))

    if profiles:
        lines.append("  configured profiles:")
        width = max(len(name) for name, _, _, _ in profiles)
        dwidth = max(len(display) for _, _, _, display in profiles)
        for name, url, domain, display in profiles:
            lines.append("    %-*s  %-*s  %s  (default domain: %s)"
                         % (width, name, dwidth, display or "-", url, domain))
    else:
        lines.append("  no profiles found - create %s (see README)" % config_path)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="fp",
        description="Forcepoint NGFW SMC command-line tools",
        epilog=_profiles_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    logtail.add_parser(sub)
    licenses.add_parser(sub)
    changes.add_parser(sub)
    tasks.add_parser(sub)
    show.attach(sub)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
