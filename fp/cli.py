import argparse
import sys

from fp import changes, licenses, logtail, show


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="fp",
        description="Forcepoint NGFW SMC command-line tools",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    logtail.add_parser(sub)
    licenses.add_parser(sub)
    changes.add_parser(sub)
    show.attach(sub)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
