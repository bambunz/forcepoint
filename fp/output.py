import os
import re
import sys

RESET = "\x1b[0m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"

_CRITICAL_HIGH = re.compile(r"\b(critical|high)\b", re.IGNORECASE)
_LOW = re.compile(r"\blow\b", re.IGNORECASE)


def color_enabled(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def colorize(text: str) -> str:
    text = _CRITICAL_HIGH.sub(lambda m: RED + m.group(0) + RESET, text)
    text = _LOW.sub(lambda m: YELLOW + m.group(0) + RESET, text)
    return text


def grep_lines(text: str, pattern: "re.Pattern") -> str:
    kept = [line for line in text.splitlines() if pattern.search(line)]
    return "\n".join(kept) + ("\n" if kept else "")


def table_lines(rows, columns):
    """Render rows (list of dicts) as aligned text lines: header, separator,
    one line per row. `columns` is a list of (key, header) tuples; missing
    keys render empty."""
    keys = [k for k, _ in columns]
    headers = {k: h for k, h in columns}
    widths = {k: max(len(headers[k]), *(len(r.get(k, "")) for r in rows)) for k in keys}

    header_line = "  ".join(headers[k].ljust(widths[k]) for k in keys)
    lines = [header_line, "-" * len(header_line)]
    for row in rows:
        line = "  ".join(row.get(k, "").ljust(widths[k]) for k in keys)
        lines.append(line.rstrip())
    return lines


def strip_trailing_padding(text: str) -> str:
    """TableFormat pads every column to the widest value in the batch, which can
    leave short rows with a lot of dead trailing whitespace. On a narrower terminal
    that padding wraps onto the next line and looks like a blank line, so strip it."""
    lines = text.split("\n")
    return "\n".join(line.rstrip() for line in lines)
