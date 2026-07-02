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
