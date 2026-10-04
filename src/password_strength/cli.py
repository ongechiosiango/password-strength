"""Command-line interface for Password Strength.

The password is never logged or stored. By default we prompt with getpass
(no echo). Use --stdin to pipe from another process.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from rich.console import Console

from . import __version__
from .analyzer import analyze
from .reporter import print_report, to_json

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-strength",
        description="Estimate password strength using entropy and pattern detection.",
    )
    parser.add_argument("--stdin", action="store_true",
                        help="Read the password from stdin (one line).")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Output results as JSON (implies --stdin).")
    parser.add_argument("--show", action="store_true",
                        help="Echo the password back (off by default; use with care).")
    parser.add_argument("--version", action="version",
                        version=f"password-strength {__version__}")
    return parser


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        line = sys.stdin.readline()
        return line.rstrip("\n")
    return getpass.getpass("Password: ")


def main() -> int:
    args = build_parser().parse_args()

    # --json implies reading from stdin unless we already prompt.
    from_stdin = args.stdin or args.as_json

    try:
        password = _read_password(from_stdin)
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return 130

    if not password:
        console.print("[bold red]Error:[/bold red] empty password.")
        return 1

    analysis = analyze(password)

    if args.as_json:
        print(to_json(analysis))
    else:
        if args.show:
            console.print(f"[dim]Password:[/dim] {password}")
        print_report(analysis)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
