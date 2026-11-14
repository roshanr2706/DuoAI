"""One-shot CLI: ``duo-agent enroll <activation>`` and ``duo-agent code``.

`code` prints exactly the 6 digits to stdout. Errors go to stderr with a
non-zero exit. The store directory is ``$DUO_AGENT_HOME`` or
``~/.config/duo-agent``.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from duo_agent import enroll as enroll_mod
from duo_agent import hotp
from duo_agent.store import SecretStore


def _store_dir() -> Path:
    env = os.environ.get("DUO_AGENT_HOME")
    return Path(env) if env else Path.home() / ".config" / "duo-agent"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(prog="duo-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    p_enroll = sub.add_parser("enroll", help="clone a dedicated Duo slot")
    p_enroll.add_argument("activation", help="'<code>-<base64 host>' from the QR")
    sub.add_parser("code", help="print the current 6-digit passcode")
    args = parser.parse_args(argv)

    store = SecretStore(_store_dir())

    if args.command == "enroll":
        try:
            enroll_mod.enroll(args.activation, store)
        except enroll_mod.EnrollError as exc:
            print(f"enroll failed: {exc}", file=sys.stderr)
            return 1
        print("enrolled; store ready", file=sys.stderr)
        return 0

    if args.command == "code":
        if not store.exists():
            print(
                "no enrollment found; run 'duo-agent enroll <activation>' first",
                file=sys.stderr,
            )
            return 1
        print(hotp.next_code(store))
        return 0

    return 2  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
