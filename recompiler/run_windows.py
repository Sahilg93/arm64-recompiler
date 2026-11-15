#!/usr/bin/env python3
"""Run a Windows executable with Wine, passing through arguments and exit status."""

import argparse
import os
from pathlib import Path
import shutil
import sys

from setup_wine import ROOT, RUNTIME, WINE_PATH


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wine", type=Path, help="Wine executable path")
    parser.add_argument("--prefix", type=Path, help="Wine configuration directory")
    parser.add_argument("exe", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    installed = Path("/Applications") / WINE_PATH
    local = RUNTIME / WINE_PATH
    configured = os.environ.get("WINDOWS_WINE")
    system = shutil.which("wine")
    wine = args.wine
    if wine is None:
        wine = Path(configured) if configured else (
            local if local.is_file() else Path(system) if system else installed
        )
    try:
        wine = wine.expanduser().resolve(strict=True)
        exe = args.exe.expanduser().resolve(strict=True)
        if not exe.is_file() or exe.suffix.lower() != ".exe":
            raise ValueError("choose a Windows .exe file")
        env = os.environ.copy()
        if args.prefix:
            env["WINEPREFIX"] = str(args.prefix.expanduser().resolve())
        elif wine == local:
            env.setdefault("WINEPREFIX", str(ROOT / "wine-prefix"))
            env.setdefault("WINEDLLOVERRIDES", "mscoree,mshtml=")
        env.setdefault("WINEDEBUG", "-all")
        env.setdefault("MVK_CONFIG_LOG_LEVEL", "0")
        os.execve(wine, [str(wine), str(exe), *args.arguments], env)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Could not launch with Wine: {error}. See WINDOWS.md for setup.\n")


if __name__ == "__main__":
    main()
