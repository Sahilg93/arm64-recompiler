#!/usr/bin/env python3
"""Build a native module for the console runner's on-demand DLL loader."""

import argparse
import os
from pathlib import Path
import subprocess

import pefile

from build_console_modules import build_plugin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        ranges = [tuple(map(int, item.split(":")))
                  for item in os.environ["ARM64_RECOMPILER_GUEST_RANGES"].split(",")]
        build_plugin(args.dll, args.output, ranges)
    except (KeyError, ValueError, pefile.PEFormatError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
