#!/usr/bin/env python3
"""Translate and run a Windows x64 EXE with supported DLLs from its folder."""

import argparse
import os
import sys
from pathlib import Path
import subprocess
import tempfile

import pefile

from build_console_modules import build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", action="store_true",
                        help="report the guest address when execution reaches unsupported code")
    parser.add_argument("exe", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    exe = args.exe.absolute()
    try:
        helper = Path(__file__).resolve().with_name("translate_console_plugin.py")
        with tempfile.TemporaryDirectory(prefix="arm64-exe-") as folder:
            runner = Path(folder) / "runner"
            build(exe, runner, (), lazy_modules=True, trace=args.trace)
            env = {**os.environ, "ARM64_RECOMPILER_PYTHON": sys.executable,
                   "ARM64_RECOMPILER_PLUGIN_HELPER": str(helper),
                   "ARM64_RECOMPILER_PLUGIN_DIR": folder}
            result = subprocess.run([str(exe), *args.arguments], executable=runner,
                                    cwd=exe.parent, env=env)
    except (ValueError, pefile.PEFormatError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
