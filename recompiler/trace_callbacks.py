#!/usr/bin/env python3
"""Iteratively lift diagnostic PE startup paths and observed internal callbacks."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import sys

import pefile

from console_lift import ConsoleLift, find_switch_tables, loader_requirements, read_console_image, relocated_code_pointers

ROOT = Path(__file__).resolve().parent
INDIRECT = re.compile(r"RVA (0x[0-9a-f]+): unsupported indirect call target (0x[0-9a-f]+)")


def trace(path, arguments, max_attempts):
    image = pefile.PE(str(path))
    requirements = loader_requirements(image)
    if requirements:
        raise ValueError(", ".join(requirements))
    source = read_console_image(image)
    eligible = relocated_code_pointers(image)
    code = image.get_section_by_rva(source[0])
    eligible.update(row.struct.BeginAddress
                    for row in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", ())
                    if code.contains_rva(row.struct.BeginAddress))
    targets = find_switch_tables(image)
    with tempfile.TemporaryDirectory() as folder:
        ir = Path(folder) / "startup.ll"
        native = Path(folder) / "startup"
        for attempt in range(max_attempts):
            ir.write_text(ConsoleLift(image, trace=True, callback_targets=targets).emit_console(*source))
            subprocess.run(["clang", "-arch", "arm64", "-O0", "-Wno-override-module",
                            str(ir), str(ROOT / "console_runtime.c"), "-o", str(native)],
                           check=True, timeout=180)
            result = subprocess.run([str(native), *arguments], capture_output=True,
                                    text=True, timeout=10)
            diagnostics = result.stderr.strip().splitlines()
            match = INDIRECT.fullmatch(diagnostics[-1]) if diagnostics else None
            if result.returncode == 125 and match:
                site, target = (int(value, 16) for value in match.groups())
                if (target in eligible or code.contains_rva(target)) and target not in targets.get(site, ()):
                    targets.setdefault(site, set()).add(target)
                    print(f"Discovered callback RVA {target:#x} at call RVA {site:#x}", flush=True)
                    continue
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            return result.returncode
    raise ValueError(f"callback discovery limit reached after {max_attempts} attempts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-attempts", type=int, default=24)
    parser.add_argument("pe", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    try:
        return trace(options.pe, options.arguments, options.max_attempts)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
