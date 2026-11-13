#!/usr/bin/env python3
"""Build a verified Apple Silicon library from a supported Windows x64 export."""

import argparse
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

import pefile
from unicorn import UcError

from export_lift import ExportLift, read_export

ROOT = Path(__file__).resolve().parent
WRITERS = {f"XXH{width}_canonicalFromHash": width for width in (32, 64, 128)}
EXPORTS = ("sqlite3_stricmp", *WRITERS)


def build(dll, name, output, *, capture=False):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("run this command with native ARM64 Python on macOS")
    if output.suffix != ".dylib":
        raise ValueError("the output path must end in .dylib")
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    width = WRITERS.get(name)
    image, entry, section = read_export(dll, name)
    ir = ExportLift(image, writable=width is not None).emit_export(image, entry, section)
    if width:
        ir += f"define i32 @recompiler_hash_width() {{ ret i32 {width} }}\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".recompile-", dir=output.parent) as staging:
        source = Path(staging) / "lifted.ll"
        library = Path(staging) / output.name
        source.write_text(ir)
        runtime = ROOT / ("writer_runtime.c" if width else "export_runtime.c")
        subprocess.run(
            ["clang", "-arch", "arm64", "-O2", "-Wno-override-module",
             "-dynamiclib", "-install_name", f"@rpath/{output.name}",
             str(source), str(runtime), "-o", str(library)],
            check=True, timeout=120, text=True, capture_output=capture,
        )
        # Keep crashes in a faulty guest or native library out of the CLI process.
        verifier = ROOT / ("verify_writer.py" if width else "verify_export.py")
        arguments = [sys.executable, str(verifier), str(dll), str(library)]
        if width:
            arguments.append(str(width))
        checked = subprocess.run(arguments, check=True, timeout=120, text=True, capture_output=capture)
        output.hardlink_to(library)
    if not capture:
        print(f"Verified ARM64 library: {output}")
    return checked.stdout.strip() if capture else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path, help="trusted Windows x64 PE DLL")
    parser.add_argument("export", choices=EXPORTS)
    parser.add_argument("-o", "--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.dll.resolve(strict=True), args.export, args.output.absolute())
    except (OSError, ValueError, pefile.PEFormatError, UcError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Recompilation failed: {error}\n")


if __name__ == "__main__":
    main()
