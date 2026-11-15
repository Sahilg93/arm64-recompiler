#!/usr/bin/env python3
"""Convert supported exports and console programs from trusted Windows x64 files."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

import pefile

from console_lift import ConsoleLift, loader_requirements, read_console_image
from recompile import EXPORTS, ROOT, build


def compile_console(path, image, output):
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    if image.OPTIONAL_HEADER.Subsystem != 3:
        raise ValueError("only Windows console executables are supported")
    requirements = loader_requirements(image)
    if requirements:
        raise ValueError("unsupported loader features: " + ", ".join(requirements))
    ir = ConsoleLift(image).emit_console(*read_console_image(image))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".convert-", dir=output.parent) as folder:
        source, native = Path(folder) / "console.ll", Path(folder) / "console"
        source.write_text(ir)
        subprocess.run(
            ["clang", "-arch", "arm64", "-O2", "-Wno-override-module", str(source),
             str(ROOT / "console_runtime.c"), "-o", str(native)],
            check=True, timeout=120, capture_output=True, text=True,
        )
        result = subprocess.run(
            [sys.executable, str(ROOT / "verify_console.py"), str(path), str(native)],
            check=True, timeout=30, capture_output=True, text=True,
        )
        output.hardlink_to(native)
    return result.stdout.strip()


def detail(error):
    if isinstance(error, subprocess.CalledProcessError):
        lines = (error.stderr or error.stdout or "").strip().splitlines()
        if lines:
            return lines[-1][:500]
    return str(error)


ERRORS = (ValueError, OSError, pefile.PEFormatError, subprocess.SubprocessError)


def convert(path, destination):
    record = {"input": str(path), "artifacts": [], "failures": []}
    try:
        image = pefile.PE(str(path))
        if (image.FILE_HEADER.Machine, image.OPTIONAL_HEADER.Magic) != (0x8664, 0x20B):
            raise ValueError("expected a Windows x64 PE32+ image")
        digest = sha256(path.read_bytes()).hexdigest()
        record["sha256"] = digest
        folder = destination / f"{path.stem}-{digest[:12]}"
        if image.FILE_HEADER.Characteristics & 0x2000:
            directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
            names = {item.name for item in directory.symbols if not item.forwarder} if directory else set()
            targets = [name for name in EXPORTS if name.encode() in names]
            if not targets:
                raise ValueError("no recognized export signatures")
            for name in targets:
                output = folder / f"{name}.dylib"
                try:
                    result = build(path, name, output, capture=True)
                    record["artifacts"].append({"path": str(output), "verification": result})
                except ERRORS as error:
                    record["failures"].append({"export": name, "reason": detail(error)})
        else:
            output = folder / path.stem
            result = compile_console(path, image, output)
            record["artifacts"].append({"path": str(output), "verification": result})
    except ERRORS as error:
        record["failures"].append({"reason": detail(error)})
    record["status"] = ("partial" if record["failures"] else "converted") if record["artifacts"] else "failed"
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="trusted files or folders")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("run with native ARM64 Python on macOS")
    files = set()
    for path in args.inputs:
        if not path.exists():
            parser.error(f"input does not exist: {path}")
        if path.is_dir():
            files.update(item.resolve() for item in path.rglob("*")
                         if item.suffix.lower() in {".exe", ".dll"} and item.is_file())
        else:
            files.add(path.resolve())
    if not files:
        parser.error("no Windows files found")
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(files):
        record = convert(path, destination)
        records.append(record)
        reasons = "; ".join(item["reason"] for item in record["failures"])
        print(f"{record['status']}: {path.name}" + (f" ({reasons})" if reasons else ""), flush=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=destination, delete=False) as report:
        json.dump(records, report, indent=2)
        report.write("\n")
    report_path = destination / "conversion-report.json"
    Path(report.name).replace(report_path)
    print(f"Report: {report_path}")
    return int(any(record["status"] != "converted" for record in records))


if __name__ == "__main__":
    raise SystemExit(main())
