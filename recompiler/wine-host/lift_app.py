#!/usr/bin/env python3
"""Lift a Windows GUI program with the Wine DLLs it imports, and optionally run it
hosted on Wine's unix side (see build.sh).

usage: lift_app.py EXE OUTDIR [--dll NAME ...] [--run [ARGS ...]]
  --dll   also lift this Wine DLL (one the program loads with LoadLibrary)
  --delay-depth N  how many levels of delay imports to lift as well (default 1)
  --trace  accept program code the lifter cannot translate; it traps, reporting
           the guest address, only if execution reaches it
  --run   start the lifted program afterwards with the hosted environment
Env: WINE_ROOT (x86-64 Wine 11.0 root), WINE_HOST_WORK (build.sh's work folder).
"""
import argparse
import os
from pathlib import Path
import shutil
import struct
import sys

import pefile

TOOL = Path(__file__).resolve().parent.parent
REPOSITORY = TOOL.parent
sys.path.insert(0, str(TOOL))
from build_console_modules import build, resolve_api_set  # noqa: E402

# Always present in a hosted process: the base system and the display driver,
# which win32u loads by name.
BASE = ("ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll", "msvcrt.dll", "advapi32.dll",
        "sechost.dll", "win32u.dll", "gdi32.dll", "user32.dll", "winemac.drv")


def delayed_imports(image):
    """DLL names of a Wine DLL's delay imports.

    winebuild keeps its delay-load descriptors out of the PE data directory, so
    find them by shape: attributes 1 (RVA based), then RVAs of the DLL name,
    module handle, import address table and name table, and three zero fields.
    """
    found = set()
    size = image.OPTIONAL_HEADER.SizeOfImage
    for section in image.sections:
        if section.Characteristics & 0x20000000:  # code
            continue
        data = section.get_data()
        for offset in range(0, len(data) - 31, 4):
            fields = struct.unpack_from("<8I", data, offset)
            if fields[0] != 1 or any(fields[5:]) or not all(0 < rva < size for rva in fields[1:5]):
                continue
            try:
                name = image.get_string_at_rva(fields[1], 64).decode("ascii").lower()
            except (pefile.PEFormatError, UnicodeDecodeError, AttributeError):
                continue
            if name.endswith((".dll", ".drv")) and all(c.isalnum() or c in "._-" for c in name):
                found.add(name)
    return found


def closure(exe, wine_dlls, extra, delay_depth):
    """Wine DLLs the program needs: BASE, extra, and everything they import.

    Delay imports are followed delay_depth levels deep: a delay-loaded DLL comes
    with the DLLs it imports, but its own delay imports count as the next level.
    """
    found = {}
    pending = [(exe, 0)] + [(wine_dlls / name, 0) for name in (*BASE, *extra)]
    while pending:
        path, depth = pending.pop()
        if path != exe:
            if not path.is_file() or found.get(path.name.lower(), delay_depth + 1) <= depth:
                continue
            found[path.name.lower()] = depth
        image = pefile.PE(str(path), fast_load=True)
        image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                                  pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        for entry in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
            pending.append((wine_dlls / resolve_api_set(entry.dll.decode("ascii")), depth))
        # Exports forwarded to another DLL ("cryptbase.SystemFunction036") need that DLL too.
        exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
        forwarded = {symbol.forwarder.decode("ascii").rsplit(".", 1)[0].lower()
                     for symbol in (exports.symbols if exports else ()) if symbol.forwarder}
        pending.extend((wine_dlls / resolve_api_set(name), depth) for name in forwarded)
        if depth < delay_depth:
            pending.extend((wine_dlls / name, depth + 1) for name in delayed_imports(image))
    return {name: wine_dlls / name for name in found}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", type=Path)
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--dll", action="append", default=[])
    parser.add_argument("--delay-depth", type=int, default=1)
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--run", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    wine_root = Path(os.environ.get("WINE_ROOT") or
                     REPOSITORY / "work/wine/Wine Stable.app/Contents/Resources/wine")
    work = Path(os.environ.get("WINE_HOST_WORK") or REPOSITORY / "work/wine-host")
    wine_dlls = wine_root / "lib/wine/x86_64-windows"
    out = args.outdir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    exe = out / args.exe.name
    if args.exe.resolve() != exe:
        shutil.copyfile(args.exe, exe)
    paths = []
    for name, source in sorted(closure(exe, wine_dlls, args.dll, args.delay_depth).items()):
        shutil.copyfile(source, out / name)
        paths.append(out / name)
    runner = out / exe.stem
    build(exe, runner, paths, trace=args.trace)
    print(f"lifted {exe.name} with {len(paths)} DLLs: {runner}", file=sys.stderr)
    if args.run is None:
        return 0
    prefix = os.environ.get("WINEPREFIX") or str(work / "gui-prefix")
    env = dict(os.environ, ARM64_RECOMPILER_WINE_HOST=str(work / "host/lib/wine/x86_64-unix"),
               ARM64_RECOMPILER_WINE_EXE=str(exe), WINEPREFIX=prefix,
               WINESERVER=str(wine_root / "bin/wineserver"), WINELOADER=str(wine_root / "bin/wine"))
    env.setdefault("WINEDEBUG", "-all")
    env.setdefault("MVK_CONFIG_LOG_LEVEL", "0")
    env.setdefault("DYLD_FALLBACK_LIBRARY_PATH", "/opt/homebrew/lib:/usr/local/lib:/usr/lib")
    os.chdir(out)
    os.execve(str(runner), [str(runner), *args.run], env)


if __name__ == "__main__":
    raise SystemExit(main())
