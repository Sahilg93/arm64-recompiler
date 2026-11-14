#!/usr/bin/env python3
"""Build an ARM64 console runner with precompiled x64 Windows DLLs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import pefile

from console_lift import ConsoleLift, read_console_image


def lift_module(path, image, index, work, registry, load_base):
    name = path.name
    if not name.isascii() or len(name) > 128 or not name.lower().endswith(".dll"):
        raise ValueError(f"unsupported DLL filename {name!r}")
    if not image.is_dll() or not image.OPTIONAL_HEADER.AddressOfEntryPoint:
        raise ValueError(f"{path}: expected a DLL with an entry point")
    if any(hasattr(image, directory) for directory in
           ("DIRECTORY_ENTRY_TLS", "DIRECTORY_ENTRY_DELAY_IMPORT", "DIRECTORY_ENTRY_LOAD_CONFIG")):
        raise ValueError(f"{path}: DLL uses unsupported loader metadata")
    tls_imports = {b"TlsAlloc", b"TlsGetValue", b"TlsSetValue", b"TlsFree"}
    imports = []
    image_base = image.OPTIONAL_HEADER.ImageBase
    for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
        dependency = dll.dll.decode("ascii")
        if dll.dll.lower() == b"kernel32.dll":
            if any(item.name not in tls_imports for item in dll.imports):
                raise ValueError(f"{path}: unsupported Kernel32 import")
            continue
        if not dependency.lower().endswith(".dll") or any(c in dependency for c in "/\\:"):
            raise ValueError(f"{path}: unsupported dependency name {dependency!r}")
        for item in dll.imports:
            symbol = json.dumps(item.name.decode("ascii")) if item.name else "NULL"
            imports.append(f"    {{{json.dumps(dependency)}, {symbol}, {item.ordinal or 0}, {load_base + item.address - image_base}ULL}},")

    tag = f"module_{index}"
    entry, base, code, data = read_console_image(image, load_base=load_base)
    lifter = ConsoleLift(image, stub_unknown=False)
    lifter.image_base = load_base
    ir = lifter.emit_console(entry, base, code, data, module=tag)
    llvm = work / f"{tag}.ll"
    llvm.write_text(ir)
    exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    symbols = exports.symbols if exports else ()
    code_section = image.get_section_by_rva(entry)
    export_rows = []
    for symbol in symbols:
        if symbol.forwarder or not code_section.contains_rva(symbol.address):
            raise ValueError(f"{path}: unsupported forwarded or non-code export")
        label = json.dumps(symbol.name.decode("ascii")) if symbol.name else "NULL"
        export_rows.append(f"    {{{label}, {symbol.ordinal}, {load_base + symbol.address}ULL}},")
    registry.extend((
        f"extern const struct section {tag}_guest_sections[];",
        f"extern const struct guest_dispatch_entry {tag}_guest_dispatch_table[];",
        f"extern void {tag}_entry(void *, uint64_t);",
        f"static const struct guest_module_export {tag}_exports[] = {{",
        *export_rows,
        "};",
        f"static const struct guest_module_import {tag}_imports[] = {{",
        *imports,
        "};",
        f"static const unsigned char {tag}_file[] = {{",
    ))
    payload = bytes(image.__data__)
    for offset in range(0, len(payload), 24):
        registry.append("    " + ", ".join(map(str, payload[offset:offset + 24])) + ",")
    registry.append("};")
    exception = image.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    row = (
        f"{{.name = {json.dumps(name)}, .base = {load_base}ULL, "
        f".size = {image.OPTIONAL_HEADER.SizeOfImage}, "
        f".exception_rva = {exception.VirtualAddress}, .exception_size = {exception.Size}, "
        f".file = {tag}_file, .file_size = sizeof {tag}_file, "
        f".sections = {tag}_guest_sections, .section_count = {len(data)}, "
        f".dispatch = {tag}_guest_dispatch_table, .dispatch_count = {len(lifter.functions)}, "
        f".exports = {tag}_exports, .export_count = {len(export_rows)}, .entry = {tag}_entry, "
        f".imports = {tag}_imports, .import_count = {len(imports)}}}"
    )
    return llvm, row


def module_range(path, image, ranges):
    preferred = image.OPTIONAL_HEADER.ImageBase
    size = image.OPTIONAL_HEADER.SizeOfImage
    if 0x100000000 <= preferred and preferred + size <= 1 << 47 and all(
        preferred >= high or preferred + size <= low for low, high in ranges
    ):
        return preferred, preferred + size
    if (image.FILE_HEADER.Characteristics & 1
            or not getattr(image, "DIRECTORY_ENTRY_BASERELOC", ())):
        raise ValueError(f"{path}: image cannot be relocated from {preferred:#x}")
    base = 0x100000000
    for low, high in sorted(ranges):
        if base + size <= low:
            break
        base = max(base, (high + 0xffff) & ~0xffff)
    if base + size > 1 << 47:
        raise ValueError(f"{path}: image exceeds the guest DLL address range")
    return base, base + size


def build_plugin(path, output_path, ranges):
    root = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix=".console-plugin-", dir=output_path.parent) as folder:
        work = Path(folder)
        image = pefile.PE(str(path))
        base, _ = module_range(path, image, ranges)
        registry = ['#include "console_modules.h"']
        llvm, row = lift_module(path, image, 0, work, registry, base)
        source = work / "registry.c"
        source.write_text("\n".join((*registry, f"struct guest_module translated_guest_module = {row};", "")))
        output = work / "plugin.dylib"
        subprocess.run(["clang", "-arch", "arm64", "-O2", "-dynamiclib",
                        "-undefined", "dynamic_lookup", "-Wno-override-module",
                        "-I", str(root), str(source), str(llvm), "-o", str(output)], check=True)
        output.replace(output_path)


def cache_key(exe_path, dll_paths, lazy_modules, trace):
    hasher = hashlib.sha256()
    root = Path(__file__).resolve().parent
    hasher.update(str(exe_path.resolve()).encode("utf-8"))
    st = exe_path.stat()
    hasher.update(str(st.st_mtime_ns).encode("utf-8"))
    hasher.update(str(st.st_size).encode("utf-8"))
    lift_py = root / "console_lift.py"
    if lift_py.exists():
        hasher.update(str(lift_py.stat().st_mtime_ns).encode("utf-8"))
    shims_h = root / "generated_shims.h"
    if shims_h.exists():
        hasher.update(str(shims_h.stat().st_mtime_ns).encode("utf-8"))
    subsys_h = root / "console_subsystems.h"
    if subsys_h.exists():
        hasher.update(str(subsys_h.stat().st_mtime_ns).encode("utf-8"))
    hasher.update(f"{lazy_modules}_{trace}".encode("utf-8"))
    for dll in sorted(dll_paths):
        p = Path(dll)
        if p.exists():
            hasher.update(str(p.resolve()).encode("utf-8"))
            hasher.update(str(p.stat().st_mtime_ns).encode("utf-8"))
    return hasher.hexdigest()[:16]


def build(exe_path, output_path, dll_paths, *, lazy_modules=False, trace=False):
    root = Path(__file__).resolve().parent
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cache_dir = root / ".cache"
    no_cache = bool(os.environ.get("ARM64_RECOMPILER_NO_CACHE"))
    if not no_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        key = cache_key(exe_path, dll_paths, lazy_modules, trace)
        cached_o = cache_dir / f"{exe_path.stem}_{key}.o"
        cached_reg = cache_dir / f"{exe_path.stem}_{key}_reg.c"
        if cached_o.exists() and (not dll_paths or cached_reg.exists()):
            extra = [str(cached_reg)] if dll_paths else []
            subprocess.run(["clang", "-arch", "arm64", "-O2", "-Wno-override-module",
                            "-I", str(root), str(root / "console_runtime.c"),
                            str(cached_o), *extra, "-o", str(output_path)], check=True)
            return

    with tempfile.TemporaryDirectory(prefix=".console-modules-", dir=output_path.parent) as folder:
        work = Path(folder)
        exe = pefile.PE(str(exe_path))
        if exe.is_dll():
            raise ValueError("first input must be an executable")
        primary = work / "main.ll"
        primary_image = read_console_image(exe)
        modules = [primary]
        exe_base = exe.OPTIONAL_HEADER.ImageBase
        ranges = [(exe_base, exe_base + 0x20000000)]
        names = set()
        registry = ['#include "console_modules.h"']
        rows = []
        images = [(path, pefile.PE(str(path))) for path in dll_paths]
        images.sort(key=lambda item: item[1].OPTIONAL_HEADER.ImageBase)
        for index, (path, image) in enumerate(images):
            base, end = module_range(path, image, ranges)
            if path.name.lower() in names:
                raise ValueError(f"{path}: duplicate DLL filename")
            llvm, row = lift_module(path, image, index, work, registry, base)
            names.add(path.name.lower())
            ranges.append((base, end))
            modules.append(llvm)
            rows.append(f"    {row},")
        lifter = ConsoleLift(exe, modules=bool(rows) or lazy_modules, trace=trace, fault_delivery=lazy_modules)
        primary.write_text(lifter.emit_console(*primary_image))
        source = None
        if rows:
            source = work / "registry.c"
            source.write_text("\n".join((*registry, "static struct guest_module modules[] = {",
                                         *rows, "};",
                                         "struct guest_module *guest_modules = modules;",
                                         f"const size_t guest_module_count = {len(rows)};", "")))
            modules.append(source)
        output = work / "runner"
        primary_object = work / "main.o"
        subprocess.run(["clang", "-arch", "arm64", "-O0", "-Wno-override-module",
                        "-c", str(primary), "-o", str(primary_object)], check=True)
        modules[0] = primary_object
        if not no_cache:
            import shutil
            shutil.copyfile(primary_object, cached_o)
            if source and source.exists():
                shutil.copyfile(source, cached_reg)
        subprocess.run(["clang", "-arch", "arm64", "-O2", "-Wno-override-module",
                        "-I", str(root), str(root / "console_runtime.c"),
                        *map(str, modules), "-o", str(output)], check=True)
        output.replace(output_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("dll", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        build(args.exe, args.output, args.dll)
    except (ValueError, pefile.PEFormatError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
