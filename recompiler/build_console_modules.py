#!/usr/bin/env python3
"""Build an ARM64 console runner with precompiled x64 Windows DLLs."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import pefile

from console_lift import ConsoleLift, read_console_image

# DLLs the runtime implements with named shims instead of lifted guest code.
SYSTEM_DLLS = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "advapi32.dll", "bcrypt.dll",
    "ws2_32.dll", "user32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
    "userenv.dll", "secur32.dll", "crypt32.dll", "shlwapi.dll", "dbghelp.dll",
}
# API-set contracts the runtime treats as system DLLs (redirected to kernelbase/ntdll on Windows).
SYSTEM_API_SET_PREFIXES = ("api-ms-win-core-", "api-ms-win-security-", "api-ms-win-eventing-",
                           "api-ms-win-appmodel-", "ext-ms-win-")


def resolve_api_set(name):
    """Map an import DLL name to the DLL that implements it, like the API-set schema."""
    lower = name.lower()
    if not lower.endswith((".dll", ".drv")):
        lower += ".dll"
    if lower.startswith("api-ms-win-crt-"):
        return "ucrtbase.dll"
    return lower


# System DLLs that become lifted guest modules when the program supplies them
# (shipped beside it, or passed explicitly). The runtime still implements their
# syscalls and process-global state (see system_overrides).
LIFTABLE_SYSTEM_DLLS = {"ntdll.dll", "kernelbase.dll",
                        # Wine's GUI stack and the DLLs under it, for programs that run hosted
                        # on Wine's unix side (see wine-host/): win32u.dll is the syscall
                        # boundary, served natively by win32u.so.
                        "user32.dll", "gdi32.dll", "win32u.dll", "kernel32.dll", "advapi32.dll",
                        "sechost.dll", "shell32.dll", "shlwapi.dll", "ole32.dll",
                        # Wine's own, over its unix side: ws2_32.dll reaches sockets through
                        # ntdll's NtDeviceIoControlFile and ws2_32.so.
                        "ws2_32.dll", "oleaut32.dll", "userenv.dll"}

# ntdll exports the runtime implements: they own process-global state (heaps,
# last error, locks, TLS/FLS, loader, exceptions) that must stay shared with the
# runtime's kernel32 shims. Wine's pure-PE Rtl code covers everything else.
NTDLL_RUNTIME_EXPORTS = {
    "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap", "RtlSizeHeap", "RtlCreateHeap",
    "RtlDestroyHeap", "RtlLockHeap", "RtlUnlockHeap", "RtlValidateHeap", "RtlCompactHeap",
    "RtlGetProcessHeaps", "RtlSetHeapInformation", "RtlQueryHeapInformation", "RtlWalkHeap",
    "RtlSetUserValueHeap", "RtlGetUserInfoHeap", "RtlSetUserFlagsHeap",
    "RtlInitializeCriticalSection", "RtlInitializeCriticalSectionAndSpinCount",
    "RtlInitializeCriticalSectionEx", "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
    "RtlTryEnterCriticalSection", "RtlDeleteCriticalSection", "RtlIsCriticalSectionLocked",
    "RtlIsCriticalSectionLockedByThread",
    "RtlInitializeSRWLock", "RtlAcquireSRWLockExclusive", "RtlReleaseSRWLockExclusive",
    "RtlAcquireSRWLockShared", "RtlReleaseSRWLockShared", "RtlTryAcquireSRWLockExclusive",
    "RtlTryAcquireSRWLockShared", "RtlInitializeConditionVariable", "RtlWakeConditionVariable",
    "RtlWakeAllConditionVariable", "RtlSleepConditionVariableSRW", "RtlSleepConditionVariableCS",
    "RtlWaitOnAddress", "RtlWakeAddressSingle", "RtlWakeAddressAll",
    "RtlGetLastWin32Error", "RtlSetLastWin32Error", "RtlRestoreLastWin32Error",
    "RtlSetLastWin32ErrorAndNtStatusFromNtStatus",
    "RtlFlsAlloc", "RtlFlsFree", "RtlFlsGetValue", "RtlFlsSetValue",
    "RtlRaiseException", "RtlCaptureContext", "RtlLookupFunctionEntry", "RtlVirtualUnwind",
    "RtlPcToFileHeader", "RtlAddVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler",
    "RtlUnwind", "RtlUnwindEx", "RtlRestoreContext",
    "RtlQueryPerformanceCounter", "RtlQueryPerformanceFrequency", "RtlGetTickCount",
    "RtlExitUserProcess", "RtlExitUserThread",
    "LdrLoadDll", "LdrGetDllHandle", "LdrGetDllHandleEx", "LdrGetProcedureAddress", "LdrUnloadDll",
    "LdrAddRefDll", "LdrLockLoaderLock", "LdrUnlockLoaderLock", "LdrFindEntryForAddress",
    "LdrGetDllFullName", "LdrGetDllPath", "LdrShutdownProcess",
    "LdrShutdownThread", "LdrInitializeThunk", "LdrRegisterDllNotification",
    "LdrUnregisterDllNotification", "LdrQueryProcessModuleInformation",
    # LdrFindResource_U, LdrFindResourceDirectory_U and LdrAccessResource stay lifted:
    # they only walk the mapped image's resource directory. LdrResolveDelayLoadedAPI
    # stays lifted too: it resolves through LdrLoadDll and LdrGetProcedureAddress.
    # Debug channels: the runtime drops messages unless ARM64_RECOMPILER_WINE_DEBUG is set.
    "__wine_dbg_get_channel_flags", "__wine_dbg_header", "__wine_dbg_strdup", "__wine_dbg_output",
}


def syscall_number(image, rva):
    """The service number of a Wine/Windows syscall stub (mov r10, rcx; mov eax, N), else None."""
    head = image.get_data(rva, 8)
    if len(head) == 8 and head[:4] == b"\x4c\x8b\xd1\xb8":
        return int.from_bytes(head[4:8], "little")
    return None


def system_overrides(name, image):
    """RVA -> runtime function name (None: return TRUE) for a liftable system DLL."""
    if name.lower() not in ("ntdll.dll", "win32u.dll"):
        return {}
    overrides = {}
    exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    if name.lower() == "win32u.dll":
        # Every NtUser*/NtGdi* export is a syscall stub; its DllMain stays lifted.
        for symbol in exports.symbols if exports else ():
            if symbol.name and not symbol.forwarder and syscall_number(image, symbol.address) is not None:
                overrides[symbol.address] = symbol.name.decode("ascii")
        return overrides
    for symbol in exports.symbols if exports else ():
        if not symbol.name or symbol.forwarder:
            continue
        label = symbol.name.decode("ascii")
        if syscall_number(image, symbol.address) is not None:
            # Zw* aliases share the Nt* stub; name the override after Nt*.
            overrides[symbol.address] = "Nt" + label[2:] if label.startswith("Zw") else label
        elif label in NTDLL_RUNTIME_EXPORTS:
            overrides[symbol.address] = label
    # The runtime loader owns loader state; Wine's DllMain would walk its own lists.
    overrides[image.OPTIONAL_HEADER.AddressOfEntryPoint] = None
    return overrides


def is_system_dll(name, available=()):
    resolved = resolve_api_set(name)
    # Only the DLL's own name selects the lifted copy; API-set contracts stay on the runtime.
    if resolved in LIFTABLE_SYSTEM_DLLS and resolved in available:
        return False
    return resolved in SYSTEM_DLLS or resolved.startswith(SYSTEM_API_SET_PREFIXES)


def bound_import_dlls(image, available):
    """Import DLL names (lowercase, as written) whose slots bind to lifted guest modules.

    available holds lowercase names of DLLs that can be lifted (shipped beside
    the program or passed explicitly). Everything else stays on runtime shims.
    """
    bound = set()
    for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
        name = dll.dll.decode("ascii")
        if not is_system_dll(name, available) and resolve_api_set(name) in available:
            bound.add(name.lower())
    return bound


def lift_module(path, image, work, registry, load_base, trace=False, available=None):
    name = path.name
    if not name.isascii() or len(name) > 128 or not name.lower().endswith((".dll", ".drv")):
        raise ValueError(f"unsupported DLL filename {name!r}")
    if not image.is_dll() or not image.OPTIONAL_HEADER.AddressOfEntryPoint:
        raise ValueError(f"{path}: expected a DLL with an entry point")
    # Load configuration (security cookie, CFG tables) needs no loader work here.
    if any(hasattr(image, directory) for directory in
           ("DIRECTORY_ENTRY_TLS", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        raise ValueError(f"{path}: DLL uses unsupported loader metadata")
    if available is None:
        # On-demand translation: the DLLs beside this one are the program's.
        folder = Path(path).resolve().parent
        available = {item.name.lower() for item in folder.iterdir() if item.suffix.lower() == ".dll"}
    imports = []
    bound = set()
    image_base = image.OPTIONAL_HEADER.ImageBase
    for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
        dependency = dll.dll.decode("ascii")
        if any(c in dependency for c in "/\\:"):
            raise ValueError(f"{path}: unsupported dependency name {dependency!r}")
        if is_system_dll(dependency, available):
            # Calls go to the runtime's named shims; the runtime still fills these
            # slots with named tokens so code that loads a slot can call it.
            target = dependency.lower()
        else:
            bound.add(dependency.lower())
            target = resolve_api_set(dependency)
        for item in dll.imports:
            symbol = json.dumps(item.name.decode("ascii")) if item.name else "NULL"
            imports.append(f"    {{{json.dumps(target)}, {symbol}, {item.ordinal or 0}, {load_base + item.address - image_base}ULL}},")

    tag = module_tag(name)
    entry, base, code, data = read_console_image(image, load_base=load_base)
    # Real system DLLs contain code the lifter cannot translate yet; trap there only if it runs.
    lifter = ConsoleLift(image, stub_unknown=False, tolerant=True, bound_dlls=bound, trace=trace,
                         overrides=system_overrides(name, image))
    lifter.image_base = load_base
    ir = lifter.emit_console(entry, base, code, data, module=tag)
    llvm = work / f"{tag}.ll"
    llvm.write_text(ir)
    exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    symbols = exports.symbols if exports else ()
    export_rows = []
    for symbol in symbols:
        label = json.dumps(symbol.name.decode("ascii")) if symbol.name else "NULL"
        if symbol.forwarder:
            # "DLL.Name" or "DLL.#ordinal"; the runtime resolves it when looked up.
            forwarder = json.dumps(symbol.forwarder.decode("ascii"))
            export_rows.append(f"    {{{label}, {symbol.ordinal}, 0, {forwarder}}},")
        else:
            # Code and data exports alike resolve to their guest address.
            export_rows.append(f"    {{{label}, {symbol.ordinal}, {load_base + symbol.address}ULL, NULL}},")
    registry.extend((
        f"extern const struct section {tag}_guest_sections[];",
        f"extern unsigned char {tag}_guest_image[];",
        f"extern const struct guest_dispatch_entry {tag}_guest_dispatch_table[];",
        f"extern void {tag}_entry(void *, uint64_t);",
        f"static const struct guest_module_export {tag}_exports[] = {{",
        *export_rows,
        "};",
        f"static const struct guest_module_import {tag}_imports[] = {{",
        *imports,
        "};",
    ))
    # The runtime checks that the DLL beside the program is the one lifted here.
    payload = bytes(image.__data__)
    digest = ", ".join(map(str, hashlib.sha256(payload).digest()))
    exception = image.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    row = (
        f"{{.name = {json.dumps(name)}, .base = {load_base}ULL, "
        f".size = {image.OPTIONAL_HEADER.SizeOfImage}, "
        f".exception_rva = {exception.VirtualAddress}, .exception_size = {exception.Size}, "
        f".file_hash = {{{digest}}}, .file_size = {len(payload)}, .image = {tag}_guest_image, "
        f".sections = {tag}_guest_sections, .section_count = {len(data)}, "
        f".dispatch = {tag}_guest_dispatch_table, .dispatch_count = {len(lifter.functions)}, "
        f".exports = {tag}_exports, .export_count = {len(export_rows)}, .entry = {tag}_entry, "
        f".imports = {tag}_imports, .import_count = {len(imports)}}}"
    )
    return llvm, row


# Optimization level for the lifted DLLs and the runtime.
MODULE_FLAGS = ("-O2",)


def program_flags():
    """Optimization level for the program's own lifted code (ARM64_RECOMPILER_PROGRAM_OPT)."""
    return (os.environ.get("ARM64_RECOMPILER_PROGRAM_OPT") or "-O2",)


def compile_program(source, target, no_cache=False):
    """Compile the program's lifted IR to an object, reusing one built from the same IR.

    The program is one large translation unit, which clang optimizes on a single
    thread: about a minute for PuTTY's size. The object is kept in the module
    store under the hash of the IR and the flags, so only the first build of a
    program (or of a changed lifter) pays for it.
    """
    import shutil
    flags = program_flags()
    cached = None
    if not no_cache:
        hasher = hashlib.sha256(Path(source).read_bytes())
        hasher.update(repr(flags).encode())
        hasher.update(subprocess.run(["clang", "--version"], capture_output=True).stdout)
        store = module_store()
        store.mkdir(parents=True, exist_ok=True)
        cached = store / f"program_{hasher.hexdigest()[:24]}.o"
        if cached.exists():
            shutil.copyfile(cached, target)
            return
    subprocess.run(["clang", "-arch", "arm64", *flags, "-Wno-override-module",
                    "-c", str(source), "-o", str(target)], check=True)
    if cached:
        scratch = cached.with_name(f".{cached.name}.{os.getpid()}")
        shutil.copyfile(target, scratch)
        scratch.replace(cached)


def compile_parallel(sources, work, flags=MODULE_FLAGS):
    """Compile independent C / LLVM IR translation units to objects on all cores.

    Lifted modules are large single translation units; clang given several
    inputs compiles them one after another. Objects come back in input order;
    existing objects (*.o) pass through unchanged.
    """
    root = Path(__file__).resolve().parent
    def one(item):
        index, source = item
        source = Path(source)
        if source.suffix == ".o":
            return source
        target = Path(work) / f"unit{index}-{source.stem}.o"
        include = ["-I", str(root)] if source.suffix == ".c" else []
        subprocess.run(["clang", "-arch", "arm64", *flags, "-Wno-override-module", *include,
                        "-c", str(source), "-o", str(target)], check=True)
        return target
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        return list(pool.map(one, enumerate(sources)))


# Guest images are mapped at their own guest addresses inside the host process
# (the runtime's guest_map_fixed), so a base must be free there. On Apple
# Silicon macOS the host executable and its heaps start at 4 GiB, the main
# thread stack sits below 0x170000000, and the kernel reserves
# 0x180000000-0x7000000000 for the dyld shared cache and a guard region
# (vm_allocate there fails even where vmmap shows nothing).
HOST_FREE_RANGES = ((0x140000000, 0x160000000), (1 << 40, 1 << 46))
# Relocated images get a slot picked by their file name, so a DLL loads at the
# same address in every program whatever else is linked beside it. Its lifted
# object (which has the address baked in) is then reusable across programs.
RELOCATION_BASE = 1 << 40
RELOCATION_SLOT = 1 << 30
RELOCATION_SLOTS = (HOST_FREE_RANGES[-1][1] - RELOCATION_BASE) // RELOCATION_SLOT


def module_tag(name):
    """Symbol prefix of a lifted DLL: a function of its file name only."""
    lower = name.lower()
    stem = "".join(c if c.isalnum() else "_" for c in lower)
    return f"module_{stem}_{hashlib.sha256(lower.encode()).hexdigest()[:8]}"


def module_range(path, image, ranges):
    preferred = image.OPTIONAL_HEADER.ImageBase
    size = image.OPTIONAL_HEADER.SizeOfImage
    def free(base):
        return all(base >= high or base + size <= low for low, high in ranges)
    if any(low <= preferred and preferred + size <= high for low, high in HOST_FREE_RANGES) and free(preferred):
        return preferred, preferred + size
    # An image whose relocations were not stripped but has none needs no fixups.
    if image.FILE_HEADER.Characteristics & 1:
        raise ValueError(f"{path}: image cannot be relocated from {preferred:#x}")
    digest = hashlib.sha256(Path(path).name.lower().encode()).digest()
    slot = int.from_bytes(digest[:8], "little") % RELOCATION_SLOTS
    # The next free slot when another image or a live allocation holds this one.
    for _ in range(RELOCATION_SLOTS):
        base = RELOCATION_BASE + slot * RELOCATION_SLOT
        if base + size <= HOST_FREE_RANGES[-1][1] and free(base):
            return base, base + size
        slot = (slot + 1) % RELOCATION_SLOTS
    raise ValueError(f"{path}: image exceeds the guest DLL address range")


def module_cache_key(path, image, base, available, trace, flags):
    """Cache key for one lifted, compiled DLL of a linked build.

    Everything the object depends on: the DLL's bytes and name (its symbol
    prefix), where it loads, which of its imports bind to other lifted DLLs,
    the lifter and build sources, and the compiler flags. Nothing about the
    program or the DLLs it does not import, so programs share these objects.
    """
    root = Path(__file__).resolve().parent
    hasher = hashlib.sha256(Path(path).read_bytes())
    imports = sorted({resolve_api_set(dll.dll.decode("ascii", "replace"))
                      for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ())} & set(available))
    hasher.update(f"{Path(path).name.lower()}@{base}:{int(bool(trace))}:{imports}:{flags}".encode())
    for name in ("console_lift.py", "build_console_modules.py", "console_modules.h", "lift.py"):
        source = root / name
        if source.exists():
            hasher.update(source.read_bytes())
    return hasher.hexdigest()[:24]


def module_store():
    """Folder of lifted DLLs built as shared libraries, shared by every program."""
    # Outside the source tree by default: the store is per user, not per checkout,
    # and a synced folder (iCloud Documents) may evict large libraries from disk.
    store = os.environ.get("ARM64_RECOMPILER_MODULE_STORE")
    return Path(store).resolve() if store else Path.home() / "Library/Caches/arm64-recompiler/modules"


def module_library(path, image, base, available, trace, store):
    """Lift one DLL into a shared library in the store, unless it is there already.

    The library exports its struct guest_module as translated_guest_module and
    takes the runtime's functions from the program that loads it. Programs
    linked against it (build) and on-demand translation (build_plugin) share it.
    """
    key = module_cache_key(path, image, base, available, trace, MODULE_FLAGS)
    library = store / f"module_{key}.dylib"
    if library.exists():
        return library
    store.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".module-", dir=store) as folder:
        work = Path(folder)
        registry = ['#include "console_modules.h"']
        llvm, row = lift_module(path, image, work, registry, base, trace=trace, available=available)
        source = work / "registry.c"
        source.write_text("\n".join((*registry, f"struct guest_module translated_guest_module = {row};", "")))
        output = work / library.name
        objects = compile_parallel([source, llvm], work)
        subprocess.run(["clang", "-arch", "arm64", "-dynamiclib", "-undefined", "dynamic_lookup",
                        "-install_name", f"@rpath/{library.name}",
                        *map(str, objects), "-o", str(output)], check=True)
        # Another build may have finished the same library meanwhile; either copy is right.
        output.replace(library)
    return library


def build_plugin(path, output_path, ranges):
    import shutil
    image = pefile.PE(str(path))
    base, _ = module_range(path, image, ranges)
    # On-demand translation: the DLLs beside this one are the program's.
    folder = Path(path).resolve().parent
    available = {item.name.lower() for item in folder.iterdir() if item.suffix.lower() == ".dll"}
    trace = bool(os.environ.get("ARM64_RECOMPILER_TRACE_MODULES"))
    if os.environ.get("ARM64_RECOMPILER_NO_CACHE"):
        with tempfile.TemporaryDirectory(prefix=".console-plugin-", dir=output_path.parent) as scratch:
            shutil.copyfile(module_library(path, image, base, available, trace, Path(scratch)), output_path)
    else:
        shutil.copyfile(module_library(path, image, base, available, trace, module_store()), output_path)


def cache_key(exe_path, dll_paths, lazy_modules, trace, bound=()):
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
    hasher.update(f"{lazy_modules}_{trace}_{sorted(bound)}".encode("utf-8"))
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
    exe = pefile.PE(str(exe_path))
    if exe.is_dll():
        raise ValueError("first input must be an executable")
    # DLLs that become lifted guest modules: explicit inputs, and in lazy mode
    # any non-system DLL shipped beside the program (translated on demand).
    available = {Path(path).name.lower() for path in dll_paths}
    if lazy_modules:
        available |= {item.name.lower() for item in exe_path.resolve().parent.iterdir()
                      if item.suffix.lower() == ".dll" and item.is_file()}
    bound = bound_import_dlls(exe, available)
    if not no_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        key = cache_key(exe_path, dll_paths, lazy_modules, trace, bound)
        cached_o = cache_dir / f"{exe_path.stem}_{key}.o"
        cached_reg = cache_dir / f"{exe_path.stem}_{key}_reg.c"
        # Whole-program cache: only for builds without lifted DLLs, whose objects
        # it does not hold (those have their own per-module cache below).
        if cached_o.exists() and not dll_paths:
            subprocess.run(["clang", "-arch", "arm64", "-O2", "-Wno-override-module",
                            "-I", str(root), str(root / "console_runtime.c"),
                            str(cached_o), "-o", str(output_path)], check=True)
            return

    with tempfile.TemporaryDirectory(prefix=".console-modules-", dir=output_path.parent) as folder:
        work = Path(folder)
        primary = work / "main.ll"
        # Pointers in the program's data are real guest addresses, like the ones its
        # code computes: a stored pointer must compare equal to a computed one.
        primary_image = read_console_image(exe, load_base=exe.OPTIONAL_HEADER.ImageBase)
        modules = [primary]
        exe_base = exe.OPTIONAL_HEADER.ImageBase
        ranges = [(exe_base, exe_base + 0x20000000)]
        names = set()
        registry = ['#include "console_modules.h"']
        rows = []
        images = [(path, pefile.PE(str(path))) for path in dll_paths]
        # An order independent of the command line: it decides which image keeps
        # a contested address.
        images.sort(key=lambda item: (item[1].OPTIONAL_HEADER.ImageBase, item[0].name.lower()))
        # Lifted DLLs normally stay out of the program: each is a shared library in
        # the module store, loaded by the runtime at startup. Without a cache to
        # keep them in, or on request, they are linked into the program instead.
        shared = bool(images) and not no_cache and not os.environ.get("ARM64_RECOMPILER_STATIC_MODULES")
        if shared:
            store = module_store()
            jobs = []
            for path, image in images:
                base, end = module_range(path, image, ranges)
                if path.name.lower() in names:
                    raise ValueError(f"{path}: duplicate DLL filename")
                names.add(path.name.lower())
                ranges.append((base, end))
                jobs.append((path, image, base, available, False, store))
            # Lifting is Python, but the compiles of uncached DLLs overlap.
            with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
                libraries = list(pool.map(lambda job: module_library(*job), jobs))
            lifter = ConsoleLift(exe, modules=True, trace=trace, fault_delivery=lazy_modules, bound_dlls=bound)
            primary.write_text(lifter.emit_console(*primary_image))
            source = work / "registry.c"
            source.write_text("\n".join((
                '#include "console_modules.h"',
                f"static struct guest_module modules[{len(libraries)}];",
                "struct guest_module *guest_modules = modules;",
                f"const size_t guest_module_count = {len(libraries)};",
                "static const char *const libraries[] = {",
                *(f"    {json.dumps(library.name)}," for library in libraries),
                "};",
                "const char *const *guest_module_libraries = libraries;",
                f"const char *guest_module_store = {json.dumps(str(store))};", "")))
            primary_object = work / "main.o"
            with ThreadPoolExecutor(max_workers=2) as pool:
                primary_job = pool.submit(compile_program, primary, primary_object)
                objects = pool.submit(compile_parallel, [root / "console_runtime.c", source], work,
                                      MODULE_FLAGS).result()
                primary_job.result()
            output = work / "runner"
            subprocess.run(["clang", "-arch", "arm64", str(primary_object), *map(str, objects),
                            "-o", str(output)], check=True)
            output.replace(output_path)
            return
        pending = []  # (position in modules, cache object, cache metadata, metadata) of fresh lifts
        for path, image in images:
            base, end = module_range(path, image, ranges)
            if path.name.lower() in names:
                raise ValueError(f"{path}: duplicate DLL filename")
            # A lifted DLL compiles to the same object until the DLL, its base or
            # the lifter changes: reuse it instead of lifting and compiling again.
            module_key = module_cache_key(path, image, base, available, trace, MODULE_FLAGS)
            cached_object = cache_dir / f"module_{module_key}.o"
            cached_meta = cache_dir / f"module_{module_key}.json"
            if not no_cache and cached_object.exists() and cached_meta.exists():
                meta = json.loads(cached_meta.read_text())
                registry.extend(meta["registry"])
                llvm, row = cached_object, meta["row"]
            else:
                before = len(registry)
                llvm, row = lift_module(path, image, work, registry, base, available=available)
                if not no_cache:
                    pending.append((len(modules), cached_object, cached_meta,
                                    {"row": row, "registry": registry[before:]}))
            names.add(path.name.lower())
            ranges.append((base, end))
            modules.append(llvm)
            rows.append(f"    {row},")
        lifter = ConsoleLift(exe, modules=bool(rows) or lazy_modules or bool(bound), trace=trace,
                             fault_delivery=lazy_modules, bound_dlls=bound)
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
        # The program's own code builds at program_flags(); the runtime, lifted
        # DLLs, and registry build at -O2. All compile concurrently.
        with ThreadPoolExecutor(max_workers=2) as pool:
            primary_job = pool.submit(compile_program, primary, primary_object, no_cache)
            others = pool.submit(compile_parallel, [root / "console_runtime.c", *modules[1:]], work,
                                 MODULE_FLAGS)
            primary_job.result()
            objects = others.result()
        modules[0] = primary_object
        if not no_cache:
            import shutil
            shutil.copyfile(primary_object, cached_o)
            for position, cached_object, cached_meta, meta in pending:
                # objects[0] is the runtime; modules[position] compiled to objects[position].
                shutil.copyfile(objects[position], cached_object)
                cached_meta.write_text(json.dumps(meta))
        subprocess.run(["clang", "-arch", "arm64", str(primary_object), *map(str, objects),
                        "-o", str(output)], check=True)
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
