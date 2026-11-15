#!/usr/bin/env python3
"""Generate hostthunks.dylib: one marshalling thunk per unix-side syscall.

Lifted x86-64 code passes every syscall argument as a 64-bit slot (four
registers, then the stack). Wine's unix-side functions are ordinary Darwin
arm64 C functions, whose stack arguments are packed by their natural size, so a
call with more than eight arguments must be made through the real prototype.
Each thunk takes the raw 64-bit slots and calls the function with every
argument converted to its declared type; a C++ template derives the conversions
from Wine's own headers.

usage: gen_thunks.py <wine-source> <wine-build> <unix-lib-dir> <output.dylib>
"""
import re
import subprocess
import sys
from pathlib import Path

HEADER = r'''
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>
#include <stdarg.h>
/* Wine's C headers use these C++ keywords as identifiers. */
#define class class_
#define virtual virtual_
extern "C" {
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wingdi.h"
#include "winuser.h"
#include "ntgdi.h"
#include "ntuser.h"
}
#undef class
#undef virtual

template <class T> static inline T slot(uint64_t value) {
    if constexpr (std::is_pointer_v<T>) {
        return reinterpret_cast<T>(static_cast<uintptr_t>(value));
    } else if constexpr (std::is_floating_point_v<T>) {
        T result;                       /* x64 passes float/double bits in the slot */
        std::memcpy(&result, &value, sizeof result);
        return result;
    } else if constexpr (std::is_class_v<T> || std::is_union_v<T>) {
        T result;                       /* x64: by value up to 8 bytes, else by reference */
        if (sizeof(T) <= 8) std::memcpy(&result, &value, sizeof result);
        else std::memcpy(&result, reinterpret_cast<const void *>(static_cast<uintptr_t>(value)), sizeof result);
        return result;
    } else {
        return static_cast<T>(value);
    }
}

template <class R> static inline uint64_t widen(R value) {
    if constexpr (std::is_pointer_v<R>) return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(value));
    else if constexpr (std::is_signed_v<R>) return static_cast<uint64_t>(static_cast<int64_t>(value));
    else return static_cast<uint64_t>(value);
}

template <class R, class... A, std::size_t... I>
static inline uint64_t invoke(R (*function)(A...), const uint64_t *slots, std::index_sequence<I...>) {
    if constexpr (std::is_void_v<R>) {
        function(slot<A>(slots[I])...);
        return 0;
    } else {
        return widen(function(slot<A>(slots[I])...));
    }
}

template <class R, class... A> static inline uint64_t call(R (*function)(A...), const uint64_t *slots) {
    return invoke(function, slots, std::index_sequence_for<A...>{});
}

typedef uint64_t (*host_thunk)(const uint64_t *slots);
struct entry { const char *name; host_thunk thunk; };
#define THUNK(name) { #name, [](const uint64_t *slots) -> uint64_t { return call(name, slots); } },
static const entry entries[] = {
%s
};

extern "C" __attribute__((visibility("default"))) host_thunk host_syscall_thunk(const char *name) {
    std::size_t low = 0, high = sizeof entries / sizeof *entries;
    while (low < high) {
        std::size_t mid = low + (high - low) / 2;
        int order = std::strcmp(entries[mid].name, name);
        if (!order) return entries[mid].thunk;
        if (order < 0) low = mid + 1; else high = mid;
    }
    return nullptr;
}
'''


def exported(library, pattern):
    listing = subprocess.run(["nm", "-gU", str(library)], check=True, capture_output=True, text=True).stdout
    return {line.split()[-1][1:] for line in listing.splitlines() if re.fullmatch(pattern, line.split()[-1][1:])}


def main():
    source, build, unix, output = map(Path, sys.argv[1:5])
    names = exported(unix / "ntdll.so", r"Nt[A-Z]\w*") | exported(unix / "win32u.so", r"Nt(User|Gdi)\w*")
    names -= {"NtCurrentTeb"}
    generated = output.with_suffix(".cc")
    command = ["/usr/bin/clang++", "-std=c++17", "-O1", "-w", "-dynamiclib", "-DWINE_UNIX_LIB", "-D__WINESRC__", "-DNO_STRICT",
               f"-I{build / 'include'}", f"-I{source / 'include'}", str(generated),
               str(unix / "ntdll.so"), str(unix / "win32u.so"), f"-Wl,-rpath,{unix}", "-o", str(output),
               "-ferror-limit=0"]
    dropped = set()
    for _ in range(6):
        rows = "\n".join(f"THUNK({name})" for name in sorted(names))  # byte order, as strcmp
        generated.write_text(HEADER % rows)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{output.name}: {len(names)} syscall thunks"
                  f" ({len(dropped)} exported functions have no prototype in Wine's headers)")
            return
        # Exported functions with no public prototype cannot be marshalled; drop them.
        missing = set(re.findall(r"use of undeclared identifier '(\w+)'", result.stderr)) & names
        if not missing:
            sys.exit(result.stderr[-3000:])
        dropped |= missing
        names -= missing
    sys.exit("could not converge on a compilable thunk list")


if __name__ == "__main__":
    main()
