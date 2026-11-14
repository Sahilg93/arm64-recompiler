#!/bin/bash
# Builds a CRT-free Windows x64 EXE that runs payload.s from VirtualAlloc
# memory, then runs it through the ARM64 launcher (and first under Wine when
# WINE is set). Exit status 0 means the JIT, RWX, and DEP checks all passed.
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
python="${PYTHON:-python3}"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

printf '%s\n' 'LIBRARY kernel32.dll' EXPORTS AddVectoredExceptionHandler ExitProcess \
    VirtualAlloc VirtualFree VirtualProtect > "$build/kernel32.def"
"$python" -m ziglang dlltool -m i386:x86-64 -d "$build/kernel32.def" -l "$build/kernel32.lib"
clang -target x86_64-w64-windows-gnu -c "$fixture/payload.s" -o "$build/payload.obj"
"$python" "$fixture/embed_text.py" "$build/payload.obj" "$build/payload.inc"
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -I"$build" -c "$fixture/main.c" -o "$build/main.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$build/main.obj" \
    "$build/kernel32.lib" -Wl,--entry,entry -o "$build/jit.exe"
if [[ -n "${WINE:-}" ]]; then
    MVK_CONFIG_LOG_LEVEL=0 "$WINE" "$build/jit.exe"
    echo "PASS under Wine"
fi
"$python" "$tool/run_exe.py" "$build/jit.exe"
echo "PASS JIT code in VirtualAlloc memory (interpreted payload, RWX patching, DEP fault)"
