#!/bin/bash
# Builds main.c + seh.s as a CRT-free Windows x64 EXE and runs it through the
# ARM64 launcher (and, if WINE is set, under Wine first). Exit status 0 means
# every raw VirtualAlloc fault reached the intended guest handler.
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
python="${PYTHON:-python3}"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

printf '%s\n' 'LIBRARY kernel32.dll' EXPORTS AddVectoredExceptionHandler ExitProcess \
    RemoveVectoredExceptionHandler VirtualAlloc VirtualFree VirtualProtect > "$build/kernel32.def"
"$python" -m ziglang dlltool -m i386:x86-64 -d "$build/kernel32.def" -l "$build/kernel32.lib"
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -c "$fixture/main.c" -o "$build/main.obj"
clang -target x86_64-w64-windows-gnu -c "$fixture/seh.s" -o "$build/seh.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$build/main.obj" "$build/seh.obj" \
    "$build/kernel32.lib" -Wl,--entry,entry -o "$build/vm_fault.exe"
if [[ -n "${WINE:-}" ]]; then
    MVK_CONFIG_LOG_LEVEL=0 "$WINE" "$build/vm_fault.exe"
    echo "PASS under Wine"
fi
"$python" "$tool/run_exe.py" "$build/vm_fault.exe"
echo "PASS raw VirtualAlloc faults (reserved read, read-only write, no-access read) reach VEH and table-driven SEH"
