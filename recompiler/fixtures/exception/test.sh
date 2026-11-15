#!/bin/bash
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
python="${PYTHON:-python3}"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

printf '%s\n' 'LIBRARY kernel32.dll' EXPORTS AddVectoredExceptionHandler ExitProcess \
    RaiseException RemoveVectoredExceptionHandler LoadLibraryW GetProcAddress FreeLibrary RtlUnwindEx CreateFileMappingW MapViewOfFile > "$build/kernel32.def"
"$python" -m ziglang dlltool -m i386:x86-64 -d "$build/kernel32.def" -l "$build/kernel32.lib"
printf '%s\n' 'LIBRARY advapi32.dll' EXPORTS RegOpenKeyExW RegQueryValueExW RegCloseKey > "$build/advapi32.def"
printf '%s\n' 'LIBRARY ws2_32.dll' EXPORTS WSAStartup WSACleanup WSAGetLastError \
    socket bind getsockname listen connect accept send recv closesocket > "$build/ws2_32.def"
for library in advapi32 ws2_32; do
    "$python" -m ziglang dlltool -m i386:x86-64 -d "$build/$library.def" -l "$build/$library.lib"
done
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding \
    -c "$fixture/main.c" -o "$build/main.obj"
clang -target x86_64-w64-windows-gnu -c "$fixture/language.s" -o "$build/language.obj"
clang -target x86_64-w64-windows-gnu -c "$fixture/consolidate.s" -o "$build/consolidate.obj"
clang -target x86_64-w64-windows-gnu -c "$fixture/fault.s" -o "$build/fault.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$build/main.obj" "$build/language.obj" "$build/consolidate.obj" "$build/fault.obj" \
    "$build/kernel32.lib" "$build/advapi32.lib" "$build/ws2_32.lib" -Wl,--entry,entry -o "$build/exception.exe"
if [[ -n "${WINE:-}" ]]; then
    "$WINE" "$build/exception.exe"
fi
"$python" "$tool/run_exe.py" "$build/exception.exe"
echo "PASS Windows vectored and table-driven exceptions, unwind consolidation, access violation, registry query, system RNG, and Winsock loopback"
