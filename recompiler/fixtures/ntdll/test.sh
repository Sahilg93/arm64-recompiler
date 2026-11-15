#!/bin/bash
# Lifts Wine's ntdll.dll as a guest module: the program's ntdll imports bind to
# lifted Wine code, while syscalls, heap, last error and loader entry points go
# to the runtime (see system_overrides in build_console_modules.py). A second
# program lifts Wine's kernelbase.dll on top: its real DllMain runs (locale init
# from Wine's NLS files) and its exports run as lifted Wine code.
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
repository="$(cd "$tool/.." && pwd)"
python="${PYTHON:-python3}"
ntdll="${NTDLL_DLL:-}"
if [[ -z "$ntdll" ]]; then
    for candidate in \
        "$tool/wine-runtime/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-windows/ntdll.dll" \
        "$repository/work/wine/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-windows/ntdll.dll"; do
        [[ -f "$candidate" ]] && ntdll="$candidate" && break
    done
fi
if [[ ! -f "$ntdll" ]]; then
    echo "SKIP Wine ntdll.dll fixture (no ntdll.dll; run setup_wine.py or set NTDLL_DLL)" >&2
    exit 0
fi
kernelbase="$(dirname "$ntdll")/kernelbase.dll"
# Wine keeps NLS tables in share/wine/nls beside lib/wine/x86_64-windows.
export ARM64_RECOMPILER_NLS_DIR="${ARM64_RECOMPILER_NLS_DIR:-$(cd "$(dirname "$ntdll")/../../.." && pwd)/share/wine/nls}"
if [[ -n "${NTDLL_FIXTURE_BUILD:-}" ]]; then
    build="$NTDLL_FIXTURE_BUILD"
    mkdir -p "$build"
else
    build="$(mktemp -d)"
    trap 'rm -rf "$build"' EXIT
fi

for dll in ntdll kernel32 kernelbase; do
    "$python" -m ziglang dlltool -m i386:x86-64 -d "$fixture/$dll.def" -l "$build/$dll.lib"
done
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-builtin -c "$fixture/main.c" -o "$build/main.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib \
    "$build/main.obj" "$build/ntdll.lib" "$build/kernel32.lib" -Wl,--entry,entry -o "$build/ntdll_fixture.exe"
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-builtin -c "$fixture/kernelbase.c" -o "$build/kernelbase.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib \
    "$build/kernelbase.obj" "$build/kernelbase.lib" "$build/kernel32.lib" -Wl,--entry,entry \
    -o "$build/kernelbase_fixture.exe"
cp "$ntdll" "$build/ntdll.dll"

result=0
(cd "$build" && ARM64_RECOMPILER_TRACE_IMPORTS=1 "$python" "$tool/run_exe.py" ntdll_fixture.exe \
    2> "$build/run.stderr") || result=$?
if [[ "$result" != 0 ]]; then
    tail -20 "$build/run.stderr" >&2
    echo "FAIL Wine ntdll.dll fixture exited $result" >&2
    exit 1
fi
# ntdll imports bind into the lifted module; runtime-owned entry points are overrides.
grep -qE '^\[bind\] ntdll\.dll!RtlInitUnicodeString -> ntdll\.dll ' "$build/run.stderr" ||
    { echo "FAIL ntdll imports did not bind to the lifted ntdll.dll" >&2; exit 1; }
for name in RtlAllocateHeap RtlFreeHeap NtQuerySystemTime NtAllocateVirtualMemory LdrGetDllHandle; do
    grep -q "^\[override\] $name(" "$build/run.stderr" ||
        { echo "FAIL $name did not reach the runtime override" >&2; exit 1; }
done
echo "PASS Wine ntdll.dll lifted as a guest module (Rtl code lifted; syscalls, heap, loader in the runtime)"

if [[ ! -f "$kernelbase" || ! -f "$ARM64_RECOMPILER_NLS_DIR/locale.nls" ]]; then
    echo "SKIP Wine kernelbase.dll fixture (needs kernelbase.dll and Wine's NLS files)" >&2
    exit 0
fi
cp "$kernelbase" "$build/kernelbase.dll"
result=0
(cd "$build" && ARM64_RECOMPILER_TRACE_IMPORTS=1 "$python" "$tool/run_exe.py" kernelbase_fixture.exe \
    2> "$build/kernelbase.stderr") || result=$?
if [[ "$result" != 0 ]]; then
    grep -v '^\[' "$build/kernelbase.stderr" | tail -20 >&2
    echo "FAIL Wine kernelbase.dll fixture exited $result" >&2
    exit 1
fi
grep -qE '^\[bind\] kernelbase\.dll!PathCchCombine -> kernelbase\.dll ' "$build/kernelbase.stderr" ||
    { echo "FAIL kernelbase imports did not bind to the lifted kernelbase.dll" >&2; exit 1; }
# kernelbase's own ntdll imports bind into the lifted ntdll, and its DllMain loads locale data.
grep -q '^\[override\] NtInitializeNlsFiles(' "$build/kernelbase.stderr" ||
    { echo "FAIL kernelbase DllMain did not initialize locale data" >&2; exit 1; }
# kernel32 functions without a runtime shim run kernelbase's lifted code.
for name in GetLocaleInfoW CompareStringOrdinal lstrcmpiW ExpandEnvironmentStringsW; do
    grep -q "^\[fallback\] $name -> kernelbase\.dll " "$build/kernelbase.stderr" ||
        { echo "FAIL kernel32!$name did not fall back to kernelbase.dll" >&2; exit 1; }
done
echo "PASS Wine kernelbase.dll lifted on the lifted ntdll.dll (real DllMain, lifted exports, kernel32 fallback)"
