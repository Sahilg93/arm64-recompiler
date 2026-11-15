#!/bin/bash
# A lifted Win32 GUI program on Wine's native windowing stack. The program and
# Wine's own x86-64 user32/gdi32/win32u/kernel32/kernelbase/ntdll DLLs are
# lifted to ARM64; their NtUser/NtGdi/Nt syscalls run natively in win32u.so,
# winemac.so and ntdll.so (wine-host/), which open a real macOS window.
# Needs wine-host/build.sh output (WINE_HOST_WORK) and a logged-in GUI session.
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
repository="$(cd "$tool/.." && pwd)"
python="${PYTHON:-python3}"
work="${WINE_HOST_WORK:-$repository/work/wine-host}"
wine_root="${WINE_ROOT:-$repository/work/wine/Wine Stable.app/Contents/Resources/wine}"
unix="$work/host/lib/wine/x86_64-unix"
if [[ ! -f "$unix/hostthunks.dylib" || ! -d "$wine_root/lib/wine/x86_64-windows" ]]; then
    echo "SKIP GUI fixture (run wine-host/build.sh; needs an x86-64 Wine 11.0 in WINE_ROOT)" >&2
    exit 0
fi
if [[ -n "${GUI_FIXTURE_BUILD:-}" ]]; then
    build="$GUI_FIXTURE_BUILD"
    mkdir -p "$build"
else
    build="$(mktemp -d)"
    trap 'rm -rf "$build"' EXIT
fi

for dll in kernel32 user32 gdi32; do
    "$python" -m ziglang dlltool -m i386:x86-64 -d "$fixture/$dll.def" -l "$build/$dll.lib"
done
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-builtin -c "$fixture/main.c" -o "$build/main.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$build/main.obj" \
    "$build/kernel32.lib" "$build/user32.lib" "$build/gdi32.lib" -Wl,--entry,entry -o "$build/gui.exe"

# The Windows side of Wine that the program runs on, lifted with it.
dlls=(ntdll.dll kernelbase.dll kernel32.dll ucrtbase.dll msvcrt.dll advapi32.dll sechost.dll
      win32u.dll gdi32.dll user32.dll winemac.drv)
paths=()
for dll in "${dlls[@]}"; do
    cp "$wine_root/lib/wine/x86_64-windows/$dll" "$build/$dll"
    paths+=("$build/$dll")
done
"$python" "$tool/build_console_modules.py" "$build/gui.exe" "$build/gui" "${paths[@]}"

export ARM64_RECOMPILER_WINE_HOST="$unix" ARM64_RECOMPILER_WINE_EXE="$build/gui.exe"
# Its own prefix, never the caller's: the hosted process shares a wineserver with it.
export WINEPREFIX="${GUI_FIXTURE_PREFIX:-$work/gui-prefix}" WINEDEBUG="${WINEDEBUG:--all}" MVK_CONFIG_LOG_LEVEL=0
export WINESERVER="$wine_root/bin/wineserver" WINELOADER="$wine_root/bin/wine"
export DYLD_FALLBACK_LIBRARY_PATH="${DYLD_FALLBACK_LIBRARY_PATH:-/opt/homebrew/lib:/usr/local/lib:/usr/lib}"
if [[ ! -f "$WINEPREFIX/system.reg" ]]; then
    "$wine_root/bin/wine" wineboot -i > /dev/null 2>&1
    "$wine_root/bin/wineserver" -w
fi
result=0
(cd "$build" && ./gui > "$build/stdout" 2> "$build/stderr") || result=$?
if [[ "$result" != 0 ]]; then
    tail -20 "$build/stderr" >&2
    echo "FAIL GUI fixture exited $result" >&2
    exit 1
fi
tr -d '\r' < "$build/stdout" > "$build/stdout.txt"
grep -qx 'created window' "$build/stdout.txt"
grep -qE '^paints [1-9]' "$build/stdout.txt"
grep -qE '^client width [1-9][0-9]+$' "$build/stdout.txt"
echo "PASS lifted Win32 GUI program opens and paints a native window (user32/gdi32 lifted, win32u.so + winemac.so native)"
