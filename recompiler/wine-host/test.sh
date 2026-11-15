#!/bin/bash
# Runs the harnesses built by build.sh: Wine's unix side must boot inside a
# native arm64 process, and win32u.so + winemac.so must open and paint a real
# macOS window with no Windows-side code running. Needs a logged-in GUI session.
#
# usage: test.sh <work-dir>   (the directory given to build.sh)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repository="$(cd "$here/../.." && pwd)"
work="$(cd "${1:?usage: test.sh <work-dir>}" && pwd)"
wine_root="${WINE_ROOT:-$repository/work/wine/Wine Stable.app/Contents/Resources/wine}"
program="${HOST_PROGRAM:-$repository/work/corpus/jq.exe}"
unix="$work/host/lib/wine/x86_64-unix"
export WINEPREFIX="${WINEPREFIX:-$work/prefix}" WINEDEBUG="${WINEDEBUG:--all}" MVK_CONFIG_LOG_LEVEL=0
export WINESERVER="$wine_root/bin/wineserver" WINELOADER="$wine_root/bin/wine"
# win32u.so loads FreeType by name at run time.
export DYLD_FALLBACK_LIBRARY_PATH="${DYLD_FALLBACK_LIBRARY_PATH:-/opt/homebrew/lib:/usr/local/lib:/usr/lib}"
if [[ ! -f "$WINEPREFIX/system.reg" ]]; then
    "$wine_root/bin/wine" wineboot -i > /dev/null 2>&1
    "$wine_root/bin/wineserver" -w
fi

"$work/host_boot" "$unix" "$program" > "$work/boot.log" 2>&1 || { tail -5 "$work/boot.log" >&2; exit 1; }
grep -q '^host: Wine unix side is up' "$work/boot.log"
grep -q '^host: win32u init -> 0$' "$work/boot.log"
grep -q '^host: NtUserGetDoubleClickTime -> [1-9][0-9]* ms$' "$work/boot.log"
echo "PASS Wine's unix side boots in a native arm64 process and win32u answers syscalls"

"$work/host_window" "$unix" "$program" 3 > "$work/window.log" 2>&1 || { tail -8 "$work/window.log" >&2; exit 1; }
grep -q '^host: winemac init -> 0$' "$work/window.log"
grep -q 'CreateWindowEx -> 0x[0-9a-f]* (WM_CREATE seen 1)' "$work/window.log"
grep -q '^host: message loop ended; WM_PAINT handled [1-9]' "$work/window.log"
echo "PASS win32u.so + winemac.so open, paint and close a native window (no Windows-side code)"
