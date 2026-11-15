#!/bin/bash
# Builds Wine 11.0's unix side (ntdll.so, win32u.so, winemac.so, ws2_32.so) natively for
# arm64 macOS with the host-mode patch, lays it out beside the Windows-side
# files of an existing x86-64 Wine 11.0 install, and compiles the harnesses.
#
# usage: build.sh <work-dir>
#   WINE_ROOT  x86-64 Wine 11.0 root holding bin/, lib/wine/, share/
#              (default: the copy setup_wine.py installs under work/wine)
# Needs Xcode's clang, Homebrew LLVM (for the PE cross-compiler configure
# probes), FreeType, and bison >= 3 (macOS ships 2.3; `brew install bison`).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repository="$(cd "$here/../.." && pwd)"
work="${1:?usage: build.sh <work-dir>}"
mkdir -p "$work"
work="$(cd "$work" && pwd)"
wine_root="${WINE_ROOT:-$repository/work/wine/Wine Stable.app/Contents/Resources/wine}"
[[ -x "$wine_root/bin/wineserver" && -d "$wine_root/lib/wine/x86_64-windows" ]] ||
    { echo "WINE_ROOT must be an x86-64 Wine 11.0 install: $wine_root" >&2; exit 1; }

for candidate in /opt/homebrew/opt/bison/bin /usr/local/opt/bison/bin; do
    [[ -x "$candidate/bison" ]] && PATH="$candidate:$PATH"
done
export PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:$PATH"
bison --version | awk 'NR == 1 { split($NF, v, "."); exit !(v[1] >= 3) }' ||
    { echo "bison >= 3 is required (brew install bison, or put one first in PATH)" >&2; exit 1; }

source="$work/wine-11.0"
if [[ ! -d "$source" ]]; then
    archive="$work/wine-11.0.tar.xz"
    [[ -f "$archive" ]] || curl -fsSL -o "$archive" https://dl.winehq.org/wine/source/11.0/wine-11.0.tar.xz
    echo "c07a6857933c1fc60dff5448d79f39c92481c1e9db5aa628db9d0358446e0701  $archive" | shasum -a 256 -c - > /dev/null
    tar xf "$archive" -C "$work"
    patch -s -p1 -d "$source" < "$here/wine-11.0-host-mode.patch"
fi

build="$work/build"
mkdir -p "$build"
if [[ ! -f "$build/Makefile" ]]; then
    (cd "$build" && "$source/configure" --enable-archs=aarch64 --without-x --disable-tests \
        CC=/usr/bin/clang > configure.log 2>&1) || { tail -5 "$build/configure.log" >&2; exit 1; }
fi
(cd "$build" && make -j"$(sysctl -n hw.ncpu)" dlls/ntdll/ntdll.so dlls/win32u/win32u.so \
    dlls/winemac.drv/winemac.so dlls/ws2_32/ws2_32.so > make.log 2>&1) || { grep -m5 -B2 -A6 'error' "$build/make.log" >&2; exit 1; }

# Wine finds everything relative to ntdll.so. The unix libraries are arm64, but
# the process presents itself as x86-64, so they live in x86_64-unix beside the
# x86-64 Windows-side DLLs. System processes (wineserver, explorer, wineboot)
# are the x86-64 install's own, started through its loader.
host="$work/host"
unix="$host/lib/wine/x86_64-unix"
mkdir -p "$unix"
cp "$build/dlls/ntdll/ntdll.so" "$build/dlls/win32u/win32u.so" "$build/dlls/winemac.drv/winemac.so" \
    "$build/dlls/ws2_32/ws2_32.so" "$unix/"
ln -sfn "$wine_root/bin" "$host/bin"
ln -sfn "$wine_root/share" "$host/share"
ln -sfn "$wine_root/lib/wine/x86_64-windows" "$host/lib/wine/x86_64-windows"
ln -sfn "$wine_root/lib/wine/x86_64-unix/wine" "$unix/wine"

# Marshalling thunks for the recompiler runtime's syscall boundary (console_wine_host.h).
python3 "$here/gen_thunks.py" "$source" "$build" "$unix" "$unix/hostthunks.dylib"

/usr/bin/clang -O1 -Wall "$here/host_boot.c" -o "$work/host_boot"
/usr/bin/clang -O1 -Wall -DWINE_UNIX_LIB -D__WINESRC__ -I"$build/include" -I"$source/include" \
    "$here/host_window.c" "$unix/win32u.so" "$unix/ntdll.so" -Wl,-rpath,"$unix" -o "$work/host_window"
echo "built $work/host_boot and $work/host_window against $unix"
