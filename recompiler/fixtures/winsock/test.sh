#!/bin/bash
# A lifted Winsock client on Wine's native socket stack: the program and Wine's
# x86-64 ws2_32.dll are lifted to ARM64; socket ioctls run natively in ntdll.so
# and ws2_32.so (wine-host/). Talks to a TCP echo server on 127.0.0.1.
# Needs wine-host/build.sh output (WINE_HOST_WORK).
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
repository="$(cd "$tool/.." && pwd)"
python="${PYTHON:-python3}"
work="${WINE_HOST_WORK:-$repository/work/wine-host}"
wine_root="${WINE_ROOT:-$repository/work/wine/Wine Stable.app/Contents/Resources/wine}"
unix="$work/host/lib/wine/x86_64-unix"
if [[ ! -f "$unix/hostthunks.dylib" || ! -f "$unix/ws2_32.so" || ! -d "$wine_root/lib/wine/x86_64-windows" ]]; then
    echo "SKIP Winsock fixture (run wine-host/build.sh; needs an x86-64 Wine 11.0 in WINE_ROOT)" >&2
    exit 0
fi
if [[ -n "${WINSOCK_FIXTURE_BUILD:-}" ]]; then
    build="$WINSOCK_FIXTURE_BUILD"
    mkdir -p "$build"
else
    build="$(mktemp -d)"
    trap 'rm -rf "$build"' EXIT
fi

for dll in kernel32 ws2_32; do
    "$python" -m ziglang dlltool -m i386:x86-64 -d "$fixture/$dll.def" -l "$build/$dll.lib"
done
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -fno-builtin -c "$fixture/main.c" -o "$build/main.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$build/main.obj" \
    "$build/kernel32.lib" "$build/ws2_32.lib" -Wl,--entry,entry -o "$build/winsock.exe"
# Statically imported DLLs only: the fixture needs none of ws2_32's delay imports.
WINE_ROOT="$wine_root" WINE_HOST_WORK="$work" "$python" "$tool/wine-host/lift_app.py" \
    "$build/winsock.exe" "$build" --delay-depth 0 2> "$build/lift.log" || { tail -5 "$build/lift.log" >&2; exit 1; }

# An echo server on an ephemeral port: prints the port, serves one connection.
"$python" -c '
import socket, sys
server = socket.socket(); server.bind(("127.0.0.1", 0)); server.listen(1)
print(server.getsockname()[1], flush=True)
server.settimeout(60); peer, _ = server.accept(); peer.settimeout(10)
data = peer.recv(256); peer.sendall(b"echo " + data); peer.close()
' > "$build/port" &
server=$!
for _ in $(seq 50); do [[ -s "$build/port" ]] && break; sleep 0.1; done

export ARM64_RECOMPILER_WINE_HOST="$unix" ARM64_RECOMPILER_WINE_EXE="$build/winsock.exe"
export WINEPREFIX="${GUI_FIXTURE_PREFIX:-$work/gui-prefix}" WINEDEBUG="${WINEDEBUG:--all}" MVK_CONFIG_LOG_LEVEL=0
export WINESERVER="$wine_root/bin/wineserver" WINELOADER="$wine_root/bin/wine"
export DYLD_FALLBACK_LIBRARY_PATH="${DYLD_FALLBACK_LIBRARY_PATH:-/opt/homebrew/lib:/usr/local/lib:/usr/lib}"
export WINSOCK_PORT="$(cat "$build/port")"
if [[ ! -f "$WINEPREFIX/system.reg" ]]; then
    "$wine_root/bin/wine" wineboot -i > /dev/null 2>&1
    "$wine_root/bin/wineserver" -w
fi
result=0
(cd "$build" && ./winsock > "$build/stdout" 2> "$build/stderr") || result=$?
kill "$server" 2> /dev/null || true
if [[ "$result" != 0 ]]; then
    tr -d '\r' < "$build/stdout" >&2
    tail -20 "$build/stderr" >&2
    echo "FAIL Winsock fixture exited $result" >&2
    exit 1
fi
tr -d '\r' < "$build/stdout" | cmp - "$fixture/expected.txt"
echo "PASS lifted Winsock client (ws2_32.dll lifted, sockets native in ntdll.so + ws2_32.so)"
