#!/bin/bash
set -euo pipefail

if [[ $# != 1 ]]; then
    echo "Usage: $0 /path/to/build-directory" >&2
    exit 2
fi

fixture="$(cd "$(dirname "$0")" && pwd)"
python="${PYTHON:-python3}"
mkdir -p "$1"
build="$(cd "$1" && pwd)"

"$python" -m ziglang dlltool -m i386:x86-64 -d "$fixture/kernel32.def" -l "$build/kernel32.lib"
for source in main plugin dependency; do
    clang -target x86_64-w64-windows-gnu -O2 -ffreestanding \
        -c "$fixture/$source.c" -o "$build/$source.obj"
done
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib -shared \
    "$build/dependency.obj" -Wl,--entry,DllMain,--image-base,0x180000000,--out-implib,"$build/dependency.lib" \
    -o "$build/fixture_dependency.dll"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib -shared \
    "$build/plugin.obj" "$build/kernel32.lib" "$build/dependency.lib" -Wl,--entry,DllMain -o "$build/fixture_plugin.dll"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib \
    "$build/main.obj" "$build/kernel32.lib" -Wl,--entry,entry -o "$build/fixture.exe"
clang -target x86_64-w64-windows-gnu -O2 -ffreestanding -DRUN_ON_MAIN_THREAD \
    -c "$fixture/main.c" -o "$build/main-thread.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib \
    "$build/main-thread.obj" "$build/kernel32.lib" -Wl,--entry,entry -o "$build/fixture-main-thread.exe"
