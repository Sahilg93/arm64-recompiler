#!/bin/bash
set -euo pipefail

fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
python="${PYTHON:-python3}"
sdk="${XWIN_SDK:?Set XWIN_SDK to the SDK and CRT directory prepared by xwin}"
compiler="${CLANG_CL:-clang-cl}"
linker="${LLD_LINK:-lld-link}"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

"$compiler" --target=x86_64-pc-windows-msvc /EHa /O1 /MT /c \
    /imsvc "$sdk/crt/include" /imsvc "$sdk/sdk/include/ucrt" \
    /imsvc "$sdk/sdk/include/um" /imsvc "$sdk/sdk/include/shared" \
    "/Fo$build/msvc.obj" -- "$fixture/msvc.cpp"
"$linker" "/libpath:$sdk/crt/lib/x86_64" "/libpath:$sdk/sdk/lib/ucrt/x86_64" \
    "/libpath:$sdk/sdk/lib/um/x86_64" "/out:$build/msvc.exe" "$build/msvc.obj"
"$python" "$tool/run_exe.py" --trace "$build/msvc.exe" > "$build/native.stdout"
tr -d '\r' < "$build/native.stdout" | grep -Fx 'C++ cleanup, rethrow, and SEH passed'
if [[ -n "${WINE:-}" ]]; then
    "$WINE" "$build/msvc.exe" > "$build/wine.stdout"
    cmp "$build/wine.stdout" "$build/native.stdout"
fi
