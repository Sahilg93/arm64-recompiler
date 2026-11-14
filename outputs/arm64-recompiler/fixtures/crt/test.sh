#!/bin/bash
# Builds main.c and crtorder.dll against the Windows SDK UCRT, ships Wine's
# ucrtbase.dll beside them, and runs the program under Wine (when WINE is set)
# and through the ARM64 launcher, which lifts ucrtbase.dll instead of using its
# own CRT shims. Both must print expected.txt.
set -euo pipefail
fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
repository="$(cd "$tool/../.." && pwd)"
python="${PYTHON:-python3}"
sdk="${XWIN_SDK:?Set XWIN_SDK to the SDK and CRT directory prepared by xwin}"
compiler="${CLANG_CL:-clang-cl}"
linker="${LLD_LINK:-lld-link}"
ucrtbase="${UCRTBASE_DLL:-}"
if [[ -z "$ucrtbase" ]]; then
    for candidate in \
        "$tool/wine-runtime/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-windows/ucrtbase.dll" \
        "$repository/work/wine/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-windows/ucrtbase.dll" \
        "$repository/work/wine/prefix/drive_c/windows/system32/ucrtbase.dll"; do
        [[ -f "$candidate" ]] && ucrtbase="$candidate" && break
    done
fi
if [[ ! -f "$ucrtbase" ]]; then
    if [[ "${REQUIRE_MSVC:-0}" == 1 ]]; then
        echo "Set UCRTBASE_DLL to an x64 ucrtbase.dll (setup_wine.py installs one)" >&2
        exit 1
    fi
    echo "SKIP real ucrtbase.dll fixture (no ucrtbase.dll; run setup_wine.py or set UCRTBASE_DLL)" >&2
    exit 0
fi
# CRT_FIXTURE_BUILD keeps the build directory for debugging.
if [[ -n "${CRT_FIXTURE_BUILD:-}" ]]; then
    build="$CRT_FIXTURE_BUILD"
    mkdir -p "$build"
else
    build="$(mktemp -d)"
    trap 'rm -rf "$build"' EXIT
fi

flags=(--target=x86_64-pc-windows-msvc /O1 /MD /GS- /Zl /c /D_CRT_SECURE_NO_WARNINGS
       /imsvc "$sdk/crt/include" /imsvc "$sdk/sdk/include/ucrt"
       /imsvc "$sdk/sdk/include/um" /imsvc "$sdk/sdk/include/shared")
libs=("/libpath:$sdk/sdk/lib/ucrt/x86_64" "/libpath:$sdk/sdk/lib/um/x86_64" /nodefaultlib ucrt.lib kernel32.lib)

cp "$ucrtbase" "$build/ucrtbase.dll"
# strlen by ordinal: the ordinal comes from the ucrtbase.dll the program ships with.
ordinal="$("$python" -c 'import pefile, sys
pe = pefile.PE(sys.argv[1])
print(next(s.ordinal for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"strlen"))' "$build/ucrtbase.dll")"
printf 'LIBRARY ucrtbase.dll\nEXPORTS\n    crt_strlen_by_ordinal @%s NONAME\n    __threadid\n' "$ordinal" > "$build/ordinal.def"
"$python" -m ziglang dlltool -m i386:x86-64 -d "$build/ordinal.def" -l "$build/ordinal.lib"

"$compiler" "${flags[@]}" "/Fo$build/crtorder.obj" -- "$fixture/crtorder.c"
"$linker" /nologo /dll /entry:DllMain /base:0x210000000 "${libs[@]}" \
    "/out:$build/crtorder.dll" "/implib:$build/crtorder.lib" "$build/crtorder.obj"
"$compiler" "${flags[@]}" "/Fo$build/main.obj" -- "$fixture/main.c"
"$linker" /nologo /entry:start /subsystem:console "${libs[@]}" "$build/crtorder.lib" \
    "$build/ordinal.lib" "/out:$build/crt.exe" "$build/main.obj"

if [[ -n "${WINE:-}" ]]; then
    (cd "$build" && MVK_CONFIG_LOG_LEVEL=0 "$WINE" crt.exe > wine.stdout)
    tr -d '\r' < "$build/wine.stdout" | cmp - "$fixture/expected.txt"
    echo "PASS under Wine"
fi
(cd "$build" && ARM64_RECOMPILER_TRACE_IMPORTS=1 "$python" "$tool/run_exe.py" crt.exe \
    > native.stdout 2> native.stderr)
tr -d '\r' < "$build/native.stdout" | cmp - "$fixture/expected.txt"
# The CRT must run from the lifted DLL: its imports are bound into ucrtbase.dll
# (by name through API sets, by ordinal, and through a forwarder)...
for binding in '[^ ]*crt-stdio-l1-1-0\.dll!__stdio_common_vfprintf -> ucrtbase\.dll ' \
               '[^ ]*crt-heap-l1-1-0\.dll!malloc -> ucrtbase\.dll ' \
               '[^ ]*crt-utility-l1-1-0\.dll!qsort -> ucrtbase\.dll ' \
               "ucrtbase\\.dll!#$ordinal -> ucrtbase\\.dll " \
               '[^ ]*!__threadid -> ucrtbase\.dll 0x7fff8' \
               'crtorder\.dll!order_message -> crtorder\.dll '; do
    # __threadid is a forwarder to kernel32, so it binds to a runtime system token (0x7fff8xxx).
    grep -qE "^\[bind\] $binding" "$build/native.stderr" || { echo "FAIL missing binding: $binding" >&2; exit 1; }
done
# ...and none of the runtime's own CRT shims may be called.
if grep -E '^\[import\] (__stdio_common_v[a-z]*printf|malloc|free|qsort|strtod|_?w?fopen|fread|fwrite|fclose|exit|strlen)\(' \
        "$build/native.stderr"; then
    echo "FAIL a CRT call reached a runtime shim instead of ucrtbase.dll" >&2
    exit 1
fi
echo "PASS real ucrtbase.dll lifted as a guest module (API sets, ordinal import, forwarder, DllMain order)"
