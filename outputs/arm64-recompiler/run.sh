#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
cd "$(dirname "$0")"

build="${1:-$PWD/build}"
python="${PYTHON:-python3}"
mkdir -p "$build"

clang -arch arm64 -O2 -Dlifted=fixture fixture.c runner.c -o "$build/reference"
for level in 1 2 3; do
    prefix="$build/O$level"
    clang -target x86_64-pc-windows-msvc "-O$level" -fno-unroll-loops \
        -c fixture.c -o "$prefix.obj"
    "$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$prefix.obj" \
        -Wl,--entry,fixture -Wl,--strip-all -o "$prefix.exe"
    "$python" lift.py "$prefix.exe" "$prefix.ll"
    clang -arch arm64 -O2 -Wno-override-module "$prefix.ll" runner.c -o "$prefix"
    file "$prefix.exe" "$prefix"
    oracle=()
    if [[ "${VERIFY_ROSETTA:-0}" == 1 ]]; then
        "$python" x86_reference.py "$prefix.exe" "$prefix.s"
        clang -arch x86_64 -O2 "$prefix.s" x86_bridge.c runner.c -o "$prefix-x86"
        oracle=(--x86-macho "$prefix-x86")
    fi
    "$python" verify.py "$prefix.exe" "$prefix" "$build/reference" ${oracle[@]+"${oracle[@]}"}
done

prefix="$build/switch"
clang -target x86_64-pc-windows-msvc -O2 -c switch.c -o "$prefix.obj"
"$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$prefix.obj" \
    -Wl,--entry,fixture -Wl,--strip-all -o "$prefix.exe"
"$python" lift.py "$prefix.exe" "$prefix.ll"
clang -arch arm64 -O2 -Wno-override-module "$prefix.ll" runner.c -o "$prefix"
clang -arch arm64 -O2 -Dlifted=fixture switch.c runner.c -o "$prefix-reference"
"$python" verify.py "$prefix.exe" "$prefix" "$prefix-reference"

reject() {
    local fixture="$1"
    local bytes="$2"
    local diagnostic="$3"
    local prefix="$build/$fixture"
    printf '.text\n.globl fixture\nfixture:\n.byte %s\n' "$bytes" > "$prefix.s"
    clang -target x86_64-pc-windows-msvc -c "$prefix.s" -o "$prefix.obj"
    "$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$prefix.obj" \
        -Wl,--entry,fixture -Wl,--strip-all -o "$prefix.exe"
    if "$python" lift.py "$prefix.exe" "$prefix.ll" 2>"$prefix.log"; then
        echo "Unexpected acceptance of $fixture" >&2
        exit 1
    fi
    grep -F "$diagnostic" "$prefix.log"
}

reject unknown-indirect '0xff, 0xe1' 'indirect branch'
reject uninitialized-register '0xc3' 'undefined incoming eax'
reject uninitialized-flags '0x74, 0x00, 0x89, 0xc8, 0xc3' 'undefined incoming zf'
reject guest-memory '0x8b, 0x01, 0xc3' 'expected a supported 32-bit volatile register'

# Build a fixture import library directly. The Windows GNU SDK is optional.
cat > "$build/console-kernel32.def" <<'EOF'
LIBRARY kernel32.dll
EXPORTS
ExitProcess
GetCurrentProcessId
GetCurrentThreadId
GetLastError
GetStdHandle
GetSystemTimeAsFileTime
QueryPerformanceCounter
SetLastError
WriteFile
EOF
"$python" -m ziglang dlltool -m i386:x86-64 -d "$build/console-kernel32.def" \
    -l "$build/console-kernel32.lib"

for variant in console console-variant console-flow console-flow-O0 console-flow-loop console-data console-atomic console-seto console-bits console-pcmpeq console-zcnt console-shufpd; do
    prefix="$build/$variant"
    source=console.c
    optimization=-O2
    repeat=1
    definitions=()
    failure=1
    message="hello from PE"
    if [[ "$variant" == console-variant ]]; then
        message="a longer message from the guest image"
    elif [[ "$variant" == console-data ]]; then
        source=console_data.c
        message="hello from writable PE"
    elif [[ "$variant" == console-atomic ]]; then
        source=console_atomic.c
        message="atomic cmpxchg passed"
    elif [[ "$variant" == console-seto ]]; then
        source=console_seto.c
        message="seto and setno passed"
    elif [[ "$variant" == console-bits ]]; then
        source=console_bits.c
        message="bsr and bsf passed"
    elif [[ "$variant" == console-pcmpeq ]]; then
        source=console_pcmpeq.c
        message="pcmpeq passed"
    elif [[ "$variant" == console-zcnt ]]; then
        source=console_zcnt.c
        message="tzcnt and lzcnt passed"
    elif [[ "$variant" == console-shufpd ]]; then
        source=console_shufpd.c
        message="shufpd passed"
    elif [[ "$variant" == console-flow* ]]; then
        source=console_flow.c
        if [[ "$variant" == console-flow-O0 ]]; then
            optimization=-O0
        fi
        if [[ "$variant" == console-flow-loop ]]; then
            repeat=3
            definitions=(-DREPEAT=3)
        fi
        failure=7
        message="hello through an internal call"
    fi
    clang -target x86_64-pc-windows-msvc "$optimization" "-DMESSAGE=\"$message\"" \
        ${definitions[@]+"${definitions[@]}"} -c "$source" -o "$prefix.obj"
    "$python" -m ziglang cc -target x86_64-windows-gnu -nostdlib "$prefix.obj" \
        "$build/console-kernel32.lib" -Wl,--entry,entry -Wl,--strip-all -o "$prefix.exe"
    "$python" console_lift.py "$prefix.exe" "$prefix.ll"
    clang -arch arm64 -O2 -Wall -Wextra -Werror -Wno-override-module \
        "$prefix.ll" console_runtime.c -o "$prefix"
    file "$prefix.exe" "$prefix"
    "$python" verify_console.py "$prefix.exe" "$prefix" "$message" --failure-status "$failure" --repeat "$repeat"
done

# Change the expected return address in generated IR to exercise the runtime guard.
prefix="$build/console-flow"
sed '/call void @guest_check_return/s/, i64 %return_va)/, i64 0)/' \
    "$prefix.ll" > "$prefix-bad-return.ll"
clang -arch arm64 -O2 -Wno-override-module "$prefix-bad-return.ll" \
    console_runtime.c -o "$prefix-bad-return"
status=0
"$prefix-bad-return" > "$prefix-bad-return.stdout" 2>"$prefix-bad-return.stderr" || status=$?
[[ "$status" == 125 ]]
grep -Fx 'guest return address mismatch' "$prefix-bad-return.stderr"

# Virtual memory: zero-tag VirtualAlloc/MapViewOfFile through guest_load/guest_store.
clang -arch arm64 -O1 -w test_mmap.c -o "$build/test_mmap"
"$build/test_mmap"

# Optional Wine oracle: WINE/WINEPREFIX, else the copy setup_wine.py installs,
# else the one under work/. Without Wine the fixtures still run on ARM64.
repository="$(cd ../.. && pwd)"
if [[ -z "${WINE:-}" ]]; then
    for candidate in "$PWD/wine-runtime/Wine Stable.app/Contents/Resources/wine/bin/wine" \
                     "$repository/work/wine/Wine Stable.app/Contents/Resources/wine/bin/wine"; do
        if [[ -x "$candidate" ]]; then
            export WINE="$candidate"
            break
        fi
    done
    if [[ -n "${WINE:-}" && -z "${WINEPREFIX:-}" && -d "$repository/work/wine/prefix" ]]; then
        export WINEPREFIX="$repository/work/wine/prefix"
    fi
fi
export WINEDEBUG="${WINEDEBUG:--all}" MVK_CONFIG_LOG_LEVEL="${MVK_CONFIG_LOG_LEVEL:-0}"
export PYTHON="$python"

# Darwin SIGSEGV/SIGBUS delivery for raw VirtualAlloc faults to VEH and table-driven SEH.
fixtures/vm_fault/test.sh

# Runtime-generated code: interpreted PAGE_EXECUTE* buffers, RWX patching, DEP faults.
fixtures/jit/test.sh

# MSVC C++ EH and __try/__except, compared with Wine. Needs clang-cl and an xwin SDK.
if [[ -z "${XWIN_SDK:-}" && -d "$repository/work/xwin-sdk/crt" ]]; then
    export XWIN_SDK="$repository/work/xwin-sdk"
fi
if [[ -z "${CLANG_CL:-}" ]] && ! command -v clang-cl > /dev/null; then
    for candidate in /opt/homebrew/opt/llvm/bin/clang-cl /usr/local/opt/llvm/bin/clang-cl; do
        [[ -x "$candidate" ]] && export CLANG_CL="$candidate" && break
    done
fi
if [[ -n "${XWIN_SDK:-}" ]] && command -v "${CLANG_CL:-clang-cl}" > /dev/null &&
   command -v "${LLD_LINK:-lld-link}" > /dev/null; then
    fixtures/exception/test_msvc.sh
    echo "PASS MSVC exception fixture${WINE:+ (matches Wine)}"
elif [[ "${REQUIRE_MSVC:-0}" == 1 ]]; then
    echo "MSVC exception fixture needs XWIN_SDK, clang-cl, and lld-link" >&2
    exit 1
else
    echo "SKIP MSVC exception fixture (set XWIN_SDK and install LLVM clang-cl/lld-link)" >&2
fi
