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

for variant in console console-variant console-flow console-flow-O0 console-flow-loop console-data console-atomic; do
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
        -lkernel32 -Wl,--entry,entry -Wl,--strip-all -o "$prefix.exe"
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
