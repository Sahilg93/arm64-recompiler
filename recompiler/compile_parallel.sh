#!/bin/bash
# Compile lifted LLVM IR plus the C runtime into a native ARM64 executable on
# all cores. One lifted module is a single huge translation unit, which a
# plain `clang -O2` optimizes and codegens on one thread. Instead:
#   1. llvm-split cuts the lifted module into PARTS partitions (round-robin,
#      so function counts balance),
#   2. each partition and the runtime compile to ThinLTO bitcode in parallel,
#   3. the ThinLTO link runs the per-module backends in parallel and imports
#      small runtime helpers (guest_load / guest_store fast paths) into the
#      lifted partitions, so they still inline as with llvm-link + -O2.
#
# Usage: compile_parallel.sh OUTPUT RUNTIME.c LIFTED.ll [EXTRA.ll ...]
# Env: LLVM_BIN (default /opt/homebrew/opt/llvm@22/bin), JOBS (default: cores),
#      PARTS (default 4 x JOBS), OPT (default -O2).
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 OUTPUT RUNTIME.c LIFTED.ll [EXTRA.ll ...]" >&2
    exit 2
fi
output="$1" runtime="$2"
shift 2
llvm_bin="${LLVM_BIN:-/opt/homebrew/opt/llvm@22/bin}"
jobs="${JOBS:-$(sysctl -n hw.ncpu)}"
# More partitions than cores, so a few huge lifted functions do not pin one backend.
parts="${PARTS:-$((jobs * 4))}"
opt="${OPT:--O2}"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
cc=("$llvm_bin/clang" -arch arm64 -isysroot "$sdk" "$opt")

work="$(mktemp -d "${TMPDIR:-/tmp}/compile-parallel.XXXXXXXX")"
trap 'rm -rf "$work"' EXIT

# Merge the lifted inputs (not the runtime) and split them into partitions.
if [[ $# -gt 1 ]]; then
    "$llvm_bin/llvm-link" "$@" -o "$work/lifted.bc"
else
    cp "$1" "$work/lifted.ll"
fi
lifted="$work/lifted.bc"
[[ -f "$lifted" ]] || lifted="$work/lifted.ll"
"$llvm_bin/llvm-split" --round-robin -j "$parts" -o "$work/part" "$lifted"
for part in "$work"/part[0-9]*; do mv "$part" "$part.bc"; done

# Compile the runtime and every partition to ThinLTO bitcode concurrently.
{
    printf '%s\0' "$runtime"
    for part in "$work"/part*.bc; do printf '%s\0' "$part"; done
} | xargs -0 -P "$jobs" -I{} sh -c '
    src="$1"; shift
    base="$(basename "$src")"
    exec "$@" -flto=thin -Wno-override-module -c "$src" -o "'"$work"'/$base.o"
' sh {} "${cc[@]}"

# ThinLTO link: ld64 runs the backends on all cores (one per partition).
"${cc[@]}" -flto=thin -Wno-override-module "$work"/*.o -o "$work/out"
mv -f "$work/out" "$output"
