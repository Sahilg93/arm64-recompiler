#!/bin/bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 /path/to/jq.exe /path/to/output" >&2
    exit 2
fi

tool="$(cd "$(dirname "$0")" && pwd)"
python="${PYTHON:-python3}"
llvm_bin="${LLVM_BIN:-/opt/homebrew/opt/llvm@22/bin}"
if [[ ! -x "$llvm_bin/clang" || ! -x "$llvm_bin/llvm-link" ]]; then
    echo "Set LLVM_BIN to a directory containing matching clang and llvm-link executables." >&2
    exit 2
fi

mkdir -p "$(dirname "$2")"
output="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
if [[ -d "$output" ]]; then
    echo "Output must be a file path: $output" >&2
    exit 2
fi
build="$(mktemp -d "$(dirname "$output")/.jq-build.XXXXXXXX")"
trap 'rm -rf "$build"' EXIT

echo "Lifting $1" >&2
"$python" "$tool/console_lift.py" "$1" "$build/jq.ll"
echo "Compiling native ARM64 executable (parallel ThinLTO)" >&2
LLVM_BIN="$llvm_bin" TMPDIR="$build" "$tool/compile_parallel.sh" "$build/jq" "$tool/console_runtime.c" "$build/jq.ll"
mv -f "$build/jq" "$output"
printf '%s\n' "$output"
