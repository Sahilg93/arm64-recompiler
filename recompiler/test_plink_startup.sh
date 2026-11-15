#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
[[ $# == 1 ]] || { echo "Usage: $0 /path/to/plink.exe" >&2; exit 2; }
tool="$(cd "$(dirname "$0")" && pwd)"
python="${PYTHON:-python3}"
output="$("$python" "$tool/trace_callbacks.py" --max-attempts 64 "$1" -V)"
printf '%s\n' "$output" | tr -d '\r' | grep -Fx 'plink: Release 0.83'
