#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect best python
if [ -f "$DIR/work/venv/bin/python3" ]; then
    PY="$DIR/work/venv/bin/python3"
elif [ -f "$DIR/.venv/bin/python3" ]; then
    PY="$DIR/.venv/bin/python3"
else
    PY="python3"
fi

exec "$PY" "$DIR/recompiler/interactive_demo.py" "$@"
