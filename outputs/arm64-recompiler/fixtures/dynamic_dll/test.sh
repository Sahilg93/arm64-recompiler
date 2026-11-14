#!/bin/bash
set -euo pipefail

fixture="$(cd "$(dirname "$0")" && pwd)"
tool="$(cd "$fixture/../.." && pwd)"
python="${PYTHON:-python3}"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

"$fixture/build.sh" "$build"
for name in fixture fixture-main-thread; do
    "$python" "$tool/build_console_modules.py" "$build/$name.exe" \
        "$build/$name-arm64" "$build/fixture_plugin.dll" "$build/fixture_dependency.dll"
done
cd "$build"

run_case() {
    local binary="$1" name="$2" expected="$3" result=0
    "./$binary-arm64" || result=$?
    if [[ "$result" != "$expected" ]]; then
        echo "FAIL $name (expected $expected, got $result)" >&2
        exit 1
    fi
    echo "PASS $name"
}

printf 'not a PE file' > unrelated.dll
for name in fixture fixture-main-thread; do
    "$python" "$tool/run_exe.py" "$build/$name.exe" 2> launch.stderr
    if [[ -s launch.stderr ]]; then
        cat launch.stderr >&2
        exit 1
    fi
    echo "PASS on-demand DLL translation for $name"
done
rm unrelated.dll

run_case fixture-main-thread "main-thread DLL export, TLS, callback, and unload" 0
run_case fixture "worker-thread DLL export, isolated TLS, callback, and unload" 0
mv fixture_plugin.dll original.dll
run_case fixture-main-thread "missing DLL" 10
result=0
"$python" "$tool/run_exe.py" "$build/fixture-main-thread.exe" || result=$?
[[ "$result" == 10 ]]
echo "PASS missing DLL with on-demand translation"
cp original.dll fixture_plugin.dll
printf 'changed' >> fixture_plugin.dll
run_case fixture "changed DLL" 10

mv fixture_dependency.dll original-dependency.dll
mv original.dll fixture_plugin.dll
result=0
"$python" "$tool/run_exe.py" "$build/fixture-main-thread.exe" || result=$?
[[ "$result" == 10 ]]
echo "PASS missing transitive dependency"
