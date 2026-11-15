#!/usr/bin/env python3
"""Compare a recompiled jq 1.8.2 executable with upstream macOS jq 1.8.2."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def run(executable, args=(), data=b"", cwd=None):
    env = {**os.environ, "NO_COLOR": "1", "LC_ALL": "C"}
    return subprocess.run(
        [str(executable), *args], input=data, capture_output=True,
        cwd=cwd, env=env, timeout=30,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lifted", type=Path)
    parser.add_argument("reference", type=Path)
    args = parser.parse_args()
    lifted, reference = args.lifted.resolve(), args.reference.resolve()

    for executable in (lifted, reference):
        version = run(executable, ("--version",))
        if (version.returncode, version.stdout, version.stderr) != (0, b"jq-1.8.2\n", b""):
            parser.error(f"{executable} must report jq-1.8.2")

    cases = [
        ("stdin", (".[] | select(.score > 90) | .id",),
         b'[{"score":98,"id":11},{"score":55,"id":12}]', 0, b"11\n"),
        ("file input", ("-c", ".", "input.json"), b"", 0, b"[3,1,2]\n"),
        ("Unicode filename", ("-c", ".", "caf\u00e9.json"), b"", 0, b"[3,1,2]\n"),
        ("sorting", ("-c", "[.[] * 1.5] | sort"), b"[3,-1,2,3,0]",
         0, b"[-1.5,0,3,4.5,4.5]\n"),
        ("regex", ('[.[] | select(test("^prod-[0-9]+$"))] | length',),
         b'["prod-12","dev-2","prod-xyz","prod-8"]', 0, b"2\n"),
        ("malformed JSON", (".",), b'{"a":}', 5, b""),
        ("false exit status", ("-e", "."), b"false", 1, b"false\n"),
        ("no result exit status", ("-e", "empty"), b"null", 4, b""),
    ]
    failures = 0
    with tempfile.TemporaryDirectory(prefix="jq-parity-") as folder:
        cwd = Path(folder)
        for filename in ("input.json", "caf\u00e9.json"):
            (cwd / filename).write_bytes(b"[3,1,2]\n")
        for name, argv, data, status, stdout in cases:
            expected = run(reference, argv, data, cwd)
            actual = run(lifted, argv, data, cwd)
            reference_result = (expected.returncode, expected.stdout, expected.stderr)
            lifted_result = (actual.returncode, actual.stdout, actual.stderr)
            if reference_result[:2] != (status, stdout) or lifted_result != reference_result:
                failures += 1
                print(f"FAIL {name}\n  reference {reference_result!r}\n  lifted    {lifted_result!r}")
            else:
                print(f"PASS {name}")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
