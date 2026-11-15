#!/usr/bin/env python3
"""Scan PE binaries and rank missing imports against console_lift.py and apis.json."""

import argparse
from collections import Counter
import json
from pathlib import Path
import pefile

def get_known_imports(lifter_path: Path) -> set[str]:
    import sys
    sys.path.insert(0, str(lifter_path.parent))
    try:
        from generated_shims import GENERATED_SHIMS
    except ImportError:
        GENERATED_SHIMS = []
    scope = {"GENERATED_SHIMS": GENERATED_SHIMS}
    with open(lifter_path) as f:
        for line in f:
            if any(line.startswith(k) for k in ("FLS_IMPORTS =", "IDENTITY_IMPORTS =", "IMPORTS =")):
                exec(line, scope)
    known = set(scope.get("IMPORTS", set()))
    known.update({"AreFileApisANSI", "SetDefaultDllDirectories", "SetThreadDescription", "RegOpenKeyExA"})
    
    # Also load apis.json if present
    apis_path = lifter_path.parent / "apis.json"
    if apis_path.exists():
        with open(apis_path) as f:
            spec = json.load(f)
        known.update(spec.get("passthrough", []))
        for s in spec.get("stubs", []):
            known.add(s["name"])
        for a in spec.get("adapters", []):
            known.add(a["name"])
    return known

def scan_directory(corpus_dir: Path, known_imports: set[str], top_n: int = 25):
    freq = Counter()
    by_file: dict[str, list[tuple[str, str]]] = {}
    by_dll: dict[str, Counter] = {}

    pe_files = sorted(list(corpus_dir.glob("*.exe")) + list(corpus_dir.glob("*.dll")))
    if not pe_files:
        print(f"No .exe or .dll files found in {corpus_dir}")
        return

    for pe_path in pe_files:
        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            missing = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = entry.dll.decode("ascii", errors="replace").lower()
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("ascii", errors="replace")
                        if name not in known_imports:
                            missing.append((dll, name))
                            freq[name] += 1
                            by_dll.setdefault(dll, Counter())[name] += 1
            by_file[pe_path.name] = missing
        except Exception as e:
            print(f"Error scanning {pe_path.name}: {e}")

    print(f"\n{' Target Binaries ':=^55}")
    for name, misses in by_file.items():
        print(f"  {name:<35} {len(misses):>4} missing")

    print(f"\n{' Top Missing Functions Across Corpus ':=^55}")
    for name, count in freq.most_common(top_n):
        print(f"  {count:>2}x  {name}")

    print(f"\n{' Top Missing DLLs ':=^55}")
    for dll, funcs in sorted(by_dll.items(), key=lambda x: sum(x[1].values()), reverse=True):
        print(f"  {dll:<38} {len(funcs):>3} funcs ({sum(funcs.values()):>3} calls)")
    print("=" * 55)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, nargs="?", default=Path(__file__).parent.parent / "work" / "corpus")
    parser.add_argument("--lifter", type=Path, default=Path(__file__).parent / "console_lift.py")
    parser.add_argument("--top", type=int, default=25, help="Number of top functions to show")
    args = parser.parse_args()
    scan_directory(args.corpus, get_known_imports(args.lifter), top_n=args.top)
