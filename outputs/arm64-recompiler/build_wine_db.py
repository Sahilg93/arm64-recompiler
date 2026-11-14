#!/usr/bin/env python3
"""Extract all Windows exports from local Wine DLLs and build the master API database."""

import json
from pathlib import Path
import pefile

def main():
    root = Path(__file__).parent
    wine_dll_dir = Path("work/wine/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-windows")
    
    if not wine_dll_dir.exists():
        # Fallback search
        matches = list(Path(".").glob("**/Wine Stable.app/**/x86_64-windows"))
        if matches:
            wine_dll_dir = matches[0]
        else:
            print(f"Error: Wine DLL directory not found at {wine_dll_dir}")
            return

    print(f"Mining Wine DLLs from: {wine_dll_dir}")
    api_to_dll = {}
    dll_to_apis = {}

    for dll_path in sorted(wine_dll_dir.glob("*.dll")):
        dll_name = dll_path.name.lower()
        try:
            pe = pefile.PE(str(dll_path), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                funcs = []
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        func_name = exp.name.decode('ascii', errors='replace')
                        funcs.append(func_name)
                        # Map function to its primary defining DLL
                        if func_name not in api_to_dll:
                            api_to_dll[func_name] = dll_name
                if funcs:
                    dll_to_apis[dll_name] = funcs
        except Exception:
            continue

    print(f"Parsed {len(dll_to_apis)} DLLs.")
    print(f"Total unique API symbols: {len(api_to_dll)}")

    # Save compact database
    db = {
        "total_symbols": len(api_to_dll),
        "dll_count": len(dll_to_apis),
        "api_to_dll": api_to_dll,
        "core_dlls": {
            dll: dll_to_apis[dll]
            for dll in ("kernel32.dll", "kernelbase.dll", "ntdll.dll", "ucrtbase.dll", "advapi32.dll", "user32.dll")
            if dll in dll_to_apis
        }
    }

    out_file = root / "wine_api_db.json"
    with open(out_file, "w") as f:
        json.dump(db, f, indent=2)

    print(f"Wrote master Wine API database to {out_file} ({out_file.stat().st_size / 1024 / 1024:.2f} MB)")

if __name__ == "__main__":
    main()
