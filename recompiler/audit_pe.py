"""Inspect Windows x64 PE files and report the console lifter's first blocker."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

import pefile

from console_lift import (ConsoleLift, IMPORTS, imported_calls, loader_requirements,
                          read_console_image)


def audit(path):
    image = pefile.PE(str(path))
    entry, base, code, data = read_console_image(image)
    recognized = imported_calls(image)
    imports = [item for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ())
               for item in dll.imports]
    try:
        ConsoleLift(image).emit_console(entry, base, code, data)
        blocker = None
    except ValueError as error:
        blocker = str(error)
    tls = getattr(image, "DIRECTORY_ENTRY_TLS", None)
    callbacks = 0
    if tls and tls.struct.AddressOfCallBacks:
        rva = tls.struct.AddressOfCallBacks - image.OPTIONAL_HEADER.ImageBase
        while callbacks < 256:
            address = image.get_qword_at_rva(rva + callbacks * 8)
            if address is None:
                raise ValueError("invalid TLS callback table")
            if address == 0:
                break
            callbacks += 1
        else:
            raise ValueError("TLS callback table exceeds audit limit")
    supported = sum(name in IMPORTS for name in recognized.values())
    return {
        "file": path.name,
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "entry_rva": f"{entry:#x}",
        "loader_requirements": loader_requirements(image),
        "first_lift_blocker": blocker,
        "import_slots": len(imports),
        "known_import_slots": supported,
        "writable_sections": [
            section.Name.rstrip(b"\0").decode("ascii", errors="replace")
            for section in image.sections if section.Characteristics & 0x80000000
        ],
        "tls_directory": tls is not None,
        "tls_callbacks": callbacks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path, nargs="+")
    args = parser.parse_args()
    results = []
    for path in args.pe:
        try:
            results.append(audit(path))
        except (OSError, ValueError, pefile.PEFormatError) as error:
            results.append({"file": path.name, "audit_error": str(error)})
    print(json.dumps(results, indent=2))
    return int(any("audit_error" in result for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
