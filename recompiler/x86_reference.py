"""Wrap the original PE text bytes in an x86-64 Mach-O for a second oracle."""

import argparse
from pathlib import Path

from lift import read_entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("assembly", type=Path)
    args = parser.parse_args()
    entry, base, code = read_entry(args.pe)
    lines = [".text", ".globl _guest"]
    for label, start, end in ((None, 0, entry - base), ("_guest:", entry - base, len(code))):
        if label:
            lines.append(label)
        for offset in range(start, end, 16):
            chunk = code[offset:min(end, offset + 16)]
            lines.append(".byte " + ", ".join(hex(byte) for byte in chunk))
    args.assembly.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
