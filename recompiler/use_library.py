#!/usr/bin/env python3
"""Call a library produced by recompile.py."""

import argparse
import ctypes as c
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("left")
    compare.add_argument("right")
    encode = commands.add_parser("encode")
    encode.add_argument("width", type=int, choices=(32, 64, 128))
    encode.add_argument("hex_hash")
    args = parser.parse_args()
    try:
        library = c.CDLL(str(args.library.resolve(strict=True)))
        if args.command == "compare":
            routine = library.compare_export
            routine.argtypes = [c.c_char_p, c.c_size_t] * 2
            routine.restype = c.c_int32
            left, right = (value.encode() + b"\0" for value in (args.left, args.right))
            print(routine(left, len(left), right, len(right)))
        else:
            # The packaged library reports its ABI so the example can reject
            # a width mismatch before entering the native function.
            width = library.recompiler_hash_width
            width.argtypes = []
            width.restype = c.c_uint32
            if width() != args.width:
                raise ValueError(f"this library encodes {width()}-bit hashes")
            value = int(args.hex_hash, 16)
            if not 0 <= value < (1 << args.width):
                raise ValueError("hash does not fit the selected width")
            size = args.width // 8
            output = c.create_string_buffer(size)
            source = c.create_string_buffer(value.to_bytes(size, "little"), size) if size == 16 else None
            routine = library.write_export
            routine.argtypes = [c.c_void_p, c.c_size_t, c.c_uint64, c.c_void_p, c.c_size_t]
            routine.restype = None
            routine(output, size, value if source is None else 0, source,
                    size if source is not None else 0)
            print(output.raw.hex())
    except (AttributeError, OSError, ValueError) as error:
        parser.exit(1, f"Could not use library: {error}\n")


if __name__ == "__main__":
    main()
