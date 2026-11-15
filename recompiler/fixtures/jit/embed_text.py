"""Write the .text section of a COFF object as a C initializer list.

The payload runs from a VirtualAlloc buffer, so it must not need relocations.
"""
import struct
import sys

data = open(sys.argv[1], "rb").read()
machine, count, _, _, _, optional, _ = struct.unpack_from("<HHIIIHH", data, 0)
if machine != 0x8664:
    sys.exit("expected an x86-64 COFF object")
for index in range(count):
    header = 20 + optional + index * 40
    name = data[header:header + 8].rstrip(b"\0")
    size, offset, _, _, relocations = struct.unpack_from("<IIIIH", data, header + 16)
    if name == b".text":
        if relocations:
            sys.exit(".text has relocations; the payload must be position-independent")
        text = data[offset:offset + size]
        with open(sys.argv[2], "w") as out:
            for start in range(0, len(text), 16):
                out.write(", ".join(f"0x{b:02x}" for b in text[start:start + 16]) + ",\n")
        break
else:
    sys.exit("no .text section")
