"""Compare SQLite's original x86 export with a native lifted dylib."""

import argparse
import ctypes
from itertools import product
from pathlib import Path
import random

from unicorn import UC_ARCH_X86, UC_HOOK_MEM_WRITE, UC_MODE_64, Uc
from unicorn import x86_const as x

from export_lift import read_export

A, B, STACK, STOP = 0x10000000, 0x20000000, 0x30000000, 0x40000000
PAGE = 4096


def run(dll, native):
    image, entry, _ = read_export(dll, "sqlite3_stricmp")
    base = image.OPTIONAL_HEADER.ImageBase
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    size = (image.OPTIONAL_HEADER.SizeOfImage + PAGE - 1) // PAGE * PAGE
    machine.mem_map(base, size)
    machine.mem_write(base, image.get_memory_mapped_image())
    for address in (A, B, STACK, STOP):
        machine.mem_map(address, PAGE)
    sp = STACK + PAGE - 8
    machine.mem_write(sp, STOP.to_bytes(8, "little"))
    writes = []
    machine.hook_add(UC_HOOK_MEM_WRITE, lambda _, access, address, width, value, data:
                     writes.append((address, width)))

    compare = ctypes.CDLL(str(native.resolve())).compare_export
    compare.argtypes = [ctypes.c_char_p, ctypes.c_size_t] * 2
    compare.restype = ctypes.c_int32
    edge = [None, b"", b"a", b"A", b"z", b"Z", b"aB", b"ab", b"abc",
            b"abd", b"\xff", b"\x80", b"\x00abc", b"a" * 2000]
    cases = list(product(edge, repeat=2))
    cases += [(bytes([a]), bytes([b])) for a in range(256) for b in range(256)]
    rng = random.Random(20261112)
    for _ in range(2000):
        prefix = bytes(rng.randrange(1, 256) for _ in range(rng.randrange(200)))
        cases.append((prefix + rng.randbytes(4), prefix.swapcase() + rng.randbytes(4)))
        cases.append((prefix, prefix.swapcase()))

    for a, b in cases:
        inputs = [None if value is None else value + b"\0" for value in (a, b)]
        for value, address, reg in zip(inputs, (A, B), (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)):
            if value is not None:
                machine.mem_write(address, value)
            machine.reg_write(reg, address if value is not None else 0)
        machine.reg_write(x.UC_X86_REG_RSP, sp)
        writes.clear()
        machine.emu_start(base + entry, STOP, count=40000)
        if (machine.reg_read(x.UC_X86_REG_RIP) != STOP or
                machine.reg_read(x.UC_X86_REG_RSP) != sp + 8 or
                writes not in ([], [(sp - 8, 8)])):
            raise RuntimeError(f"x86 export did not return cleanly: {writes!r}")
        expected = ctypes.c_int32(machine.reg_read(x.UC_X86_REG_EAX)).value
        args = [item for value in inputs for item in (value, len(value or b""))]
        actual = compare(*args)
        if expected != actual:
            raise RuntimeError(f"{a!r}, {b!r}: x86={expected}, ARM64={actual}")
    print(f"{len(cases):,} exact return values matched. No writes outside the optional frame-save slot.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("native", type=Path)
    args = parser.parse_args()
    run(args.dll, args.native)
