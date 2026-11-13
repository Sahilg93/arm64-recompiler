"""Compare canonical xxHash output buffers across x86 and lifted ARM64."""

import argparse
import ctypes as c
from pathlib import Path
import random

from unicorn import UC_ARCH_X86, UC_HOOK_MEM_WRITE, UC_MODE_64, Uc
from unicorn import x86_const as x

from export_lift import read_export

PAGE = 4096
DEST, INPUT, STACK, STOP = (0x10000000 * n for n in range(1, 5))
ARENA = 96


def verify(path, library, width):
    image, entry, _ = read_export(path, f"XXH{width}_canonicalFromHash")
    base = image.OPTIONAL_HEADER.ImageBase
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    size = (image.OPTIONAL_HEADER.SizeOfImage + PAGE - 1) // PAGE * PAGE
    machine.mem_map(base, size)
    machine.mem_write(base, image.get_memory_mapped_image())
    for address in (DEST, INPUT, STACK, STOP):
        machine.mem_map(address, PAGE)
    stack = STACK + PAGE - 8
    machine.mem_write(stack, STOP.to_bytes(8, "little"))
    writes = []
    machine.hook_add(UC_HOOK_MEM_WRITE, lambda _, access, address, size, value, data:
                     writes.append((address, size)))
    write = c.CDLL(str(library.resolve())).write_export
    write.argtypes = [c.c_void_p, c.c_size_t, c.c_uint64, c.c_void_p, c.c_size_t]
    write.restype = None
    rng = random.Random(20261112 + width)
    count = width // 8
    values = [0, 1, (1 << width) - 1, *(1 << bit for bit in range(width))]
    values += [rng.getrandbits(width) for _ in range(5000)]
    for i, value in enumerate(values):
        offset = 16 + i % 16
        initial = rng.randbytes(ARENA)
        machine.mem_write(DEST, initial)
        little = value.to_bytes(count, "little")
        if width == 128:
            machine.mem_write(INPUT, little)
        machine.reg_write(x.UC_X86_REG_RCX, DEST + offset)
        machine.reg_write(x.UC_X86_REG_RDX, INPUT if width == 128 else value)
        machine.reg_write(x.UC_X86_REG_RSP, stack)
        writes.clear()
        machine.emu_start(base + entry, STOP, count=64)
        expected_writes = set(range(DEST + offset, DEST + offset + count))
        actual_writes = {byte for address, size in writes
                         for byte in range(address, address + size)}
        if machine.reg_read(x.UC_X86_REG_RIP) != STOP or actual_writes != expected_writes:
            raise RuntimeError(f"unexpected x86 control flow or write footprint: {writes!r}")
        output = c.create_string_buffer(initial, ARENA)
        source = c.create_string_buffer(little, count) if width == 128 else None
        write(c.byref(output, offset), count, value if width != 128 else 0,
              source, count if source is not None else 0)
        expected = initial[:offset] + value.to_bytes(count, "big") + initial[offset + count:]
        if output.raw != expected or machine.mem_read(DEST, ARENA) != expected:
            raise RuntimeError(f"buffer mismatch at case {i}, value {value:#x}")
        if source is not None and source.raw != little:
            raise RuntimeError("native input buffer was modified")
    print(f"XXH{width}: {len(values):,} complete buffer comparisons passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("native", type=Path)
    parser.add_argument("width", type=int, choices=[32, 64, 128])
    args = parser.parse_args()
    verify(args.dll, args.native, args.width)
