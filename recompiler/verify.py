"""Compare a native Mach-O with the original PE instructions and C reference."""

import argparse
from itertools import product
from pathlib import Path
import random
import subprocess

import pefile

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn import x86_const as x86

from lift import read_entry

CODE = 0x100000
STOP = 0x200000
STACK = 0x300000
PAGE = 4096


def expected_from_x86(path, cases):
    entry, base, code = read_entry(path)
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    machine.mem_map(CODE, (len(code) + PAGE - 1) // PAGE * PAGE)
    machine.mem_write(CODE, code)
    image = pefile.PE(str(path))
    for section in image.sections:
        if section.VirtualAddress == base or not section.Misc_VirtualSize:
            continue
        start = CODE + section.VirtualAddress - base
        size = (section.Misc_VirtualSize + PAGE - 1) // PAGE * PAGE
        machine.mem_map(start, size)
        machine.mem_write(start, section.get_data()[:section.Misc_VirtualSize])
    machine.mem_map(STOP, PAGE)
    machine.mem_map(STACK, PAGE)
    sp = STACK + PAGE // 2 - 8
    machine.mem_write(sp, STOP.to_bytes(8, "little"))
    registers = (x86.UC_X86_REG_RAX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9,
                 x86.UC_X86_REG_R10, x86.UC_X86_REG_R11)
    for a, b in cases:
        for register in registers:
            machine.reg_write(register, 0xDEADBEEFDEADBEEF)
        machine.reg_write(x86.UC_X86_REG_EFLAGS, 0x203)
        machine.reg_write(x86.UC_X86_REG_RCX, a)
        machine.reg_write(x86.UC_X86_REG_RDX, b)
        machine.reg_write(x86.UC_X86_REG_RSP, sp)
        machine.emu_start(CODE + entry - base, STOP, count=2048)
        if machine.reg_read(x86.UC_X86_REG_RIP) != STOP:
            raise RuntimeError(f"x86 fixture did not return for {(a, b)}")
        yield machine.reg_read(x86.UC_X86_REG_EAX)


def native_results(path, cases):
    result = subprocess.run(
        [str(path.resolve())], input="".join(f"{a} {b}\n" for a, b in cases),
        text=True, capture_output=True, check=True, timeout=30,
    )
    return list(map(int, result.stdout.splitlines()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("lifted", type=Path)
    parser.add_argument("reference", type=Path)
    parser.add_argument("--x86-macho", type=Path)
    args = parser.parse_args()
    boundaries = [0, 1, 2, 3, 4, 5, 6, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]
    rng = random.Random(20261112)
    cases = list(product(boundaries, repeat=2))
    cases += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(10000)]
    cases += [(rng.randrange(7), rng.getrandbits(32)) for _ in range(1000)]
    x86_results = expected_from_x86(args.pe, cases)
    lifted_results = native_results(args.lifted, cases)
    reference_results = native_results(args.reference, cases)
    if args.x86_macho and native_results(args.x86_macho, cases) != lifted_results:
        raise SystemExit("original x86 bytes wrapped in Mach-O disagree with the lift")
    for case, guest, lifted, reference in zip(
        cases, x86_results, lifted_results, reference_results, strict=True,
    ):
        if guest != lifted or guest != reference:
            raise SystemExit(f"{case}: x86={guest}, lifted={lifted}, reference={reference}")
    suffix = ", plus original x86 bytes under Rosetta" if args.x86_macho else ""
    print(f"{len(cases):,} cases matched across x86 emulation, lifted ARM64, native C{suffix}")


if __name__ == "__main__":
    main()
