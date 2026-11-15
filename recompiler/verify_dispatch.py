"""Recover and check bounded byte dispatches in SQLite sqlite3_complete."""

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import capstone as cs
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, Uc
from unicorn import x86_const as x

from export_lift import read_export


def recover(image, entry, section):
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    thunk = image.get_data(entry, 5)
    if thunk[0] != 0xe9:
        raise ValueError("expected direct export thunk")
    body = entry + 5 + struct.unpack_from("<i", thunk, 1)[0]
    # The pinned build establishes RSI as the loaded image base before the
    # loop. Validate the exact dispatch idiom and derive offsets from bytes.
    setup = image.get_data(body + 0x21, 7)
    if setup[:3] != bytes.fromhex("488d35") or body + 0x28 + struct.unpack_from("<i", setup, 3)[0]:
        raise ValueError("expected image base initialization")
    start = body + 0x30
    expected = ("450fbec8", "418d41f7", "83f857", "0f87", "4898",
                "0fb68406", "8b9486", "4803d6", "ffe2")
    sizes = (4, 4, 3, 6, 2, 8, 7, 3, 2)
    ins = list(decoder.disasm(image.get_data(start, sum(sizes)), start))
    if len(ins) != len(sizes) or any(
        i.size != n or not bytes(i.bytes).startswith(bytes.fromhex(prefix))
        for i, n, prefix in zip(ins, sizes, expected)
    ):
        raise ValueError("dispatch bytes differ from the supported idiom")
    guard, index, table, jump = (ins[n] for n in (3, 5, 6, 8))
    default = guard.address + guard.size + struct.unpack_from("<i", guard.bytes, 2)[0]
    index_rva = struct.unpack_from("<i", index.bytes, 4)[0]
    table_rva = struct.unpack_from("<i", table.bytes, 3)[0]
    indices = image.get_data(index_rva, 88)
    if len(indices) != 88:
        raise ValueError("truncated index table")
    entries = max(indices) + 1
    if table_rva + entries * 4 > index_rva:
        raise ValueError("target table overlaps index table")
    targets = struct.unpack(f"<{entries}I", image.get_data(table_rva, entries * 4))
    lo = section.VirtualAddress
    hi = lo + section.Misc_VirtualSize
    if not all(lo <= address < hi for address in (*targets, default)):
        raise ValueError("target outside executable section")
    return start, jump.address, default, [targets[i] for i in indices]


def recover_relative(image, entry, section):
    """Recognize an unsigned byte guard followed by a signed relative table."""
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(image.get_data(entry, 512), entry))
    bases = {}
    candidates = []
    aliases = {**dict(zip(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"),
                         ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"))),
               **{f"r{i}d": f"r{i}" for i in range(8, 16)}}
    for index, ins in enumerate(instructions):
        args = ins.operands
        _, written = ins.regs_access()
        for register in written:
            name = ins.reg_name(register)
            bases.pop(aliases.get(name, name), None)
        if (ins.mnemonic == "lea" and args[1].type == cs.CS_OP_MEM
                and ins.reg_name(args[1].mem.base) == "rip"):
            bases[ins.reg_name(args[0].reg)] = ins.address + ins.size + args[1].mem.disp
        if ins.mnemonic != "cmp" or len(instructions) - index < 5:
            continue
        guard, load, add, jump = instructions[index + 1:index + 5]
        if [guard.mnemonic, load.mnemonic, add.mnemonic, jump.mnemonic] != [
            "ja", "movsxd", "add", "jmp"
        ]:
            continue
        if (args[0].type != cs.CS_OP_REG or args[1].type != cs.CS_OP_IMM
                or not 0 <= args[1].imm < 256
                or guard.operands[0].type != cs.CS_OP_IMM
                or load.operands[0].type != cs.CS_OP_REG
                or load.operands[1].type != cs.CS_OP_MEM
                or any(op.type != cs.CS_OP_REG for op in (*add.operands, *jump.operands))):
            continue
        mem = load.operands[1].mem
        dest = load.operands[0].reg
        base_name = ins.reg_name(mem.base)
        if (base_name not in bases or mem.index != args[0].reg or mem.scale != 4
                or mem.disp or mem.segment or add.operands[0].reg != dest
                or add.operands[1].reg != mem.base or jump.operands[0].reg != dest):
            continue
        # Require a byte load immediately before the guard comparison.
        previous = instructions[index - 1] if index else None
        index_name = ins.reg_name(mem.index)
        if (previous is None or previous.mnemonic != "movzx"
                or previous.operands[1].size != 1
                or aliases.get(previous.reg_name(previous.operands[0].reg)) != index_name):
            continue
        table = bases[base_name]
        count = args[1].imm + 1
        table_section = image.get_section_by_rva(table)
        if (table_section is None or table_section.Characteristics & 0x80000000
                or table + count * 4 > table_section.VirtualAddress + table_section.Misc_VirtualSize):
            continue
        raw = image.get_data(table, count * 4)
        targets = [table + displacement for displacement in struct.unpack(f"<{count}i", raw)]
        default = guard.operands[0].imm
        lo = section.VirtualAddress
        if not all(lo <= target < lo + section.Misc_VirtualSize for target in (*targets, default)):
            continue
        candidates.append((ins.address, jump.address, default, targets,
                           (table, ins.reg_name(mem.base), index_name, guard.address, guard.size)))
    if len(candidates) != 1:
        raise ValueError(f"expected one supported relative dispatch, found {len(candidates)}")
    return candidates[0]


def verify(image, start, jump, default, targets, first=9, context=None):
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    base = image.OPTIONAL_HEADER.ImageBase
    size = (image.OPTIONAL_HEADER.SizeOfImage + 4095) & -4096
    machine.mem_map(base, size)
    machine.mem_write(base, image.get_memory_mapped_image())
    observed = None
    dispatched = False
    if context is None:
        table, table_register, index_register = 0, "rsi", "r8"
        guard_rva, guard_size = start + 11, 6
    else:
        table, table_register, index_register, guard_rva, guard_size = context
    guard = base + guard_rva
    guard_end = guard + guard_size
    table_register = getattr(x, "UC_X86_REG_" + table_register.upper())
    index_register = getattr(x, "UC_X86_REG_" + index_register.upper())
    after_guard = False

    def stop_at_destination(uc, address, _size, _data):
        nonlocal observed, dispatched, after_guard
        if dispatched or (after_guard and address != guard_end):
            observed = address
            uc.emu_stop()
        else:
            after_guard = address == guard
            dispatched = address == base + jump

    machine.hook_add(UC_HOOK_CODE, stop_at_destination)
    for value in range(256):
        observed, dispatched, after_guard = None, False, False
        machine.reg_write(table_register, base + table)
        machine.reg_write(index_register, value)
        expected = selected(value, first, default, targets)
        machine.emu_start(base + start, 0, count=12)
        if observed != base + expected or dispatched != (first <= value < first + len(targets)):
            raise ValueError(f"target mismatch for byte {value:#04x} at dispatch {jump:#x}")


def selected(value, first, default, targets):
    index = value - first
    return targets[index] if 0 <= index < len(targets) else default


def verify_native(default, targets, first=9):
    # Return the selected guest RVA so the dispatch can be checked without
    # executing the case bodies of sqlite3_complete.
    lines = ["define i32 @dispatch(i8 %byte) {", "entry:",
             "  switch i8 %byte, label %fallback ["]
    for value, target in enumerate(targets, first):
        lines.append(f"    i8 {value}, label %target{target:x}")
    lines.extend(["  ]", "fallback:", f"  ret i32 {default}"])
    for target in sorted(set(targets)):
        lines.extend([f"target{target:x}:", f"  ret i32 {target}"])
    lines.append("}")
    with tempfile.TemporaryDirectory() as folder:
        ir = Path(folder) / "dispatch.ll"
        native = Path(folder) / "dispatch.dylib"
        ir.write_text("\n".join(lines) + "\n")
        subprocess.run(["clang", "-arch", "arm64", "-O2", "-Wno-override-module",
                        "-dynamiclib", str(ir), "-o", str(native)], check=True)
        library = ctypes.CDLL(str(native))
        dispatch = library.dispatch
        dispatch.argtypes = [ctypes.c_uint8]
        dispatch.restype = ctypes.c_uint32
        for value in range(256):
            expected = selected(value, first, default, targets)
            if dispatch(value) != expected:
                raise ValueError(f"ARM64 target mismatch for byte {value:#04x}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("--relative", "--clang-proposal", dest="relative", action="store_true")
    args = parser.parse_args()
    digest = sha256(args.dll.read_bytes()).hexdigest()
    image, entry, section = read_export(args.dll, "sqlite3_complete")
    try:
        if args.relative:
            start, jump, default, targets, table = recover_relative(image, entry, section)
            first = 0
        else:
            start, jump, default, targets = recover(image, entry, section)
            first, table = 9, None
        verify(image, start, jump, default, targets, first, table)
        verify_native(default, targets, first)
    except (ValueError, struct.error) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps({
        "export": "sqlite3_complete",
        "dll_sha256": digest,
        "layout": "clang-signed-offset" if args.relative else "two-level",
        "indirect_jump_rva": hex(jump),
        "indirect_targets": [hex(target) for target in sorted(set(targets))],
        "guard_default_rva": hex(default),
        "x86_and_arm64_verified_byte_values": 256,
        "guarded_indirect_byte_values": len(targets),
    }, indent=2))


if __name__ == "__main__":
    main()
