"""Lift the entry function of a restricted Windows x64 PE into LLVM IR."""

import argparse
from dataclasses import dataclass
from pathlib import Path

import capstone as cs
import pefile
from capstone import x86_const as x86

REGISTERS = ("eax", "ecx", "edx", "r8d", "r9d", "r10d", "r11d")
BRANCHES = {"jmp", "je", "jne", "ja", "jae", "jb", "jbe"}


def read_entry(path):
    return read_image_entry(pefile.PE(str(path)))


def read_image_entry(image):
    if (image.FILE_HEADER.Machine, image.OPTIONAL_HEADER.Magic) != (0x8664, 0x20B):
        raise ValueError("expected an x86-64 PE32+ image")
    entry = image.OPTIONAL_HEADER.AddressOfEntryPoint
    section = image.get_section_by_rva(entry)
    if section is None or not section.Characteristics & 0x20000000:
        raise ValueError("entry must be in an executable section")
    return entry, section.VirtualAddress, section.get_data()[:section.Misc_VirtualSize]


@dataclass(frozen=True)
class JumpTable:
    address: int
    default: int
    case_start: int
    targets: tuple


def recognize_entry_table(path, entry, base, code, decoder):
    # Exact Clang entry idiom: unsigned guard, result copy, zero-extended
    # index, RIP-relative table of signed 32-bit offsets, indirect jump.
    instructions = list(decoder.disasm(code[entry - base:], entry, count=8))
    if len(instructions) != 8:
        return None
    cmp, guard, copy, index, lea, load, add, jump = instructions
    if (cmp.mnemonic != "cmp" or len(cmp.operands) != 2
            or cmp.operands[0].type != x86.X86_OP_REG
            or cmp.operands[0].reg != x86.X86_REG_ECX
            or cmp.operands[1].type != x86.X86_OP_IMM
            or guard.mnemonic != "ja" or guard.operands[0].type != x86.X86_OP_IMM
            or bytes(copy.bytes) != bytes.fromhex("89d0")
            or bytes(index.bytes) != bytes.fromhex("89c9")
            or len(lea.bytes) != 7 or bytes(lea.bytes[:3]) != bytes.fromhex("488d15")
            or bytes(load.bytes) != bytes.fromhex("48630c8a")
            or bytes(add.bytes) != bytes.fromhex("4801d1")
            or bytes(jump.bytes) != bytes.fromhex("ffe1")):
        return None
    count = cmp.operands[1].imm + 1
    if not 1 <= count <= 256:
        raise ValueError("entry jump table exceeds supported bounds")
    table = lea.address + lea.size + lea.operands[1].mem.disp
    image = pefile.PE(str(path))
    section = image.get_section_by_rva(table)
    if (section is None or section.Characteristics & 0xa0000000
            or not section.Characteristics & 0x40000000
            or table + count * 4 > section.VirtualAddress + section.Misc_VirtualSize):
        raise ValueError("jump table must fit in read-only data")
    raw = image.get_data(table, count * 4)
    if len(raw) != count * 4:
        raise ValueError("truncated jump table")
    targets = tuple(table + int.from_bytes(raw[i:i + 4], "little", signed=True)
                    for i in range(0, len(raw), 4))
    default = guard.operands[0].imm
    case_start = jump.address + jump.size
    if any(not case_start <= target < base + len(code)
           for target in (default, *targets)):
        raise ValueError("jump table target outside supported case region")
    return JumpTable(entry, default, case_start, targets)


def discover(path, entry, base, data):
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    table = recognize_entry_table(path, entry, base, data, decoder)
    pending = [entry] if table is None else [table.default, *table.targets]
    instructions = {} if table is None else {entry: table}
    occupied = {}
    while pending:
        address = pending.pop()
        if table is not None and address < table.case_start:
            raise ValueError(f"branch back into jump table setup at RVA {address:#x}")
        if address in instructions:
            continue
        offset = address - base
        if not 0 <= offset < len(data):
            raise ValueError(f"target outside entry section at RVA {address:#x}")
        ins = next(decoder.disasm(data[offset:offset + 15], address, count=1), None)
        if ins is None:
            raise ValueError(f"cannot decode RVA {address:#x}")
        for byte in range(address, address + ins.size):
            if occupied.setdefault(byte, address) != address:
                raise ValueError(f"overlapping instructions at RVA {address:#x}")
        if ins.mnemonic == "call":
            raise ValueError(f"unsupported call at RVA {address:#x} ({ins.op_str})")
        instructions[address] = ins
        if ins.mnemonic in BRANCHES:
            if len(ins.operands) != 1 or ins.operands[0].type != x86.X86_OP_IMM:
                raise ValueError(f"indirect branch at RVA {address:#x}")
            pending.append(ins.operands[0].imm)
        if ins.mnemonic not in {"ret", "jmp"}:
            pending.append(address + ins.size)
    return instructions


class Lift:
    def __init__(self):
        self.lines = []
        self.counter = 0
        self.reads = set()
        self.writes = set()

    def line(self, text):
        self.lines.append(text)

    def value(self, expression):
        self.counter += 1
        name = f"%v{self.counter}"
        self.line(f"  {name} = {expression}")
        return name

    def store(self, kind, value, slot):
        self.writes.add(slot)
        self.line(f"  store {kind} {value}, ptr %{slot}")

    def load(self, kind, slot):
        if slot not in self.writes:
            self.reads.add(slot)
        return self.value(f"load {kind}, ptr %{slot}")

    def register(self, ins, operand):
        if operand.type == x86.X86_OP_REG and ins.reg_name(operand.reg) in REGISTERS:
            return ins.reg_name(operand.reg)
        raise ValueError("expected a supported 32-bit volatile register")

    def operand(self, ins, operand):
        if operand.type == x86.X86_OP_IMM:
            return str(operand.imm & 0xffffffff)
        return self.load("i32", self.register(ins, operand))

    def instruction(self, ins):
        if isinstance(ins, JumpTable):
            index = self.load("i32", "ecx")
            value = self.load("i32", "edx")
            self.line(f"  switch i32 {index}, label %pc{ins.default:x} [")
            for case, target in enumerate(ins.targets):
                self.line(f"    i32 {case}, label %case{target:x}")
            self.line("  ]")
            for target in dict.fromkeys(ins.targets):
                self.line(f"case{target:x}:")
                self.store("i32", value, "eax")
                self.line(f"  br label %pc{target:x}")
            return
        op = ins.mnemonic
        args = ins.operands
        next_block = f"%pc{ins.address + ins.size:x}"
        if op == "ret" and not args:
            result = self.load("i32", "eax")
            self.line(f"  ret i32 {result}")
            return
        if op in BRANCHES:
            target = f"%pc{args[0].imm:x}"
            if op == "jmp":
                self.line(f"  br label {target}")
                return
            if op in {"je", "jne"}:
                condition = self.load("i1", "zf")
            elif op in {"jb", "jae"}:
                condition = self.load("i1", "cf")
            else:
                carry = self.load("i1", "cf")
                zero = self.load("i1", "zf")
                condition = self.value(f"or i1 {carry}, {zero}")
            if op in {"jne", "jae", "ja"}:
                condition = self.value(f"xor i1 {condition}, true")
            self.line(f"  br i1 {condition}, label {target}, label {next_block}")
            return

        if op == "nop":
            pass
        elif op == "mov" and len(args) == 2:
            self.store("i32", self.operand(ins, args[1]), self.register(ins, args[0]))
        elif op in {"add", "sub", "and", "or", "xor", "test", "cmp", "neg", "shr"}:
            dest = self.register(ins, args[0])
            zeroing = (op in {"xor", "sub", "cmp"} and args[1].type == x86.X86_OP_REG
                       and args[0].reg == args[1].reg)
            lhs = "0" if zeroing else self.load("i32", dest)
            if op == "neg":
                result = self.value(f"sub i32 0, {lhs}")
                carry = self.value(f"icmp ne i32 {lhs}, 0")
            elif op == "shr":
                if args[1].type != x86.X86_OP_IMM or args[1].imm != 1:
                    raise ValueError("only a shift count of one is supported")
                result = self.value(f"lshr i32 {lhs}, 1")
                carry = self.value(f"trunc i32 {lhs} to i1")
            else:
                rhs = "0" if zeroing else self.operand(ins, args[1])
                llvm_op = {"test": "and", "cmp": "sub"}.get(op, op)
                result = self.value(f"{llvm_op} i32 {lhs}, {rhs}")
                if op == "add":
                    carry = self.value(f"icmp ult i32 {result}, {lhs}")
                elif op in {"sub", "cmp"}:
                    carry = self.value(f"icmp ult i32 {lhs}, {rhs}")
                else:
                    carry = "false"
            zero = self.value(f"icmp eq i32 {result}, 0")
            self.store("i1", zero, "zf")
            self.store("i1", carry, "cf")
            if op not in {"test", "cmp"}:
                self.store("i32", result, dest)
        else:
            raise ValueError("unsupported instruction")
        self.line(f"  br label {next_block}")

    def emit(self, entry, instructions):
        self.line("define i32 @lifted(i32 %a, i32 %b) {")
        self.line("entry:")
        for slot in REGISTERS:
            self.line(f"  %{slot} = alloca i32")
        self.store("i32", "%a", "ecx")
        self.store("i32", "%b", "edx")
        for slot in ("zf", "cf"):
            self.line(f"  %{slot} = alloca i1")
        self.line(f"  br label %pc{entry:x}")
        effects = {}
        for address, ins in sorted(instructions.items()):
            self.reads, self.writes = set(), set()
            self.line(f"pc{address:x}:")
            try:
                self.instruction(ins)
            except ValueError as error:
                raise ValueError(f"RVA {address:#x} ({ins.mnemonic} {ins.op_str}): {error}") from error
            effects[address] = self.reads, self.writes
        validate_initialization(entry, instructions, effects)
        self.line("}")
        return "\n".join(self.lines) + "\n"


def validate_initialization(entry, instructions, effects):
    predecessors = {address: [] for address in instructions}
    table_inputs = {}
    for address, ins in instructions.items():
        if isinstance(ins, JumpTable):
            table_inputs = {target: {"eax"} for target in ins.targets}
            table_inputs[ins.default] = set()
            continue
        if ins.mnemonic in BRANCHES:
            predecessors[ins.operands[0].imm].append(address)
        if ins.mnemonic not in {"ret", "jmp"}:
            predecessors[address + ins.size].append(address)

    # At a merge, a value is defined only if every incoming path defines it.
    incoming = {address: set(REGISTERS) | {"zf", "cf"} for address in instructions}
    changed = True
    while changed:
        changed = False
        for address, parents in predecessors.items():
            sources = [incoming[p] | effects[p][1] for p in parents]
            if address == entry:
                sources.append({"ecx", "edx"})
            if address in table_inputs:
                sources.append(table_inputs[address])
            defined = set.intersection(*sources)
            if defined != incoming[address]:
                incoming[address] = defined
                changed = True
    for address, (reads, _) in effects.items():
        missing = reads - incoming[address]
        if missing:
            raise ValueError(f"RVA {address:#x}: undefined incoming {', '.join(sorted(missing))}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        entry, base, code = read_entry(args.pe)
        args.output.write_text(Lift().emit(entry, discover(args.pe, entry, base, code)))
    except (ValueError, pefile.PEFormatError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
