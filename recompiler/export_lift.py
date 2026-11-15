"""Lift a Windows x64 leaf export with a bounded buffer ABI."""

import argparse
from pathlib import Path

from capstone import x86_const as x
import pefile

from console_lift import ConsoleLift, VOLATILE
from lift import read_image_entry


def read_export(path, name):
    image = pefile.PE(str(path))
    read_image_entry(image)
    exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    matches = [item for item in exports.symbols
               if item.name == name.encode() and not item.forwarder] if exports else []
    if len(matches) != 1:
        raise ValueError(f"expected one direct export named {name}")
    entry = matches[0].address
    section = image.get_section_by_rva(entry)
    if section is None or not section.Characteristics & 0x20000000:
        raise ValueError("export is outside executable code")
    return image, entry, section


class ExportLift(ConsoleLift):
    def __init__(self, image, writable=False):
        super().__init__(image)
        self.writable = writable
    def reg(self, ins, operand):
        spelling = ins.reg_name(operand.reg)
        if not self.writable and spelling in {"rbp", "r10b", "r8b"}:
            return ("rbp", 64) if spelling == "rbp" else (spelling[:-1], 8)
        name, width = super().reg(ins, operand)
        if name not in VOLATILE and name not in {"rbp", "rsp"}:
            raise ValueError(f"unsupported leaf export register {name}")
        return name, width

    def address(self, ins, operand):
        mem = operand.mem
        if operand.type != x.X86_OP_MEM or mem.segment:
            raise ValueError("expected an unsegmented memory operand")
        if mem.base == x.X86_REG_RIP:
            return str(ins.address + ins.size + mem.disp)
        base = str(mem.disp)
        for register, scale in ((mem.base, 1), (mem.index, mem.scale)):
            if register:
                name = ins.reg_name(register)
                if name not in VOLATILE:
                    raise ValueError(f"unsupported address register {name}")
                value = self.read_reg(name, 64)
                if scale != 1:
                    value = self.value(f"mul i64 {value}, {scale}")
                base = self.value(f"add i64 {base}, {value}")
        return base

    def write(self, ins, operand, value):
        if operand.type != x.X86_OP_REG and not self.writable:
            raise ValueError("leaf export memory writes are outside this ABI")
        super().write(ins, operand, value)

    def step(self, ins, returns):
        op = ins.mnemonic
        args = ins.operands
        if op == "call" or (self.writable and op in {"push", "pop"}):
            raise ValueError("leaf export stack operations are outside this ABI")
        if op == "pop" and args[0].type == x.X86_OP_REG and ins.reg_name(args[0].reg) == "rbp":
            rsp = self.read_reg("rsp", 64)
            value = self.value(f"call i64 @guest_load(i64 {rsp}, i32 8)")
            self.write_reg("rbp", 64, value)
            self.write_reg("rsp", 64, self.value(f"add i64 {rsp}, 8"))
            self.jump(ins.address + ins.size, returns)
            return
        if op == "ret" and not args:
            if self.writable:
                self.line("  ret void")
                return
            rsp = self.read_reg("rsp", 64)
            self.line(f"  call void @check_export_stack(i64 {rsp})")
            value = self.read_reg("rax", 32)
            self.line(f"  ret i32 {value}")
            return
        if op == "bswap" and args[0].type == x.X86_OP_REG and args[0].size in (4, 8):
            name, width = self.reg(ins, args[0])
            value = self.read_reg(name, width)
            result = self.value(f"call i{width} @llvm.bswap.i{width}(i{width} {value})")
            self.write_reg(name, width, result)
        elif op == "neg":
            name, width = self.reg(ins, args[0])
            value = self.read_reg(name, width)
            result = self.value(f"sub i{width} 0, {value}")
            carry = self.value(f"icmp ne i{width} {value}, 0")
            zero = self.value(f"xor i1 {carry}, true")
            self.store("i1", carry, "cf")
            self.store("i1", zero, "zf")
            self.carry = self.zero = True
            self.signed = False
            self.write_reg(name, width, result)
        elif op == "sbb" and args[0].type == args[1].type == x.X86_OP_REG and args[0].reg == args[1].reg:
            if not self.carry:
                raise ValueError("sbb reads undefined carry")
            name, width = self.reg(ins, args[0])
            carry = self.load("i1", "cf")
            value = self.value(f"sext i1 {carry} to i{width}")
            self.write_reg(name, width, value)
            zero = self.value(f"xor i1 {carry}, true")
            self.store("i1", zero, "zf")
            self.zero = True
            self.signed = False
        else:
            super().step(ins, returns)
            return
        self.jump(ins.address + ins.size, returns)

    def emit_export(self, image, entry, section):
        ro_sections = [s for s in image.sections if s.Name.rstrip(b"\0") == b".rdata"]
        if len(ro_sections) != 1 or ro_sections[0].Characteristics & 0xa0000000:
            raise ValueError("expected read-only .rdata")
        ro = ro_sections[0]
        blob = ro.get_data()[:ro.Misc_VirtualSize]
        contents = "".join(f"\\{byte:02x}" for byte in blob)
        self.line(f'@guest_ro = constant [{len(blob)} x i8] c"{contents}"')
        self.line(f"@guest_ro_start = constant i64 {ro.VirtualAddress}")
        self.line(f"@guest_ro_size = constant i64 {len(blob)}")
        self.line("declare i64 @guest_load(i64, i32)")
        for width in (32, 64):
            self.line(f"declare i{width} @llvm.bswap.i{width}(i{width})")
        self.line("declare void @guest_store(i64, i64, i32)")
        if self.writable:
            self.line("define void @lifted_writer(i64 %a, i64 %b) {")
        else:
            self.line("declare void @check_export_stack(i64)")
            self.line("define i32 @lifted_export(i64 %a, i64 %b) {")
        self.line("entry:")
        for name in (*VOLATILE, "rbp", "rsp"):
            self.line(f"  %{name} = alloca i64")
        for flag in ("zf", "cf", "signed_less", "sf"):
            self.line(f"  %{flag} = alloca i1")
        self.store("i64", "%a", "rcx")
        self.store("i64", "%b", "rdx")
        self.store("i64", "0", "rbp")
        self.store("i64", str(0x30000ff8), "rsp")
        self.defined = {"rcx": 64, "rdx": 64, "rbp": 64, "rsp": 64}
        return self.emit_body(entry, section.VirtualAddress,
                              section.get_data()[:section.Misc_VirtualSize])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("name")
    parser.add_argument("output", type=Path)
    parser.add_argument("--writer", action="store_true",
                        help="void export taking a destination and scalar or pointer")
    args = parser.parse_args()
    try:
        image, entry, section = read_export(args.dll, args.name)
        args.output.write_text(ExportLift(image, args.writer).emit_export(image, entry, section))
    except (ValueError, pefile.PEFormatError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
