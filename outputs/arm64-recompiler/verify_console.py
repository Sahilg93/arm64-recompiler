"""Compare the lifted console with original x86 execution and modeled imports."""

import argparse
from pathlib import Path
import subprocess
import time

import pefile
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_MODE_64, Uc
from unicorn import x86_const as x

from console_lift import IMPORTS, imported_calls

PAGE = 4096
STACK = 0x800000
STUBS = 0x900000


def run_guest(path, fail_write):
    image = pefile.PE(str(path))
    base = image.OPTIONAL_HEADER.ImageBase
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    size = (image.OPTIONAL_HEADER.SizeOfImage + PAGE - 1) // PAGE * PAGE
    machine.mem_map(base, size)
    machine.mem_write(base, image.get_memory_mapped_image())
    machine.mem_map(STACK, PAGE)
    machine.mem_map(STUBS, PAGE)
    machine.mem_map(STACK + PAGE, 2 * PAGE)
    teb, peb = STACK + PAGE, STACK + 2 * PAGE
    machine.reg_write(x.UC_X86_REG_GS_BASE, teb)
    for offset, value in ((8, STACK + PAGE), (16, STACK), (48, teb),
                          (64, 1000), (72, 1001), (96, peb)):
        machine.mem_write(teb + offset, value.to_bytes(8, "little"))
    machine.mem_write(peb + 16, base.to_bytes(8, "little"))
    sp = STACK + PAGE - 40
    machine.reg_write(x.UC_X86_REG_RSP, sp)
    imports = {}
    for index, (rva, name) in enumerate(imported_calls(image).items()):
        if name not in IMPORTS:
            continue
        stub = STUBS + index
        imports[stub] = name
        machine.mem_write(stub, b"\xc3")
        machine.mem_write(base + rva, stub.to_bytes(8, "little"))
    output = bytearray()
    status = None
    last_error = 0

    def dispatch(uc, address, _size, _data):
        nonlocal status, last_error
        name = imports.get(address)
        if name is None:
            raise RuntimeError(f"unexpected import stub {address:#x}")
        rcx = uc.reg_read(x.UC_X86_REG_RCX)
        if name == "ExitProcess":
            status = rcx & 0xffffffff
            uc.emu_stop()
            return
        if name == "GetSystemTimeAsFileTime":
            ticks = 116444736000000000 + time.time_ns() // 100
            uc.mem_write(rcx, ticks.to_bytes(8, "little"))
            result = 0xDEADBEEFDEADBEEF
        elif name == "GetCurrentProcessId":
            result = 1000
        elif name == "GetCurrentThreadId":
            result = 1001
        elif name == "QueryPerformanceCounter":
            uc.mem_write(rcx, time.monotonic_ns().to_bytes(8, "little"))
            result = 1
        elif name == "SetLastError":
            last_error = rcx & 0xffffffff
            result = 0xDEADBEEFDEADBEEF
        elif name == "GetLastError":
            result = last_error
        elif name == "GetStdHandle":
            result = 1 if rcx & 0xffffffff == 0xfffffff5 else 0xffffffffffffffff
        else:
            buffer = uc.reg_read(x.UC_X86_REG_RDX)
            count = uc.reg_read(x.UC_X86_REG_R8) & 0xffffffff
            written = uc.reg_read(x.UC_X86_REG_R9)
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            overlapped = int.from_bytes(uc.mem_read(rsp + 40, 8), "little")
            result = int(not fail_write and rcx == 1 and overlapped == 0)
            if not result:
                last_error = 6 if fail_write or rcx != 1 else 87
            if result:
                output.extend(uc.mem_read(buffer, count))
            uc.mem_write(written, (count if result else 0).to_bytes(4, "little"))
        for register in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8,
                         x.UC_X86_REG_R9, x.UC_X86_REG_R10, x.UC_X86_REG_R11):
            uc.reg_write(register, 0xDEADBEEFDEADBEEF)
        uc.reg_write(x.UC_X86_REG_RAX, result)

    def cpuid(uc, _data):
        leaf = uc.reg_read(x.UC_X86_REG_EAX)
        eax = 1 if leaf == 0 else 0x80000000 if leaf == 0x80000000 else 0
        vendor = b"AOTGuestCPU!" if leaf == 0 else bytes(12)
        for register, value in zip(
            (x.UC_X86_REG_RAX, x.UC_X86_REG_RBX, x.UC_X86_REG_RDX, x.UC_X86_REG_RCX),
            (eax, *(int.from_bytes(vendor[i:i+4], "little") for i in (0, 4, 8))),
        ):
            uc.reg_write(register, value)
        return 1

    def xgetbv(uc, address, size, _data):
        if size == 3 and uc.mem_read(address, 3) == b"\x0f\x01\xd0":
            if uc.reg_read(x.UC_X86_REG_ECX):
                raise RuntimeError("unsupported XGETBV index")
            uc.reg_write(x.UC_X86_REG_RAX, 3)
            uc.reg_write(x.UC_X86_REG_RDX, 0)
            uc.reg_write(x.UC_X86_REG_RIP, address + size)

    machine.hook_add(UC_HOOK_CODE, xgetbv, begin=base, end=base + size - 1)
    machine.hook_add(UC_HOOK_INSN, cpuid, None, 1, 0, x.UC_X86_INS_CPUID)
    machine.hook_add(UC_HOOK_CODE, dispatch, begin=STUBS, end=STUBS + PAGE - 1)
    machine.emu_start(base + image.OPTIONAL_HEADER.AddressOfEntryPoint, 0, count=10000)
    if status is None:
        raise RuntimeError("x86 guest did not call ExitProcess")
    return status, bytes(output)


def run_native(path, fail_write):
    # A read-only descriptor fails write(2) deterministically without SIGPIPE.
    with open("/dev/null", "rb") as read_only:
        process = subprocess.run(
            [str(path.resolve())],
            stdout=read_only if fail_write else subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10,
        )
    if process.stderr:
        raise RuntimeError(f"unexpected native stderr: {process.stderr!r}")
    return process.returncode, process.stdout or b""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("native", type=Path)
    parser.add_argument("message", nargs="?")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--failure-status", type=int, default=1)
    args = parser.parse_args()
    for fail_write in (False, True):
        expected = None
        if args.message is not None:
            expected = (args.failure_status, b"") if fail_write else (
                0, (args.message.encode() + b"\n") * args.repeat
            )
        guest = run_guest(args.pe, fail_write)
        native = run_native(args.native, fail_write)
        if native != guest or (args.message is not None and guest != expected):
            raise SystemExit(f"fail_write={fail_write}: x86={guest!r}, "
                             f"ARM64={native!r}, expected={expected!r}")
        print(f"console write {'failure' if fail_write else 'success'}: "
              f"x86 and ARM64 agree on stdout and status {native[0]}")


if __name__ == "__main__":
    main()
