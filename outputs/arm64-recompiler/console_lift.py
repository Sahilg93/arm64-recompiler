"""Lift a restricted Windows console entry subset to native LLVM IR."""

import argparse
from pathlib import Path

import capstone as cs
from capstone import x86_const as x
import pefile

from lift import Lift, read_image_entry

MAX_BLOCKS = 60000

FLS_IMPORTS = {"FlsAlloc": 0x7fff1002, "FlsGetValue": 0x7fff1003, "FlsGetValue2": 0x7fff1003, "FlsSetValue": 0x7fff1004, "FlsFree": 0x7fff1005}
IDENTITY_IMPORTS = {"GetCurrentProcessId": 0, "GetCurrentThreadId": 1}
IMPORTS = {"GetStdHandle", "WriteFile", "ExitProcess", "SetLastError", "GetLastError", "GetSystemTimeAsFileTime", "QueryPerformanceCounter", "LoadLibraryExW", "GetProcAddress", "FreeLibrary", "GetProcessHeap", "HeapAlloc", "HeapFree", "HeapReAlloc", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection", "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx", "VirtualProtect", "GetStartupInfoW", "GetFileType", "GetCommandLineA", "GetCommandLineW", "GetACP", "GetOEMCP", "IsValidCodePage", "GetModuleFileNameW", "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExW", "WideCharToMultiByte", "MultiByteToWideChar", "InitializeSListHead", "GetEnvironmentStringsW", "FreeEnvironmentStringsW", "SetUnhandledExceptionFilter", "GetSystemDirectoryA", "GetSystemDirectoryW", "LoadLibraryA", "__acrt_iob_func", "fwrite", "fputs", "fflush", "_errno", "fputc", "putchar", "puts", "setvbuf", "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler", "MessageBoxA", "MessageBoxW", "_crt_atexit", "_register_onexit_function", "_initialize_onexit_table", "_execute_onexit_table", "_initterm", "_initterm_e", "_configure_wide_argv", "_configure_narrow_argv", "_initialize_wide_environment", "_initialize_narrow_environment", "_get_initial_wide_environment", "_get_initial_narrow_environment", "_set_app_type", "_seh_filter_exe", "_set_invalid_parameter_handler", "__p___argc", "__p___wargv", "__p___argv", "exit", "_exit", "_cexit", "SetThreadStackGuarantee", "malloc", "free", "calloc", "realloc", "GetCurrentThread", "GetCurrentProcess", "__p__fmode", "__p__commode"} | IDENTITY_IMPORTS.keys() | FLS_IMPORTS.keys()
VOLATILE = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
NONVOLATILE = ("rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15")
ALIASES = {
    "esp": ("rsp", 32),
    **{name: (name, 64) for name in NONVOLATILE},
    **{name: ("r" + name[1:], 32) for name in ("ebx", "ebp", "esi", "edi")},
    **{f"{name}d": (name, 32) for name in NONVOLATILE if name[1:].isdigit()},
    **{name: (name, 64) for name in (*VOLATILE, "rsp")},
    **{name: (f"r{name[1:]}", 32) for name in ("eax", "ecx", "edx")},
    **{f"{name}d": (name, 32) for name in VOLATILE if name[1:].isdigit()},
    **{name: (register, 8) for name, register in
       zip(("al", "bl", "cl", "dl", "sil", "dil", "bpl"),
           ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp"))},
    **{name: (register, 16) for name, register in
       zip(("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"),
           ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"))},
    **{f"r{i}w": (f"r{i}", 16) for i in range(8, 16)},
    **{f"r{i}b": (f"r{i}", 8) for i in range(8, 16)},
}


def imported_calls(image):
    return {
        item.address - image.OPTIONAL_HEADER.ImageBase: item.name.decode("ascii")
        for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ())
        for item in dll.imports if item.name
    }


class ConsoleLift(Lift):
    def __init__(self, image, *, trace=False, callback_targets=None):
        super().__init__()
        self.trace = trace
        self.shared = False
        self.image = image
        self.image_exception_entries = getattr(image, "DIRECTORY_ENTRY_EXCEPTION", ())
        self.traps = {}
        self.imports = imported_calls(image)
        self.iat_labels = {item.address - image.OPTIONAL_HEADER.ImageBase:
                           f"{dll.dll.decode('ascii', 'replace')}!" +
                           (item.name.decode("ascii", "replace") if item.name else f"#{item.ordinal}")
                           for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ())
                           for item in dll.imports}
        self.image_base = image.OPTIONAL_HEADER.ImageBase
        config = getattr(image, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
        self.cfg_dispatch_slots = {
            str(pointer - self.image_base)
            for field in ("GuardCFDispatchFunctionPointer", "GuardXFGDispatchFunctionPointer",
                          "GuardXFGTableDispatchFunctionPointer")
            if config and (pointer := getattr(config.struct, field, 0))
        }
        self.callback_targets = callback_targets or {}
        tls = getattr(image, "DIRECTORY_ENTRY_TLS", None)
        self.tls_callbacks = []
        if tls and tls.struct.AddressOfCallBacks:
            cb_rva = tls.struct.AddressOfCallBacks - self.image_base
            for idx in range(256):
                va = image.get_qword_at_rva(cb_rva + idx * 8)
                if va is None or va == 0:
                    break
                rva = va - self.image_base if va >= self.image_base else va
                self.tls_callbacks.append(rva)
        self.defined = dict.fromkeys(("rsp", *NONVOLATILE), 64)
        self.zero = False
        self.carry = False
        self.signed = False
        self.overflow = False
        self.blocks = {}
        self.pending = []
        self.decoded = {}
        self.occupied = {}

    def reg(self, ins, operand):
        name = ins.reg_name(operand.reg)
        if name not in ALIASES:
            raise ValueError(f"unsupported register {name}")
        return ALIASES[name]

    def read_reg(self, name, width):
        if self.shared:
            available = self.value(f"load i8, ptr %{name}_width")
            self.line(f"  call void @guest_require_register(i8 {available}, i8 {width})")
        elif self.defined.get(name, 0) < width:
            raise ValueError(f"undefined register {name}")
        value = self.load("i64", name)
        return value if width == 64 else self.value(f"trunc i64 {value} to i{width}")

    def write_reg(self, name, width, value):
        wide = value if width == 64 else self.value(f"zext i{width} {value} to i64")
        old_width = self.defined.get(name, 0)
        if width < 32 and (self.shared or old_width > width):
            previous = self.load("i64", name)
            upper = self.value(f"and i64 {previous}, {-1 << width}")
            wide = self.value(f"or i64 {upper}, {wide}")
        self.store("i64", wide, name)
        if self.shared:
            if width < 32:
                available = self.value(f"load i8, ptr %{name}_width")
                enough = self.value(f"icmp uge i8 {available}, {width}")
                validity = self.value(f"select i1 {enough}, i8 {available}, i8 {width}")
            else:
                validity = "64"
            self.line(f"  store i8 {validity}, ptr %{name}_width")
        self.defined[name] = max(old_width, width) if width < 32 else 64

    def address(self, ins, operand):
        mem = operand.mem
        if mem.segment not in (0, x.X86_REG_GS) or (ins.addr_size not in (4, 8) and ins.mnemonic != "lea"):
            raise ValueError("unsupported segmented or narrow address")
        if mem.base == x.X86_REG_RIP:
            return str(ins.address + ins.size + mem.disp)
        address = str(mem.disp + (0x2101000 if mem.segment else 0))
        for register, scale in ((mem.base, 1), (mem.index, mem.scale)):
            if register:
                name = ins.reg_name(register)
                if ins.addr_size == 4:
                    alias = ALIASES.get(name)
                    if alias is None or alias[1] != 32:
                        raise ValueError(f"unsupported 32-bit address register {name}")
                    low = self.read_reg(alias[0], 32)
                    value = self.value(f"zext i32 {low} to i64")
                else:
                    value = self.read_reg(name, 64)
                if ins.addr_size == 8 and name not in (*VOLATILE, "rsp", *NONVOLATILE):
                    raise ValueError(f"unsupported address register {name}")
                if scale != 1:
                    value = self.value(f"mul i64 {value}, {scale}")
                address = self.value(f"add i64 {address}, {value}")
        if ins.addr_size == 4:
            low = self.value(f"trunc i64 {address} to i32")
            return self.value(f"zext i32 {low} to i64")
        return address

    def read(self, ins, operand, width):
        if operand.type == x.X86_OP_IMM:
            return str(operand.imm % (1 << width))
        if operand.size * 8 != width:
            raise ValueError("operand width mismatch")
        if operand.type == x.X86_OP_REG:
            name = ins.reg_name(operand.reg)
            if name in {"ah", "bh", "ch", "dh"} and width == 8:
                low = self.read_reg(f"r{name[0]}x", 16)
                shifted = self.value(f"lshr i16 {low}, 8")
                return self.value(f"trunc i16 {shifted} to i8")
            return self.read_reg(*self.reg(ins, operand))
        if operand.type != x.X86_OP_MEM:
            raise ValueError("unsupported source operand")
        addr = self.address(ins, operand)
        if self.shared and width == 64 and addr.isdecimal():
            label = self.iat_labels.get(int(addr), "").lower()
            if label == "advapi32.dll!regopenkeyexa":
                return str(0x7fff1030)
            name = self.imports.get(int(addr))
            if name in {"GetSystemDirectoryA", "GetSystemDirectoryW"}:
                return str(0x7fff1020 + int(name.endswith("W")))
        value = self.value(f"call i64 @guest_load(i64 {addr}, i32 {width // 8})")
        return value if width == 64 else self.value(f"trunc i64 {value} to i{width}")

    def write(self, ins, operand, value):
        width = operand.size * 8
        if operand.type == x.X86_OP_REG:
            self.write_reg(*self.reg(ins, operand), value)
        elif operand.type == x.X86_OP_MEM:
            addr = self.address(ins, operand)
            wide = value if width == 64 else self.value(f"zext i{width} {value} to i64")
            self.line(f"  call void @guest_store(i64 {addr}, i64 {wide}, i32 {width // 8})")
        else:
            raise ValueError("unsupported destination operand")

    def trap(self, message):
        symbol = self.traps.setdefault(message, f"@guest_trap_message_{len(self.traps)}")
        self.line(f"  call void @guest_trap(ptr {symbol})")
        self.line("  unreachable")

    def import_call(self, ins, *, tail=False):
        operand = ins.operands[0]
        if operand.type != x.X86_OP_MEM or operand.mem.base != x.X86_REG_RIP:
            raise ValueError("expected a RIP-relative IAT call")
        slot = int(self.address(ins, operand))
        name = self.imports.get(slot)
        if name not in IMPORTS:
            label = self.iat_labels.get(slot)
            if label:
                self.trap(f"RVA {ins.address:#x}: unsupported import {label}")
                return True
            raise ValueError(f"call through non-IAT slot RVA {slot:#x}")
        if name == "ExitProcess":
            status = self.read_reg("rcx", 32)
            self.line(f"  call void @guest_exit(i32 {status})")
            self.line("  unreachable")
            return True
        if name in FLS_IMPORTS:
            self.dynamic_call(str(FLS_IMPORTS[name]))
            return False
        if name == "LoadLibraryA":
            path = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_load_library_a(i64 {path})")
        elif name in {"GetSystemDirectoryA", "GetSystemDirectoryW"}:
            buffer = self.read_reg("rcx", 64)
            size = self.read_reg("rdx", 32)
            wide = int(name.endswith("W"))
            result = self.value(f"call i64 @guest_system_directory(i64 {buffer}, i32 {size}, i32 {wide})")
        elif name == "SetUnhandledExceptionFilter":
            callback = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_exception_filter(i64 {callback})")
        elif name == "GetEnvironmentStringsW":
            result = self.value("call i64 @guest_environment()")
        elif name == "FreeEnvironmentStringsW":
            pointer = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_heap_free(i64 {0x7fff2001}, i32 0, i64 {pointer})")
        elif name == "__acrt_iob_func":
            index = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_acrt_iob_func(i32 {index})")
        elif name == "_errno":
            result = self.value("call i64 @guest_errno()")
        elif name == "fwrite":
            buffer = self.read_reg("rcx", 64)
            size = self.read_reg("rdx", 64)
            count = self.read_reg("r8", 64)
            stream = self.read_reg("r9", 64)
            result = self.value(f"call i64 @guest_fwrite(i64 {buffer}, i64 {size}, i64 {count}, i64 {stream})")
        elif name == "fputs":
            string = self.read_reg("rcx", 64)
            stream = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_fputs(i64 {string}, i64 {stream})")
        elif name == "fflush":
            stream = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_fflush(i64 {stream})")
        elif name == "fputc":
            ch = self.read_reg("rcx", 32)
            stream = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_fputc(i32 {ch}, i64 {stream})")
        elif name == "putchar":
            ch = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_putchar(i32 {ch})")
        elif name == "puts":
            string = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_puts(i64 {string})")
        elif name == "setvbuf":
            stream = self.read_reg("rcx", 64)
            buffer = self.read_reg("rdx", 64)
            mode = self.read_reg("r8", 32)
            size = self.read_reg("r9", 64)
            result = self.value(f"call i64 @guest_setvbuf(i64 {stream}, i64 {buffer}, i32 {mode}, i64 {size})")
        elif name == "AddVectoredExceptionHandler":
            first = self.read_reg("rcx", 32)
            handler = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_add_vectored_exception_handler(i32 {first}, i64 {handler})")
        elif name == "RemoveVectoredExceptionHandler":
            handle = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_remove_vectored_exception_handler(i64 {handle})")
        elif name == "MessageBoxA":
            hwnd = self.read_reg("rcx", 64)
            text = self.read_reg("rdx", 64)
            caption = self.read_reg("r8", 64)
            flags = self.read_reg("r9", 32)
            result = self.value(f"call i64 @guest_message_box_a(i64 {hwnd}, i64 {text}, i64 {caption}, i32 {flags})")
        elif name == "MessageBoxW":
            hwnd = self.read_reg("rcx", 64)
            text = self.read_reg("rdx", 64)
            caption = self.read_reg("r8", 64)
            flags = self.read_reg("r9", 32)
            result = self.value(f"call i64 @guest_message_box_w(i64 {hwnd}, i64 {text}, i64 {caption}, i32 {flags})")
        elif name == "_crt_atexit":
            fn = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_crt_atexit(i64 {fn})")
        elif name == "_register_onexit_function":
            table = self.read_reg("rcx", 64)
            fn = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_register_onexit(i64 {table}, i64 {fn})")
        elif name == "_initialize_onexit_table":
            table = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_init_onexit(i64 {table})")
        elif name == "_execute_onexit_table":
            table = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_exec_onexit(i64 {table})")
        elif name == "_initterm":
            start = self.read_reg("rcx", 64)
            end = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_initterm(i64 {start}, i64 {end})")
        elif name == "_initterm_e":
            start = self.read_reg("rcx", 64)
            end = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_initterm_e(i64 {start}, i64 {end})")
        elif name in {"_configure_wide_argv", "_configure_narrow_argv"}:
            mode = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_configure_argv(i32 {mode})")
        elif name in {"_initialize_wide_environment", "_initialize_narrow_environment"}:
            result = self.value("call i64 @guest_init_env()")
        elif name in {"_get_initial_wide_environment", "_get_initial_narrow_environment"}:
            result = self.value("call i64 @guest_get_initial_env()")
        elif name == "_set_app_type":
            type_val = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_set_app_type(i32 {type_val})")
        elif name == "_seh_filter_exe":
            code = self.read_reg("rcx", 32)
            info = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_seh_filter_exe(i32 {code}, i64 {info})")
        elif name == "_set_invalid_parameter_handler":
            h = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_set_invalid_param(i64 {h})")
        elif name == "__p___argc":
            result = self.value("call i64 @guest_p_argc()")
        elif name == "__p___wargv":
            result = self.value("call i64 @guest_p_wargv()")
        elif name == "__p___argv":
            result = self.value("call i64 @guest_p_argv()")
        elif name in {"exit", "_exit"}:
            status = self.read_reg("rcx", 32)
            self.line(f"  call void @guest_exit(i32 {status})")
            self.line("  unreachable")
            return
        elif name == "_cexit":
            result = self.value("call i64 @guest_cexit()")
        elif name == "__p__fmode":
            result = self.value("call i64 @guest_p_fmode()")
        elif name == "__p__commode":
            result = self.value("call i64 @guest_p_commode()")
        elif name == "SetThreadStackGuarantee":
            size_ptr = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_set_thread_stack_guarantee(i64 {size_ptr})")
        elif name == "malloc":
            size = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_heap_alloc(i64 {0x7fff2001}, i32 0, i64 {size})")
        elif name == "free":
            ptr = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_heap_free(i64 {0x7fff2001}, i32 0, i64 {ptr})")
        elif name == "calloc":
            num = self.read_reg("rcx", 64)
            size = self.read_reg("rdx", 64)
            total = self.value(f"mul i64 {num}, {size}")
            result = self.value(f"call i64 @guest_heap_alloc(i64 {0x7fff2001}, i32 8, i64 {total})")
        elif name == "realloc":
            ptr = self.read_reg("rcx", 64)
            size = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_heap_realloc(i64 {0x7fff2001}, i32 0, i64 {ptr}, i64 {size})")
        elif name == "InitializeSListHead":
            dest = self.read_reg("rcx", 64)
            high = self.value(f"add i64 {dest}, 8")
            for field in (dest, high):
                self.line(f"  call void @guest_store(i64 {field}, i64 0, i32 8)")
            result = None
        elif name in {"WideCharToMultiByte", "MultiByteToWideChar"}:
            page = self.read_reg("rcx", 32)
            flags = self.read_reg("rdx", 32)
            source = self.read_reg("r8", 64)
            length = self.read_reg("r9", 32)
            stack = self.read_reg("rsp", 64)
            offset = 40 if tail else 32
            arguments = [self.value(f"add i64 {stack}, {offset + i * 8}") for i in range(2)]
            dest, size = (self.value(f"call i64 @guest_load(i64 {pointer}, i32 {width})")
                          for pointer, width in zip(arguments, (8, 4)))
            wide = int(name == "MultiByteToWideChar")
            result = self.value(f"call i64 @guest_convert_text(i32 {wide}, i32 {page}, i32 {flags}, i64 {source}, i32 {length}, i64 {dest}, i64 {size})")
        elif name == "GetModuleHandleExW":
            flags = self.read_reg("rcx", 32)
            pointer = self.read_reg("rdx", 64)
            output = self.read_reg("r8", 64)
            result = self.value(f"call i64 @guest_module_handle_ex(i32 {flags}, i64 {pointer}, i64 {output})")
        elif name in {"GetModuleHandleA", "GetModuleHandleW"}:
            pointer = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_module_handle(i64 {pointer}, i32 {int(name.endswith('W'))})")
        elif name == "GetModuleFileNameW":
            module = self.read_reg("rcx", 64)
            buffer = self.read_reg("rdx", 64)
            size = self.read_reg("r8", 32)
            result = self.value(f"call i64 @guest_module_filename(i64 {module}, i64 {buffer}, i32 {size})")
        elif name == "IsValidCodePage":
            page = self.read_reg("rcx", 32)
            match = self.value(f"icmp eq i32 {page}, 65001")
            result = self.value(f"zext i1 {match} to i64")
        elif name in {"GetACP", "GetOEMCP"}:
            result = "65001"
        elif name in {"GetCommandLineA", "GetCommandLineW"}:
            result = self.value(f"call i64 @guest_command_line(i32 {int(name.endswith('W'))})")
        elif name == "GetFileType":
            handle = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_file_type(i64 {handle})")
        elif name == "GetStartupInfoW":
            address = self.read_reg("rcx", 64)
            self.line(f"  call void @guest_startup_info(i64 {address})")
            result = None
        elif name in {"EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection"}:
            section = self.read_reg("rcx", 64)
            entering = {"EnterCriticalSection": 1, "LeaveCriticalSection": 0, "DeleteCriticalSection": 2}[name]
            self.line(f"  call void @guest_critical_section(i64 {section}, i32 {entering})")
            result = None
        elif name in {"InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx"}:
            address = self.read_reg("rcx", 64)
            spin = self.read_reg("rdx", 32) if name in {"InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx"} else "0"
            self.line(f"  call void @guest_init_critical(i64 {address}, i32 {spin})")
            result = "1" if name != "InitializeCriticalSection" else None
        elif name == "VirtualProtect":
            addr = self.read_reg("rcx", 64)
            size = self.read_reg("rdx", 64)
            prot = self.read_reg("r8", 32)
            old_prot = self.read_reg("r9", 64)
            result = self.value(f"call i64 @guest_virtual_protect(i64 {addr}, i64 {size}, i32 {prot}, i64 {old_prot})")
        elif name == "HeapReAlloc":
            handle = self.read_reg("rcx", 64)
            flags = self.read_reg("rdx", 32)
            pointer = self.read_reg("r8", 64)
            size = self.read_reg("r9", 64)
            result = self.value(f"call i64 @guest_heap_realloc(i64 {handle}, i32 {flags}, i64 {pointer}, i64 {size})")
        elif name in {"HeapAlloc", "HeapFree"}:
            handle = self.read_reg("rcx", 64)
            flags = self.read_reg("rdx", 32)
            argument = self.read_reg("r8", 64)
            function = "guest_heap_alloc" if name == "HeapAlloc" else "guest_heap_free"
            result = self.value(f"call i64 @{function}(i64 {handle}, i32 {flags}, i64 {argument})")
        elif name == "GetProcessHeap":
            result = str(0x7fff2001)
        elif name in {"LoadLibraryExW", "GetProcAddress", "FreeLibrary"}:
            first = self.read_reg("rcx", 64)
            if name == "LoadLibraryExW":
                reserved = self.read_reg("rdx", 64)
                flags = self.read_reg("r8", 32)
                result = self.value(f"call i64 @guest_load_library(i64 {first}, i64 {reserved}, i32 {flags})")
            elif name == "GetProcAddress":
                symbol = self.read_reg("rdx", 64)
                result = self.value(f"call i64 @guest_get_proc(i64 {first}, i64 {symbol})")
            else:
                result = self.value(f"call i64 @guest_free_library(i64 {first})")
        elif name == "GetSystemTimeAsFileTime":
            address = self.read_reg("rcx", 64)
            self.line(f"  call void @guest_system_filetime(i64 {address})")
            result = None
        elif name == "GetCurrentThread":
            result = self.value("add i64 0, -2")
        elif name == "GetCurrentProcess":
            result = self.value("add i64 0, -1")
        elif name in IDENTITY_IMPORTS:
            result = self.value(f"call i64 @guest_identity(i32 {IDENTITY_IMPORTS[name]})")
        elif name == "QueryPerformanceCounter":
            address = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_performance_counter(i64 {address})")
        elif name == "SetLastError":
            value = self.read_reg("rcx", 32)
            self.line(f"  call void @guest_set_last_error(i32 {value})")
            result = None
        elif name == "GetLastError":
            result = self.value("call i64 @guest_get_last_error()")
        elif name == "GetStdHandle":
            selector = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_stdout(i32 {selector})")
        else:
            handle = self.read_reg("rcx", 64)
            buffer = self.read_reg("rdx", 64)
            size = self.read_reg("r8", 32)
            written = self.read_reg("r9", 64)
            stack = self.read_reg("rsp", 64)
            slot = self.value(f"add i64 {stack}, {40 if tail else 32}")
            overlapped = self.value(f"call i64 @guest_load(i64 {slot}, i32 8)")
            result = self.value(f"call i64 @guest_write(i64 {handle}, i64 {buffer}, "
                                f"i32 {size}, i64 {written}, i64 {overlapped})")
        for register in (*VOLATILE, *(f"xmm{i}" for i in range(6))):
            self.defined.pop(register, None)
            if self.shared:
                slot = f"{register}_0" if register.startswith("xmm") else register
                self.line(f"  store i8 0, ptr %{slot}_width")
        self.zero = False
        self.carry = False
        self.signed = False
        self.overflow = False
        if result is not None:
            self.write_reg("rax", 64, result)
        return False

    def block(self, address, returns):
        defined = () if self.shared else tuple(sorted(self.defined.items()))
        state = address, returns, defined, self.zero, self.carry, self.signed, self.overflow
        if state not in self.blocks:
            if len(self.blocks) >= MAX_BLOCKS:
                raise ValueError("console control-flow expansion exceeds block limit")
            self.blocks[state] = f"block{len(self.blocks)}"
            self.pending.append(state)
        return "%" + self.blocks[state]

    def jump(self, address, returns):
        self.line(f"  br label {self.block(address, returns)}")

    def dynamic_call(self, target):
        values = [self.load("i64", name) if self.shared else
                  self.read_reg(name, 64) if self.defined.get(name) == 64 else "0"
                  for name in ("rcx", "rdx", "r8", "r9")]
        arguments = ", ".join(f"i64 {value}" for value in (target, *values))
        result = self.value(f"call i64 @guest_indirect_call({arguments})")
        for register in (*VOLATILE, *(f"xmm{i}" for i in range(6))):
            self.defined.pop(register, None)
            if self.shared:
                slot = f"{register}_0" if register.startswith("xmm") else register
                self.line(f"  store i8 0, ptr %{slot}_width")
        self.zero = self.carry = self.signed = self.overflow = False
        self.write_reg("rax", 64, result)

    def return_to_caller(self, returns):
        rsp = self.read_reg("rsp", 64)
        self.line(f"  call void @guest_check_return(i64 {rsp}, i64 %return_va)")
        restored = self.value(f"add i64 {rsp}, 8")
        self.write_reg("rsp", 64, restored)
        self.line("  ret void")

    def internal_call(self, target, following, returns):
        rsp = self.read_reg("rsp", 64)
        slot = self.value(f"sub i64 {rsp}, 8")
        return_va = self.image_base + following
        self.line(f"  call void @guest_store(i64 {slot}, i64 {return_va}, i32 8)")
        self.write_reg("rsp", 64, slot)
        self.line(f"  call void @{self.function(target)}(ptr %cpu, i64 {return_va})")
        self.zero = self.carry = self.signed = self.overflow = False
        self.jump(following, returns)

    def guarded_call(self, ins, target, following, returns, *, tail=False):
        candidates = sorted(self.callback_targets.get(ins.address, ()))
        if candidates:
            self.counter += 1
            identifier = self.counter
            fallback = f"fallback{identifier}"
            self.line(f"  switch i64 {target}, label %{fallback} [")
            for address in candidates:
                self.line(f"    i64 {address}, label %callback{identifier}_{address:x}")
            self.line("  ]")
            initial = self.defined.copy()
            flags = self.zero, self.carry, self.signed, self.overflow
            for address in candidates:
                self.line(f"callback{identifier}_{address:x}:")
                self.defined = initial.copy()
                self.zero, self.carry, self.signed, self.overflow = flags
                if tail:
                    self.line(f"  musttail call void @{self.function(address)}(ptr %cpu, i64 %return_va)")
                    self.line("  ret void")
                else:
                    self.internal_call(address, following, returns)
            self.defined = initial
            self.line(f"{fallback}:")

        if tail:
            self.line(f"  call void @guest_indirect_dispatch(ptr %cpu, i64 {target}, i64 %return_va, i32 1)")
            self.line("  ret void")
        else:
            rsp = self.read_reg("rsp", 64)
            slot = self.value(f"sub i64 {rsp}, 8")
            return_va = self.image_base + following
            self.line(f"  call void @guest_store(i64 {slot}, i64 {return_va}, i32 8)")
            self.write_reg("rsp", 64, slot)
            result = self.value(f"call i64 @guest_indirect_dispatch(ptr %cpu, i64 {target}, i64 {return_va}, i32 0)")
            for register in (*VOLATILE, *(f"xmm{i}" for i in range(6))):
                self.defined.pop(register, None)
                if self.shared:
                    slot = f"{register}_0" if register.startswith("xmm") else register
                    self.line(f"  store i8 0, ptr %{slot}_width")
            self.zero = self.carry = self.signed = self.overflow = False
            self.write_reg("rax", 64, result)
            self.jump(following, returns)

    def crt_fill_jump(self, ins, returns):
        """Recognize the bounded, unrolled tail stores in the CRT fill routine."""
        prefix = bytes.fromhex("4981f88000000073c24d8d480f4983e1f04d8bd949c1eb04")
        start = ins.address - len(prefix) - 11
        code = self.image.get_data(start, len(prefix) + 14)
        if (code.startswith(prefix) and code[len(prefix):len(prefix) + 4] == bytes.fromhex("478b9c9a")
                and code[-6:] == bytes.fromhex("4d03da41ffe3")):
            table_bytes = code[len(prefix) + 4:len(prefix) + 8]
            table = int.from_bytes(table_bytes, "little")
            count, register, relative = 9, "r11", False
        elif (self.image.get_data(ins.address - 22, 11) ==
              bytes.fromhex("4983e1f04d8bd949c1eb04")
              and self.image.get_data(ins.address - 11, 4) == bytes.fromhex("478b9c9a")
              and self.image.get_data(ins.address - 3, 6) == bytes.fromhex("4d03da41ffe3")):
            table = int.from_bytes(self.image.get_data(ins.address - 7, 4), "little")
            count, register, relative = 9, "r11", False
        else:
            code = self.image.get_data(ins.address - 11, 14)
            guard = self.image.get_data(ins.address - 33, 10)
            if (code.startswith(bytes.fromhex("478b8c82"))
                    and code[-6:] == bytes.fromhex("4d03ca41ffe1")
                    and guard.startswith(bytes.fromhex("4983f80f0f87"))):
                table = int.from_bytes(code[4:8], "little")
                count, register, relative = 16, "r9", False
            else:
                code = self.image.get_data(ins.address - 16, 18)
                if code.startswith(bytes.fromhex("83f8060f87")) and code[-9:] == bytes.fromhex("496304864c01f0ffe0"):
                    pattern, count = bytes.fromhex("4c8d35"), 7
                elif code.startswith(bytes.fromhex("83f8040f87")) and code[-9:] == bytes.fromhex("486304864801f0ffe0"):
                    pattern, count = bytes.fromhex("488d35"), 5
                else:
                    return False
                # Bound the table-base search by the current function and
                # require a unique RIP-relative initialization of R14.
                start = max(self.current, ins.address - 512)
                window = self.image.get_data(start, ins.address - start)
                bases = [start + offset + 7 + int.from_bytes(window[offset + 3:offset + 7], "little", signed=True)
                         for offset in range(len(window) - 6)
                         if window[offset:offset + 3] == pattern]
                if len(bases) != 1:
                    return False
                table, count, register, relative = bases[0], count, "rax", True
        raw = self.image.get_data(table, count * 4)
        if len(raw) != count * 4:
            return False
        targets = sorted({(table if relative else 0) +
                          int.from_bytes(raw[i:i + 4], "little", signed=relative)
                          for i in range(0, len(raw), 4)})
        section = self.image.get_section_by_rva(ins.address)
        if not section or not all(section.contains_rva(target) for target in targets):
            return False
        target = self.read_reg(register, 64)
        self.counter += 1
        fallback = f"bad_fill_target{self.counter}"
        self.line(f"  switch i64 {target}, label %{fallback} [")
        for address in targets:
            self.line(f"    i64 {address}, label {self.block(address, returns)}")
        self.line("  ]")
        self.line(f"{fallback}:")
        self.trap(f"RVA {ins.address:#x}: CRT fill target outside bounded table")
        return True

    def step(self, ins, returns):
        op = ins.mnemonic
        if op in {"lock inc", "lock dec", "lock or", "lock and", "lock cmpxchg"}:
            op = op.removeprefix("lock ")
        args = ins.operands
        following = ins.address + ins.size
        if op == "call":
            operand = args[0]
            cfg_call = (operand.type == x.X86_OP_MEM and operand.mem.base == x.X86_REG_RIP
                        and not operand.mem.segment and self.address(ins, operand) in self.cfg_dispatch_slots)
            non_iat_mem = (operand.type == x.X86_OP_MEM and (operand.mem.base != x.X86_REG_RIP or
                           (int(self.address(ins, operand)) not in self.iat_labels and int(self.address(ins, operand)) not in self.imports)))
            if operand.type == x.X86_OP_REG or cfg_call or non_iat_mem:
                target = self.read_reg("rax", 64) if cfg_call else self.read(ins, operand, 64)
                self.guarded_call(ins, target, following, returns)
                return
            if args[0].type != x.X86_OP_IMM:
                if not self.import_call(ins):
                    self.jump(following, returns)
                return
            self.internal_call(args[0].imm, following, returns)
            return
        if op == "ret":
            if args and (args[0].type != x.X86_OP_IMM or args[0].imm != 0):
                raise ValueError("expected a plain return from an internal call")
            self.return_to_caller(returns)
            return
        if op in {"jmp", "je", "jne", "ja", "jae", "jb", "jbe", "jl", "jge", "jg", "jle", "jo", "jno", "js", "jns"}:
            operand = args[0]
            if self.shared and op == "jmp" and operand.type == x.X86_OP_REG:
                if self.crt_fill_jump(ins, returns):
                    return
                self.guarded_call(ins, self.read(ins, operand, 64), following, returns, tail=True)
                return
            if (op == "jmp" and operand.type == x.X86_OP_MEM
                    and operand.mem.base == x.X86_REG_RIP and not operand.mem.segment):
                if self.address(ins, operand) in self.cfg_dispatch_slots:
                    self.guarded_call(ins, self.read_reg("rax", 64), following, returns, tail=True)
                    self.return_to_caller(returns)
                elif not self.import_call(ins, tail=True):
                    self.return_to_caller(returns)
                return
            if args[0].type != x.X86_OP_IMM:
                if self.shared and op == "jmp" and self.crt_fill_jump(ins, returns):
                    return
                raise ValueError("unsupported indirect console branch")
            if op == "jmp":
                target = args[0].imm
                bound = self.runtime_functions.get(self.current) if self.shared else None
                if bound and not self.current <= target < bound and target in self.runtime_functions:
                    self.line(f"  musttail call void @{self.function(target)}(ptr %cpu, i64 %return_va)")
                    self.line("  ret void")
                else:
                    self.jump(target, returns)
                return
            if (op in {"je", "jne", "ja", "jbe", "jg", "jle"} and not self.zero
                    or op in {"ja", "jae", "jb", "jbe"} and not self.carry
                    or op in {"jl", "jge", "jg", "jle"} and not self.signed
                    or op in {"jo", "jno"} and not self.overflow
                    or op in {"js", "jns"} and not self.signed):
                raise ValueError("branch reads undefined flags")
            if op in {"js", "jns"}:
                condition = self.load("i1", "sf")
            elif op in {"jo", "jno"}:
                condition = self.load("i1", "of")
            elif op in {"je", "jne"}:
                condition = self.load("i1", "zf")
            elif op in {"jb", "jae"}:
                condition = self.load("i1", "cf")
            elif op in {"jl", "jge", "jg", "jle"}:
                condition = self.load("i1", "signed_less")
                if op in {"jg", "jle"}:
                    zero = self.load("i1", "zf")
                    condition = self.value(f"or i1 {condition}, {zero}")
            else:
                carry = self.load("i1", "cf")
                zero = self.load("i1", "zf")
                condition = self.value(f"or i1 {carry}, {zero}")
            taken = self.block(args[0].imm, returns)
            fallthrough = self.block(following, returns)
            yes, no = (fallthrough, taken) if op in {"jne", "ja", "jae", "jge", "jg", "jno", "jns"} else (taken, fallthrough)
            self.line(f"  br i1 {condition}, label {yes}, label {no}")
            return
        if op == "pop" and args[0].type == x.X86_OP_REG and args[0].size == 8:
            if self.reg(ins, args[0])[0] == "rsp":
                raise ValueError("pop into rsp is unsupported")
            rsp = self.read_reg("rsp", 64)
            value = self.value(f"call i64 @guest_load(i64 {rsp}, i32 8)")
            self.write(ins, args[0], value)
            self.write_reg("rsp", 64, self.value(f"add i64 {rsp}, 8"))
            self.jump(following, returns)
            return
        if op == "push" and args[0].size == 8:
            value = self.read(ins, args[0], 64)
            rsp = self.read_reg("rsp", 64)
            slot = self.value(f"sub i64 {rsp}, 8")
            self.line(f"  call void @guest_store(i64 {slot}, i64 {value}, i32 8)")
            self.write_reg("rsp", 64, slot)
            self.jump(following, returns)
            return
        if op in {"rep stosq", "rep stosd", "rep stosw", "rep stosb"}:
            width = args[0].size
            dest = self.read_reg("rdi", 64)
            count = self.read_reg("rcx", 64)
            value = self.read_reg("rax", width * 8)
            wide = value if width == 8 else self.value(f"zext i{width * 8} {value} to i64")
            end = self.value(f"call i64 @guest_fill(i64 {dest}, i64 {count}, i64 {wide}, i32 {width})")
            self.write_reg("rdi", 64, end)
            self.write_reg("rcx", 64, "0")
            self.jump(following, returns)
            return
        if op == "xgetbv":
            index = self.read_reg("rcx", 32)
            self.line(f"  call void @guest_check_xcr(i32 {index}, i64 {ins.address})")
            self.write_reg("rax", 32, "3")
            self.write_reg("rdx", 32, "0")
            self.jump(following, returns)
            return
        if op == "cpuid":
            leaf = self.read_reg("rax", 32)
            basic = self.value(f"icmp eq i32 {leaf}, 0")
            extended = self.value(f"icmp eq i32 {leaf}, 2147483648")
            maximum = self.value(f"select i1 {extended}, i32 2147483648, i32 0")
            self.write_reg("rax", 32, self.value(f"select i1 {basic}, i32 1, i32 {maximum}"))
            # Synthetic vendor ID "AOTGuestCPU!" in architectural order.
            for register, chunk in zip(("rbx", "rdx", "rcx"), (b"AOTG", b"uest", b"CPU!")):
                vendor = int.from_bytes(chunk, "little")
                value = self.value(f"select i1 {basic}, i32 {vendor}, i32 0")
                self.write_reg(register, 32, value)
            self.jump(following, returns)
            return
        if (op in {"movq", "movd"} or op == "movsd" and len(args) == 2 and args[1].type == x.X86_OP_MEM) and args[0].type == x.X86_OP_REG:
            name = ins.reg_name(args[0].reg)
            if name.startswith("xmm"):
                width = args[1].size * 8
                low = self.read(ins, args[1], width)
                if width == 32:
                    low = self.value(f"zext i32 {low} to i64")
                self.store("i64", low, f"{name}_0")
                self.store("i64", "0", f"{name}_1")
                self.defined[name] = 128
                if self.shared:
                    self.line(f"  store i8 128, ptr %{name}_0_width")
                self.jump(following, returns)
                return
        if op in {"movups", "movaps", "movdqu", "movdqa", "pxor", "xorps", "punpcklqdq", "punpcklbw", "pshuflw", "pshufd", "pcmpeqw", "pcmpeqb", "pmovmskb", "paddd", "movd", "movq", "movsd"}:
            dest, source = args[:2]
            def vector(operand):
                if operand.type == x.X86_OP_REG:
                    name = ins.reg_name(operand.reg)
                    if not name.startswith("xmm") or (not self.shared and self.defined.get(name) != 128):
                        raise ValueError(f"undefined vector {name}")
                    if self.shared:
                        available = self.value(f"load i8, ptr %{name}_0_width")
                        self.line(f"  call void @guest_require_register(i8 {available}, i8 128)")
                    return tuple(self.load("i64", f"{name}_{i}") for i in range(2))
                address = self.address(ins, operand)
                high = self.value(f"add i64 {address}, 8")
                return tuple(self.value(f"call i64 @guest_load(i64 {at}, i32 8)")
                             for at in (address, high))
            if op in {"movd", "movq", "movsd"} and dest.type == x.X86_OP_MEM or op in {"movd", "movq"}:
                low = vector(source)[0]
                value = low if dest.size == 8 else self.value(f"trunc i64 {low} to i{dest.size * 8}")
                self.write(ins, dest, value)
                self.jump(following, returns)
                return
            if op == "pmovmskb":
                low, high = vector(source)
                value = self.value(f"call i32 @guest_vector_mask(i64 {low}, i64 {high})")
                self.write(ins, dest, value)
                self.jump(following, returns)
                return
            if op == "paddd":
                output = []
                for a, b in zip(vector(dest), vector(source)):
                    left = self.value(f"bitcast i64 {a} to <2 x i32>")
                    right = self.value(f"bitcast i64 {b} to <2 x i32>")
                    total = self.value(f"add <2 x i32> {left}, {right}")
                    output.append(self.value(f"bitcast <2 x i32> {total} to i64"))
                values = output
            elif op in {"pcmpeqw", "pcmpeqb"}:
                values = tuple(self.value(f"call i64 @guest_compare_words(i64 {a}, i64 {b}, i32 {16 if op.endswith('w') else 8})")
                               for a, b in zip(vector(dest), vector(source)))
            elif op in {"punpcklbw", "pshuflw", "pshufd"}:
                low, high = vector(source)
                other = vector(dest)[0] if op == "punpcklbw" else "0"
                control = args[2].imm if op != "punpcklbw" else 0
                output = []
                for lane in range(2):
                    value = self.value(f"call i64 @guest_shuffle(i64 {low}, i64 {high}, i64 {other}, "
                                       f"i32 {('punpcklbw', 'pshuflw', 'pshufd').index(op)}, i32 {control}, i32 {lane})")
                    output.append(value)
                values = output
            elif op == "punpcklqdq":
                values = (vector(dest)[0], vector(source)[0])
            elif op in {"pxor", "xorps"}:
                values = ("0", "0") if dest.reg == source.reg else tuple(
                    self.value(f"xor i64 {left}, {right}") for left, right in zip(vector(dest), vector(source)))
            else:
                values = vector(source)
            if dest.type == x.X86_OP_REG:
                name = ins.reg_name(dest.reg)
                if not name.startswith("xmm"):
                    raise ValueError("expected XMM destination")
                for i, value in enumerate(values):
                    self.store("i64", value, f"{name}_{i}")
                self.defined[name] = 128
                if self.shared:
                    self.line(f"  store i8 128, ptr %{name}_0_width")
            else:
                address = self.address(ins, dest)
                high = self.value(f"add i64 {address}, 8")
                for at, value in zip((address, high), values):
                    self.line(f"  call void @guest_store(i64 {at}, i64 {value}, i32 8)")
            self.jump(following, returns)
            return
        if op == "nop":
            self.jump(following, returns)
            return
        width = args[0].size * 8 if args else 0
        if op == "cdqe":
            low = self.read_reg("rax", 32)
            self.write_reg("rax", 64, self.value(f"sext i32 {low} to i64"))
        elif op == "mov" or (op == "movabs" and args[1].type == x.X86_OP_IMM):
            if self.shared and width in (32, 64) and args[0].type == args[1].type == x.X86_OP_REG:
                dest, _ = self.reg(ins, args[0])
                source, _ = self.reg(ins, args[1])
                value = self.load("i64", source)
                available = self.value(f"load i8, ptr %{source}_width")
                if width == 32:
                    value = self.value(f"and i64 {value}, 4294967295")
                    complete = self.value(f"icmp uge i8 {available}, 32")
                    available = self.value(f"select i1 {complete}, i8 64, i8 {available}")
                self.store("i64", value, dest)
                self.line(f"  store i8 {available}, ptr %{dest}_width")
            elif (self.shared and width == 64 and args[0].type == x.X86_OP_MEM
                    and args[0].mem.base == x.X86_REG_RSP and args[1].type == x.X86_OP_REG
                    and ins.reg_name(args[1].reg) in VOLATILE):
                # ABI prologues and stack probes can spill unused volatile registers.
                value = self.load("i64", ins.reg_name(args[1].reg))
            else:
                value = self.read(ins, args[1], width)
            if not (self.shared and width in (32, 64) and args[0].type == args[1].type == x.X86_OP_REG):
                self.write(ins, args[0], value)
        elif op in {"movzx", "movsx", "movsxd"}:
            source_width = args[1].size * 8
            source = self.read(ins, args[1], source_width)
            extension = "zext" if op == "movzx" else "sext"
            self.write(ins, args[0], self.value(f"{extension} i{source_width} {source} to i{width}"))
        elif op == "lea" and width in (32, 64):
            address = self.address(ins, args[1])
            value = address if width == 64 else self.value(f"trunc i64 {address} to i32")
            self.write(ins, args[0], value)
        elif op in {"bt", "btr", "bts"} and args[0].type == x.X86_OP_REG and args[1].type in (x.X86_OP_REG, x.X86_OP_IMM):
            value, index = (self.read(ins, arg, width) for arg in args)
            index = self.value(f"and i{width} {index}, {width - 1}")
            shifted = self.value(f"lshr i{width} {value}, {index}")
            self.store("i1", self.value(f"trunc i{width} {shifted} to i1"), "cf")
            self.carry = True
            if op == "bts":
                mask = self.value(f"shl i{width} 1, {index}")
                self.write(ins, args[0], self.value(f"or i{width} {value}, {mask}"))
            if op == "btr":
                mask = self.value(f"shl i{width} 1, {index}")
                inverse = self.value(f"xor i{width} {mask}, -1")
                self.write(ins, args[0], self.value(f"and i{width} {value}, {inverse}"))
        elif op in {"xadd", "lock xadd"} and args[0].type == x.X86_OP_MEM and args[1].type == x.X86_OP_REG:
            left, right = (self.read(ins, arg, width) for arg in args)
            total = self.value(f"add i{width} {left}, {right}")
            self.write(ins, args[0], total)
            self.write(ins, args[1], left)
            self.zero = self.carry = self.signed = self.overflow = False
        elif op == "xchg" and args[0].type == x.X86_OP_MEM and args[1].type == x.X86_OP_REG:
            addr = self.address(ins, args[0])
            value = self.read(ins, args[1], width)
            wide = value if width == 64 else self.value(f"zext i{width} {value} to i64")
            previous = self.value(f"call i64 @guest_load(i64 {addr}, i32 {width // 8})")
            self.line(f"  call void @guest_store(i64 {addr}, i64 {wide}, i32 {width // 8})")
            value = previous if width == 64 else self.value(f"trunc i64 {previous} to i{width}")
            self.write(ins, args[1], value)
        elif op == "cmpxchg" and width in (32, 64) and args[1].type == x.X86_OP_REG:
            expected = self.read_reg("rax", width)
            replacement = self.read(ins, args[1], width)
            if args[0].type == x.X86_OP_MEM:
                addr = self.address(ins, args[0])
                ptr = self.value(f"call ptr @guest_pointer(i64 {addr}, i32 {width // 8})")
                res = self.value(f"cmpxchg ptr {ptr}, i{width} {expected}, i{width} {replacement} seq_cst seq_cst")
                old = self.value(f"extractvalue {{ i{width}, i1 }} {res}, 0")
            elif args[0].type == x.X86_OP_REG:
                temp = self.value(f"alloca i{width}")
                curr = self.read(ins, args[0], width)
                self.line(f"  store i{width} {curr}, ptr {temp}")
                res = self.value(f"cmpxchg ptr {temp}, i{width} {expected}, i{width} {replacement} seq_cst seq_cst")
                old = self.value(f"extractvalue {{ i{width}, i1 }} {res}, 0")
                new_val = self.value(f"load i{width}, ptr {temp}")
                self.write(ins, args[0], new_val)
            else:
                raise ValueError("unsupported cmpxchg destination")
            diff = self.value(f"sub i{width} {expected}, {old}")
            zero = self.value(f"icmp eq i{width} {old}, {expected}")
            carry = self.value(f"icmp ult i{width} {expected}, {old}")
            negative = self.value(f"icmp slt i{width} {diff}, 0")
            signed_less = self.value(f"icmp slt i{width} {expected}, {old}")
            overflow = self.value(f"xor i1 {negative}, {signed_less}")
            self.store("i1", zero, "zf")
            self.store("i1", carry, "cf")
            self.store("i1", negative, "sf")
            self.store("i1", signed_less, "signed_less")
            self.store("i1", overflow, "of")
            self.zero = self.carry = self.signed = self.overflow = True
            self.write_reg("rax", width, old)
        elif op in {"ror", "rol"} and width in (32, 64):
            value = self.read(ins, args[0], width)
            if args[1].type == x.X86_OP_IMM:
                count = str(args[1].imm % width)
            else:
                byte = self.read(ins, args[1], 8)
                count = self.value(f"zext i8 {byte} to i{width}")
            intrinsic = "fshr" if op == "ror" else "fshl"
            result = self.value(f"call i{width} @llvm.{intrinsic}.i{width}(i{width} {value}, i{width} {value}, i{width} {count})")
            self.carry = self.signed = self.overflow = False
            self.write(ins, args[0], result)
        elif op == "mul" and width in (32, 64):
            operands = (self.read_reg("rax", width), self.read(ins, args[0], width))
            extended = [self.value(f"zext i{width} {value} to i{width * 2}") for value in operands]
            product = self.value(f"mul i{width * 2} {extended[0]}, {extended[1]}")
            upper = self.value(f"lshr i{width * 2} {product}, {width}")
            for register, value in (("rax", product), ("rdx", upper)):
                self.write_reg(register, width, self.value(f"trunc i{width * 2} {value} to i{width}"))
            overflow = self.value(f"icmp ne i{width * 2} {upper}, 0")
            self.store("i1", overflow, "of")
            self.store("i1", overflow, "cf")
            self.carry = self.overflow = True
            self.zero = self.signed = False
        elif op == "imul" and len(args) in (2, 3):
            left, right = (self.read(ins, arg, width) for arg in args[-2:])
            value = self.value(f"mul i{width} {left}, {right}")
            self.write(ins, args[0], value)
            self.zero = self.carry = self.signed = self.overflow = False
        elif op == "div" and width == 32:
            parts = [self.read_reg(name, 32) for name in ("rdx", "rax")]
            high, low = (self.value(f"zext i32 {part} to i64") for part in parts)
            top = self.value(f"shl i64 {high}, 32")
            combined = self.value(f"or i64 {top}, {low}")
            denominator = self.read(ins, args[0], 32)
            wide = self.value(f"zext i32 {denominator} to i64")
            self.line(f"  call void @guest_div32(i64 {combined}, i64 {wide}, ptr %rax, ptr %rdx)")
            self.write_reg("rax", 64, self.load("i64", "rax"))
            self.write_reg("rdx", 64, self.load("i64", "rdx"))
            self.zero = self.carry = self.signed = self.overflow = False
        elif op == "div" and width == 64:
            denominator = self.read(ins, args[0], 64)
            high = self.read_reg("rdx", 64)
            low = self.read_reg("rax", 64)
            self.line(f"  call void @guest_div(i64 {high}, i64 {low}, i64 {denominator}, ptr %rax, ptr %rdx)")
            self.write_reg("rax", 64, self.load("i64", "rax"))
            self.write_reg("rdx", 64, self.load("i64", "rdx"))
            self.zero = self.carry = self.signed = self.overflow = False
        elif op in {"adc", "sbb"} and args[1].type == x.X86_OP_IMM:
            if not self.carry:
                raise ValueError(f"{op} reads undefined carry")
            original = self.read(ins, args[0], width)
            right = self.read(ins, args[1], width)
            carry = self.load("i1", "cf")
            bit = self.value(f"zext i1 {carry} to i{width}")
            operation = "add" if op == "adc" else "sub"
            difference = self.value(f"{operation} i{width} {original}, {right}")
            value = self.value(f"{operation} i{width} {difference}, {bit}")
            if op == "adc":
                borrow = self.value(f"icmp ult i{width} {difference}, {original}")
                extra = self.value(f"icmp ult i{width} {value}, {difference}")
            else:
                borrow = self.value(f"icmp ult i{width} {original}, {right}")
                extra = self.value(f"icmp ult i{width} {difference}, {bit}")
            self.write(ins, args[0], value)
            self.store("i1", self.value(f"icmp eq i{width} {value}, 0"), "zf")
            self.store("i1", self.value(f"or i1 {borrow}, {extra}"), "cf")
            self.zero, self.signed, self.overflow = True, False, False
        elif op == "neg" or (op == "sbb" and args[0].type == args[1].type == x.X86_OP_REG
                              and args[0].reg == args[1].reg):
            if op == "neg":
                original = self.read(ins, args[0], width)
                value = self.value(f"sub i{width} 0, {original}")
                carry = self.value(f"icmp ne i{width} {original}, 0")
                overflow = self.value(f"icmp eq i{width} {original}, {1 << (width - 1)}")
            else:
                if not self.carry:
                    raise ValueError("sbb reads undefined carry")
                carry = self.load("i1", "cf")
                value = self.value(f"sext i1 {carry} to i{width}")
                overflow = "false"
            negative = self.value(f"icmp slt i{width} {value}, 0")
            self.store("i1", negative, "sf")
            self.store("i1", self.value(f"xor i1 {negative}, {overflow}"), "signed_less")
            self.store("i1", self.value(f"icmp eq i{width} {value}, 0"), "zf")
            self.store("i1", carry, "cf")
            self.overflow = False
            self.zero = self.carry = self.signed = True
            self.write(ins, args[0], value)
        elif op == "not":
            value = self.read(ins, args[0], width)
            self.write(ins, args[0], self.value(f"xor i{width} {value}, -1"))
        elif op in {"shl", "shr", "sar"} and width in (8, 16, 32, 64):
            shift_width = max(width, 32)
            if args[1].type == x.X86_OP_IMM:
                count = str(args[1].imm & (shift_width - 1))
            else:
                byte = self.read(ins, args[1], 8)
                wide = self.value(f"zext i8 {byte} to i{shift_width}")
                count = self.value(f"and i{shift_width} {wide}, {shift_width - 1}")
            if count != "0":
                previous = self.read(ins, args[0], width)
                operation = {"shl": "shl", "shr": "lshr", "sar": "ashr"}[op]
                if shift_width != width:
                    extend = "sext" if op == "sar" else "zext"
                    previous = self.value(f"{extend} i{width} {previous} to i{shift_width}")
                value = self.value(f"{operation} i{shift_width} {previous}, {count}")
                if shift_width != width:
                    value = self.value(f"trunc i{shift_width} {value} to i{width}")
                zero = self.value(f"icmp eq i{width} {value}, 0")
                if args[1].type != x.X86_OP_IMM and self.zero:
                    unchanged = self.value(f"icmp eq i{shift_width} {count}, 0")
                    prior_zero = self.load("i1", "zf")
                    zero = self.value(f"select i1 {unchanged}, i1 {prior_zero}, i1 {zero}")
                self.store("i1", zero, "zf")
                self.zero = self.zero or args[1].type == x.X86_OP_IMM
                self.carry = self.signed = self.overflow = False
                self.write(ins, args[0], value)
        elif op == "cmovs" and self.signed:
            condition = self.load("i1", "sf")
            old, candidate = (self.read(ins, arg, width) for arg in args)
            selected = self.value(f"select i1 {condition}, i{width} {candidate}, i{width} {old}")
            self.write(ins, args[0], selected)
        elif op in {"cmove", "cmovne", "cmova", "cmovb", "cmovae"} and (self.zero or op in {"cmovb", "cmovae"}):
            condition = "false" if op in {"cmovb", "cmovae"} else self.load("i1", "zf")
            if op in {"cmova", "cmovb", "cmovae"}:
                if not self.carry:
                    raise ValueError("cmova reads undefined carry")
                carry = self.load("i1", "cf")
                condition = self.value(f"or i1 {carry}, {condition}") if op == "cmova" else carry
            if op in {"cmovne", "cmova", "cmovae"}:
                condition = self.value(f"xor i1 {condition}, true")
            old, candidate = (self.read(ins, arg, width) for arg in args)
            selected = self.value(f"select i1 {condition}, i{width} {candidate}, i{width} {old}")
            self.write(ins, args[0], selected)
        elif op in {"inc", "dec"}:
            previous = self.read(ins, args[0], width)
            operation = "add" if op == "inc" else "sub"
            value = self.value(f"{operation} i{width} {previous}, 1")
            zero = self.value(f"icmp eq i{width} {value}, 0")
            self.store("i1", zero, "zf")
            self.zero = True
            boundary = (1 << (width - 1)) - (1 if op == "inc" else 0)
            overflow = self.value(f"icmp eq i{width} {previous}, {boundary}")
            negative = self.value(f"icmp slt i{width} {value}, 0")
            self.store("i1", negative, "sf")
            self.store("i1", self.value(f"xor i1 {negative}, {overflow}"), "signed_less")
            self.signed = True
            self.overflow = False
            self.write(ins, args[0], value)
        elif op in {"sub", "add", "and", "or", "xor", "test", "cmp"}:
            zeroing = (op == "xor" and args[0].type == args[1].type == x.X86_OP_REG
                       and args[0].reg == args[1].reg)
            zeroing |= op == "and" and args[1].type == x.X86_OP_IMM and args[1].imm == 0
            all_ones = op == "or" and args[1].type == x.X86_OP_IMM and args[1].imm & ((1 << width) - 1) == (1 << width) - 1
            lhs, rhs = ("0", "-1") if all_ones else ("0", "0") if zeroing else (
                self.read(ins, arg, width) for arg in args
            )
            ir_op = {"test": "and", "cmp": "sub"}.get(op, op)
            value = self.value(f"{ir_op} i{width} {lhs}, {rhs}")
            zero = self.value(f"icmp eq i{width} {value}, 0")
            self.store("i1", zero, "zf")
            self.zero = True
            if op == "add":
                carry = self.value(f"icmp ult i{width} {value}, {lhs}")
            elif op in {"sub", "cmp"}:
                carry = self.value(f"icmp ult i{width} {lhs}, {rhs}")
            else:
                carry = "false"
            self.store("i1", carry, "cf")
            self.carry = True
            negative = self.value(f"icmp slt i{width} {value}, 0")
            self.store("i1", negative, "sf")
            if op in {"sub", "cmp"}:
                signed_less = self.value(f"icmp slt i{width} {lhs}, {rhs}")
            else:
                signed_less = negative
                if op == "add":
                    left = self.value(f"xor i{width} {lhs}, {value}")
                    right = self.value(f"xor i{width} {rhs}, {value}")
                    both = self.value(f"and i{width} {left}, {right}")
                    overflow = self.value(f"icmp slt i{width} {both}, 0")
                    signed_less = self.value(f"xor i1 {negative}, {overflow}")
            self.store("i1", signed_less, "signed_less")
            self.signed = True
            self.overflow = False
            if op not in {"test", "cmp"}:
                self.write(ins, args[0], value)
        elif op in {"setb", "setae"} and self.carry:
            value = self.load("i1", "cf")
            if op == "setae":
                value = self.value(f"xor i1 {value}, true")
            self.write(ins, args[0], self.value(f"zext i1 {value} to i8"))
        elif op in {"sete", "setne", "setbe", "seta", "setg"} and self.zero:
            value = self.load("i1", "zf")
            if op == "setg":
                if not self.signed:
                    raise ValueError("setg reads undefined signed flags")
                less = self.load("i1", "signed_less")
                value = self.value(f"or i1 {less}, {value}")
            if op in {"setbe", "seta"}:
                if not self.carry:
                    raise ValueError("setbe reads undefined carry")
                carry = self.load("i1", "cf")
                value = self.value(f"or i1 {carry}, {value}")
            if op in {"setne", "seta", "setg"}:
                value = self.value(f"xor i1 {value}, true")
            self.write(ins, args[0], self.value(f"zext i1 {value} to i8"))
        elif op in {"sets", "setns"} and self.signed:
            value = self.load("i1", "sf")
            if op == "setns":
                value = self.value(f"xor i1 {value}, true")
            self.write(ins, args[0], self.value(f"zext i1 {value} to i8"))
        elif op in {"nop", "fninit", "cld"}:
            pass
        else:
            raise ValueError("unsupported console instruction")
        self.jump(following, returns)

    def emit_console(self, entry, base, code, data):
        descriptors = []
        for index, (rva, blob, size, writable) in enumerate(data):
            symbol = f"@guest_section_{index}"
            if blob:
                contents = "".join(f"\\{byte:02x}" for byte in blob)
                self.line(f'{symbol} = private constant [{len(blob)} x i8] c"{contents}"')
            pointer = symbol if blob else "null"
            descriptors.append(f"{{ i64, i64, i64, ptr, i64 }} "
                               f"{{ i64 {rva}, i64 {size}, i64 {len(blob)}, "
                               f"ptr {pointer}, i64 {int(writable)} }}")
        count = len(descriptors)
        kind = f"[{count} x {{ i64, i64, i64, ptr, i64 }}]"
        self.line(f"@guest_sections = constant {kind} [{', '.join(descriptors)}]")
        self.line(f"@guest_section_count = constant i64 {count}")
        self.line(f"@guest_image_base = constant i64 {self.image_base}")
        self.line("declare void @guest_set_pc(i64)")
        self.line("declare i64 @guest_load_library_a(i64)")
        self.line("declare i64 @guest_system_directory(i64, i32, i32)")
        self.line("declare i64 @guest_exception_filter(i64)")
        self.line("declare i64 @guest_environment()")
        self.line("declare i64 @guest_convert_text(i32, i32, i32, i64, i32, i64, i64)")
        self.line("declare i64 @guest_module_handle_ex(i32, i64, i64)")
        self.line("declare i64 @guest_module_handle(i64, i32)")
        self.line("declare i64 @guest_module_filename(i64, i64, i32)")
        self.line("declare i64 @guest_command_line(i32)")
        self.line("declare i64 @guest_file_type(i64)")
        self.line("declare void @guest_startup_info(i64)")
        self.line("declare void @guest_critical_section(i64, i32)")
        self.line("declare void @guest_init_critical(i64, i32)")
        self.line("declare i64 @guest_virtual_protect(i64, i64, i32, i64)")
        self.line("declare ptr @guest_pointer(i64, i32)")
        self.line("declare i64 @guest_acrt_iob_func(i32)")
        self.line("declare i64 @guest_errno()")
        self.line("declare i64 @guest_fwrite(i64, i64, i64, i64)")
        self.line("declare i64 @guest_fputs(i64, i64)")
        self.line("declare i64 @guest_fflush(i64)")
        self.line("declare i64 @guest_fputc(i32, i64)")
        self.line("declare i64 @guest_putchar(i32)")
        self.line("declare i64 @guest_puts(i64)")
        self.line("declare i64 @guest_setvbuf(i64, i64, i32, i64)")
        self.line("declare i64 @guest_add_vectored_exception_handler(i32, i64)")
        self.line("declare i64 @guest_remove_vectored_exception_handler(i64)")
        self.line("declare i64 @guest_message_box_a(i64, i64, i64, i32)")
        self.line("declare i64 @guest_message_box_w(i64, i64, i64, i32)")
        self.line("declare i64 @guest_crt_atexit(i64)")
        self.line("declare i64 @guest_register_onexit(i64, i64)")
        self.line("declare i64 @guest_init_onexit(i64)")
        self.line("declare i64 @guest_exec_onexit(i64)")
        self.line("declare i64 @guest_initterm(i64, i64)")
        self.line("declare i64 @guest_initterm_e(i64, i64)")
        self.line("declare i64 @guest_configure_argv(i32)")
        self.line("declare i64 @guest_init_env()")
        self.line("declare i64 @guest_get_initial_env()")
        self.line("declare i64 @guest_set_app_type(i32)")
        self.line("declare i64 @guest_seh_filter_exe(i32, i64)")
        self.line("declare i64 @guest_set_invalid_param(i64)")
        self.line("declare i64 @guest_p_argc()")
        self.line("declare i64 @guest_p_wargv()")
        self.line("declare i64 @guest_p_argv()")
        self.line("declare i64 @guest_p_fmode()")
        self.line("declare i64 @guest_p_commode()")
        self.line("declare i64 @guest_cexit()")
        self.line("declare i64 @guest_set_thread_stack_guarantee(i64)")
        self.line("declare i64 @guest_heap_realloc(i64, i32, i64, i64)")
        self.line("declare i64 @guest_heap_alloc(i64, i32, i64)")
        self.line("declare i64 @guest_heap_free(i64, i32, i64)")
        self.line("declare i64 @guest_load_library(i64, i64, i32)")
        self.line("declare i64 @guest_get_proc(i64, i64)")
        self.line("declare i64 @guest_indirect_call(i64, i64, i64, i64, i64)")
        self.line("declare i64 @guest_free_library(i64)")
        self.line("declare void @guest_trap(ptr) noreturn")
        self.line("declare void @guest_check_xcr(i32, i64)")
        for width in (32, 64):
            for name in ("fshr", "fshl"):
                self.line(f"declare i{width} @llvm.{name}.i{width}(i{width}, i{width}, i{width})")
        self.line("declare i32 @guest_vector_mask(i64, i64)")
        self.line("declare i64 @guest_compare_words(i64, i64, i32)")
        self.line("declare i64 @guest_shuffle(i64, i64, i64, i32, i32, i32)")
        self.line("declare void @guest_div32(i64, i64, ptr, ptr)")
        self.line("declare void @guest_div(i64, i64, i64, ptr, ptr)")
        self.line("declare i64 @guest_fill(i64, i64, i64, i32)")
        self.line("declare i64 @guest_load(i64, i32)")
        self.line("declare void @guest_store(i64, i64, i32)")
        self.line("declare void @guest_check_return(i64, i64)")
        self.line("declare i64 @guest_identity(i32)")
        self.line("declare i64 @guest_performance_counter(i64)")
        self.line("declare void @guest_system_filetime(i64)")
        self.line("declare void @guest_set_last_error(i32)")
        self.line("declare i64 @guest_get_last_error()")
        self.line("declare i64 @guest_stdout(i32)")
        self.line("declare i64 @guest_write(i64, i64, i32, i64, i64)")
        self.shared = True
        self.functions = {}
        self.function_queue = []
        self.cpu_slots = (*VOLATILE, "rsp", *NONVOLATILE,
                          *(f"xmm{i}_{lane}" for i in range(16) for lane in range(2)),
                          "zf", "cf", "signed_less", "of", "sf")
        self.runtime_functions = {
            row.struct.BeginAddress: row.struct.EndAddress
            for row in self.image_exception_entries
        }
        code_sec = self.image.get_section_by_rva(entry)
        if code_sec:
            for row in self.image_exception_entries:
                rva = row.struct.BeginAddress
                if not code_sec.contains_rva(rva):
                    continue
                unwind = self.image.get_data(row.struct.UnwindData, 1)
                if unwind and ((unwind[0] >> 3) & 4):
                    continue
                self.function(rva)
            for rva in relocated_code_pointers(self.image):
                if code_sec.contains_rva(rva):
                    self.function(rva)
            for rva in self.tls_callbacks:
                if code_sec.contains_rva(rva):
                    self.function(rva)
        self.line("declare void @guest_exit(i32) noreturn")
        self.line("declare void @guest_require_register(i8, i8)")
        self.line("define i32 @lifted_console() {")
        self.line("entry:")
        count = len(self.cpu_slots)
        self.line(f"  %cpu = alloca [{count * 2} x i64], align 8")
        self.line(f"  store [{count * 2} x i64] zeroinitializer, ptr %cpu, align 8")
        self.cpu_pointers()
        for name in NONVOLATILE:
            self.write_reg(name, 64, "0")
        for index in range(6, 16):
            self.line(f"  store i8 128, ptr %xmm{index}_0_width")
        initial = 0x2000000 + 1048576 - 40
        self.write_reg("rsp", 64, str(initial))
        for cb in self.tls_callbacks:
            self.write_reg("rcx", 64, str(self.image_base))
            self.write_reg("rdx", 64, "1")
            self.write_reg("r8", 64, "0")
            self.write_reg("r9", 64, "0")
            self.write_reg("rsp", 64, str(initial))
            self.line(f"  call void @guest_store(i64 {initial}, i64 0, i32 8)")
            self.line(f"  call void @{self.function(cb)}(ptr %cpu, i64 0)")
        self.write_reg("rsp", 64, str(initial))
        self.line(f"  call void @guest_store(i64 {initial}, i64 0, i32 8)")
        self.line(f"  call void @{self.function(entry)}(ptr %cpu, i64 0)")
        result = self.value("load i64, ptr %rax")
        result = self.value(f"trunc i64 {result} to i32")
        self.line(f"  ret i32 {result}")
        self.line("}")
        while self.function_queue:
            target = self.function_queue.pop()
            self.current = target
            self.blocks, self.pending = {}, []
            self.zero = self.carry = self.signed = self.overflow = False
            self.defined = {}
            self.line(f"define internal void @{self.functions[target]}(ptr %cpu, i64 %return_va) {{")
            self.line("entry:")
            self.cpu_pointers()
            self.emit_body(target, base, code, finalize=False)
        return self.finish_module()

    def cpu_pointers(self):
        count = len(self.cpu_slots)
        for i, name in enumerate(self.cpu_slots):
            self.line(f"  %{name} = getelementptr i64, ptr %cpu, i32 {i}")
        for i, name in enumerate(self.cpu_slots):
            self.line(f"  %{name}_width = getelementptr i64, ptr %cpu, i32 {count + i}")

    def function(self, target):
        if target not in self.functions:
            self.functions[target] = f"guest_fn_{target:x}"
            self.function_queue.append(target)
        return self.functions[target]

    def emit_body(self, entry, base, code, *, finalize=True):
        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        decoder.detail = True
        self.jump(entry, ())
        while self.pending:
            state = self.pending.pop()
            address, returns, defined, self.zero, self.carry, self.signed, self.overflow = state
            self.defined = dict(defined)
            self.line(f"{self.blocks[state]}:")
            ins = self.decoded.get(address)
            if ins is None:
                offset = address - base
                if not 0 <= offset < len(code):
                    raise ValueError(f"console target outside entry section at RVA {address:#x}")
                ins = next(decoder.disasm(code[offset:offset + 15], address, count=1), None)
                if ins is None:
                    raise ValueError(f"cannot decode console target RVA {address:#x}")
                for byte in range(address, address + ins.size):
                    if self.occupied.setdefault(byte, address) != address:
                        raise ValueError(f"overlapping console instructions at RVA {address:#x}")
                self.decoded[address] = ins
            if self.trace:
                self.line(f"  call void @guest_set_pc(i64 {address})")
            checkpoint = len(self.lines)
            try:
                self.step(ins, returns)
            except ValueError as error:
                message = f"RVA {ins.address:#x} ({ins.mnemonic} {ins.op_str}): {error}"
                if not self.trace:
                    raise ValueError(message) from error
                del self.lines[checkpoint:]
                self.trap(message)
        self.line("}")
        if finalize:
            return self.finish_module()

    def finish_module(self):
        self.line("declare i64 @guest_indirect_dispatch(ptr, i64, i64, i32)")
        entries = sorted(self.functions.keys())
        table_kind = f"[{len(entries)} x {{ i64, ptr }}]"
        table_items = [f"{{ i64, ptr }} {{ i64 {addr}, ptr @{self.functions[addr]} }}" for addr in entries]
        self.line(f"@guest_dispatch_table = constant {table_kind} [{', '.join(table_items)}]")
        self.line(f"@guest_dispatch_count = constant i64 {len(entries)}")
        for message, symbol in self.traps.items():
            data = message.encode() + b"\0"
            content = "".join(f"\\{byte:02x}" for byte in data)
            self.line(f'{symbol} = private constant [{len(data)} x i8] c"{content}"')
        return "\n".join(self.lines) + "\n"


def loader_requirements(image):
    return []


def read_console_image(image):
    entry, base, code = read_image_entry(image)
    header_size = image.OPTIONAL_HEADER.SizeOfHeaders
    data = [(0, image.__data__[:header_size], header_size, False)] if header_size else []
    for section in image.sections:
        flags = section.Characteristics
        size = section.Misc_VirtualSize
        if not size or not flags & 0x40000000:
            continue
        writable = bool(flags & 0x80000000)
        start = section.VirtualAddress
        if start < 0x2103000 and start + size > 0x2000000:
            raise ValueError("image data overlaps the guest stack address range")
        if start + size > image.OPTIONAL_HEADER.SizeOfImage:
            raise ValueError("section exceeds declared image size")
        blob = section.get_data()[:min(size, section.SizeOfRawData)] if section.PointerToRawData else b""
        data.append((start, blob, size, writable))
    if sum(size for _, _, size, _ in data) > 16 * 1024 * 1024:
        raise ValueError("guest data exceeds 16 MiB")
    ordered = sorted(data)
    if any(a[0] + a[2] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("overlapping guest data sections")
    # Guest pointers use RVAs. Normalize loader-relocated data pointers to
    # that address space while preserving the original bytes for the x86 oracle.
    buffers = [bytearray(blob.ljust(size, b"\0")) for _, blob, size, _ in ordered]
    touched = set()
    for block in getattr(image, "DIRECTORY_ENTRY_BASERELOC", ()):
        for fixup in block.entries:
            if fixup.type == 0:
                continue
            if fixup.type != 10:
                raise ValueError(f"unsupported base relocation type {fixup.type}")
            for index, (start, _, size, _) in enumerate(ordered):
                offset = fixup.rva - start
                if 0 <= offset <= size - 8:
                    raw = int.from_bytes(buffers[index][offset:offset + 8], "little")
                    pointer = raw - image.OPTIONAL_HEADER.ImageBase
                    if not 0 <= pointer < image.OPTIONAL_HEADER.SizeOfImage:
                        raise ValueError(f"relocation points outside image at RVA {fixup.rva:#x}")
                    buffers[index][offset:offset + 8] = pointer.to_bytes(8, "little")
                    touched.add(index)
                    break
            else:
                raise ValueError(f"relocation outside mapped data at RVA {fixup.rva:#x}")
    mapped = [(start, bytes(buffers[i]).rstrip(b"\0") if i in touched else blob, size, writable)
              for i, (start, blob, size, writable) in enumerate(ordered)]
    return entry, base, code, mapped


def relocated_code_pointers(image):
    """Read candidate RVAs from relocated, read-only PE data."""
    base = image.OPTIONAL_HEADER.ImageBase
    code = image.get_section_by_rva(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    candidates = set()
    for block in getattr(image, "DIRECTORY_ENTRY_BASERELOC", ()):
        for fixup in block.entries:
            if fixup.type != 10:
                continue
            section = image.get_section_by_rva(fixup.rva)
            if section is None or section.Name.rstrip(b"\0") != b".rdata":
                continue
            pointer = image.get_qword_at_rva(fixup.rva)
            if pointer is not None and code and code.contains_rva(pointer - base):
                candidates.add(pointer - base)
    return candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--trace", action="store_true", help="trap unsupported instructions at runtime")
    args = parser.parse_args()
    try:
        image = pefile.PE(str(args.pe))
        entry, base, code, data = read_console_image(image)
        requirements = loader_requirements(image)
        if requirements:
            raise ValueError(f"unsupported Windows loader requirements: {', '.join(requirements)}")
        ir = ConsoleLift(image, trace=args.trace).emit_console(entry, base, code, data)
        args.output.write_text(ir)
    except (ValueError, pefile.PEFormatError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
