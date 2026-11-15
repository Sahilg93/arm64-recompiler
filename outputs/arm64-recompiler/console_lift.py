"""Lift a restricted Windows console entry subset to native LLVM IR."""

import argparse
import json
from pathlib import Path
import re
import struct

import capstone as cs
from capstone import x86_const as x
import pefile

from lift import Lift, read_image_entry

try:
    from generated_shims import GENERATED_SHIMS, FLOAT_1ARG_SHIMS, FLOAT_2ARG_SHIMS
except ImportError:
    GENERATED_SHIMS = []
    FLOAT_1ARG_SHIMS = []
    FLOAT_2ARG_SHIMS = []

WINE_DB = {}
wine_db_path = Path(__file__).parent / "wine_api_db.json"
if wine_db_path.exists():
    try:
        with open(wine_db_path) as f:
            WINE_DB = json.load(f).get("api_to_dll", {})
    except Exception:
        pass

MAX_BLOCKS = 60000

FLS_IMPORTS = {"FlsAlloc": 0x7fff1002, "FlsGetValue": 0x7fff1003, "FlsGetValue2": 0x7fff1003, "FlsSetValue": 0x7fff1004, "FlsFree": 0x7fff1005, "TlsAlloc": 0x7fff1031, "TlsGetValue": 0x7fff1003, "TlsSetValue": 0x7fff1004, "TlsFree": 0x7fff1005}
IDENTITY_IMPORTS = {"GetCurrentProcessId": 0, "GetCurrentThreadId": 1}
IMPORTS = {"GetStdHandle", "WriteFile", "NtReadFile", "ExitProcess", "SetLastError", "GetLastError", "GetSystemTimeAsFileTime", "QueryPerformanceCounter", "LoadLibraryW", "LoadLibraryExW", "GetProcAddress", "FreeLibrary", "GetProcessHeap", "HeapAlloc", "HeapFree", "HeapReAlloc", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection", "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx", "VirtualProtect", "GetStartupInfoW", "GetFileType", "GetCommandLineA", "GetCommandLineW", "GetACP", "GetOEMCP", "IsValidCodePage", "GetModuleFileNameW", "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExW", "WideCharToMultiByte", "MultiByteToWideChar", "InitializeSListHead", "GetEnvironmentStringsW", "FreeEnvironmentStringsW", "SetUnhandledExceptionFilter", "GetSystemDirectoryA", "GetSystemDirectoryW", "LoadLibraryA", "__acrt_iob_func", "fwrite", "fputs", "fflush", "_errno", "fputc", "putchar", "puts", "setvbuf", "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler", "MessageBoxA", "MessageBoxW", "_crt_atexit", "_register_onexit_function", "_initialize_onexit_table", "_execute_onexit_table", "_initterm", "_initterm_e", "_configure_wide_argv", "_configure_narrow_argv", "_initialize_wide_environment", "_initialize_narrow_environment", "_get_initial_wide_environment", "_get_initial_narrow_environment", "_set_app_type", "_seh_filter_exe", "_set_invalid_parameter_handler", "__p___argc", "__p___wargv", "__p___argv", "exit", "_exit", "_cexit", "SetThreadStackGuarantee", "malloc", "free", "calloc", "realloc", "GetCurrentThread", "GetCurrentProcess", "__p__fmode", "__p__commode", "__p__wenviron", "__p__environ", "getenv", "_set_new_mode", "wcslen", "wcsnlen", "strlen", "strnlen", "memset", "memcpy", "memmove", "strcmp", "strncmp", "strcpy", "_strdup", "isalnum", "isalpha", "isspace", "ProcessPrng", "GetHandleInformation", "GetTickCount64", "GetTickCount", "GetSystemTimePreciseAsFileTime", "QueryPerformanceFrequency", "IsProcessorFeaturePresent", "UnhandledExceptionFilter", "TerminateProcess", "RtlCaptureContext", "RaiseException", "RtlLookupFunctionEntry", "RtlUnwindEx", "RtlVirtualUnwind", "IsDebuggerPresent", "CreateThread", "GetFinalPathNameByHandleW", "WaitOnAddress", "WakeByAddressSingle", "WakeByAddressAll", "CreateWaitableTimerExW", "CreateWaitableTimerW", "SetWaitableTimer"} | IDENTITY_IMPORTS.keys() | FLS_IMPORTS.keys() | set(GENERATED_SHIMS)
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
    def __init__(self, image, *, trace=False, callback_targets=None, stub_unknown=True, modules=False,
                 fault_delivery=False, tolerant=False, bound_dlls=None, overrides=None):
        super().__init__()
        # RVA -> runtime function name: the lifted body becomes a call to the
        # runtime's named implementation (None: return TRUE). Used for system
        # DLLs whose syscalls and process-global state the runtime owns.
        self.overrides = dict(overrides or {})
        self.override_caches = []
        self.trace = trace
        # Tolerant lifting turns undecodable or unsupported instructions into
        # runtime traps (like trace mode) without per-instruction PC updates.
        self.tolerant = tolerant or trace
        # Lowercase import DLL names whose IAT slots the runtime loader binds to
        # lifted guest modules. Calls through those slots dispatch to the bound
        # value; other imports use the runtime's named shims.
        self.bound_dlls = None if bound_dlls is None else {name.lower() for name in bound_dlls}
        self.fault_delivery = fault_delivery
        self.resume_sites = set()
        self.stub_unknown = stub_unknown
        self.strings = {}
        self.shared = False
        self.module_base = 0
        self.modules = modules
        self.image = image
        self.image_exception_entries = getattr(image, "DIRECTORY_ENTRY_EXCEPTION", ())
        self.runtime_functions = {
            row.struct.BeginAddress: row.struct.EndAddress
            for row in self.image_exception_entries
        }
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
        self.foreign_iat = {
            item.address - self.image_base
            for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ())
            if (dll.dll.decode("ascii", "replace").lower() in self.bound_dlls
                if self.bound_dlls is not None else dll.dll.lower() != b"kernel32.dll")
            for item in dll.imports
        }
        self.bound_slots = sorted(self.foreign_iat) if self.bound_dlls else []
        self.iat_thunks = {}
        self.foreign_thunks = {}
        for dll in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
            for item in dll.imports:
                if item.name:
                    rva = item.address - self.image_base
                    raw_val = image.get_qword_at_rva(rva)
                    if raw_val and raw_val < image.OPTIONAL_HEADER.SizeOfImage:
                        self.iat_thunks[raw_val] = item.name.decode("ascii", "replace")
                        if rva in self.foreign_iat:
                            self.foreign_thunks[raw_val] = rva
        if callback_targets is None:
            self.callback_targets = find_switch_tables(image)
        else:
            self.callback_targets = callback_targets
        tls = getattr(image, "DIRECTORY_ENTRY_TLS", None)
        self.tls_callbacks = []
        if tls and tls.struct:
            self.tls_start = getattr(tls.struct, "StartAddressOfRawData", 0)
            self.tls_end = getattr(tls.struct, "EndAddressOfRawData", 0)
            self.tls_index_va = getattr(tls.struct, "AddressOfIndex", 0)
            self.tls_zero_fill = getattr(tls.struct, "SizeOfZeroFill", 0)
            if tls.struct.AddressOfCallBacks:
                cb_rva = tls.struct.AddressOfCallBacks - self.image_base
                for idx in range(256):
                    va = image.get_qword_at_rva(cb_rva + idx * 8)
                    if va is None or va == 0:
                        break
                    rva = va - self.image_base if va >= self.image_base else va
                    self.tls_callbacks.append(rva)
        else:
            self.tls_start = 0
            self.tls_end = 0
            self.tls_index_va = 0
            self.tls_zero_fill = 0
        self.defined = dict.fromkeys(("rsp", *NONVOLATILE), 64)
        self.zero = False
        self.carry = False
        self.signed = False
        self.overflow = False
        self.blocks = {}
        self.pending = []
        self.decoded = {}
        self.occupied = {}

    def string_constant(self, text: str) -> str:
        if text not in self.strings:
            var_name = f".str_{len(self.strings)}_{''.join(c if c.isalnum() else '_' for c in text[:16])}"
            encoded = text.encode("utf-8") + b"\0"
            escaped = "".join(f"\\{b:02x}" if b < 32 or b >= 127 or b in (b'"'[0], b'\\'[0]) else chr(b) for b in encoded)
            self.strings[text] = (var_name, len(encoded), escaped)
        return self.strings[text][0]

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
            return str(ins.address + ins.size + mem.disp + self.module_base)
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
            name = ins.reg_name(operand.reg)
            if name in {"ah", "bh", "ch", "dh"} and width == 8:
                reg_name = f"r{name[0]}x"
                wide_val = self.value(f"zext i8 {value} to i64")
                shifted = self.value(f"shl i64 {wide_val}, 8")
                old = self.load("i64", reg_name)
                cleared = self.value(f"and i64 {old}, -65281")
                new_val = self.value(f"or i64 {cleared}, {shifted}")
                self.store("i64", new_val, reg_name)
                return
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
        slot = int(self.address(ins, operand)) - self.module_base
        name = self.imports.get(slot)
        if name not in IMPORTS:
            raw_val = self.image.get_qword_at_rva(slot) if slot < self.image.OPTIONAL_HEADER.SizeOfImage else 0
            call_target = raw_val if (raw_val and raw_val < self.image.OPTIONAL_HEADER.SizeOfImage) else slot
            if name in {"RegOpenKeyExW", "RegQueryValueExW"}:
                self.guarded_call(ins, str(call_target + self.module_base), ins.address + ins.size, (), tail=tail)
                return True
            self.dynamic_call(str(call_target + self.module_base))
            return False
        elif name == "ExitProcess":
            status = self.read_reg("rcx", 32)
            self.line(f"  call void @guest_exit(i32 {status})")
            self.line("  unreachable")
            return True
        elif name in FLS_IMPORTS:
            self.dynamic_call(str(FLS_IMPORTS[name]))
            return False
        elif name == "CreateThread":
            attrs, size, start, argument = (self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9"))
            rsp = self.read_reg("rsp", 64)
            flags_ptr = self.value(f"add i64 {rsp}, {40 if tail else 32}")
            id_ptr = self.value(f"add i64 {rsp}, {48 if tail else 40}")
            flags = self.value(f"call i64 @guest_load(i64 {flags_ptr}, i32 4)")
            flags = self.value(f"trunc i64 {flags} to i32")
            thread_id = self.value(f"call i64 @guest_load(i64 {id_ptr}, i32 8)")
            result = self.value(f"call i64 @guest_create_thread(i64 {attrs}, i64 {size}, i64 {start}, i64 {argument}, i32 {flags}, i64 {thread_id})")
        elif name == "GetFinalPathNameByHandleW":
            handle, buf, cch, flags = (self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9"))
            cch_32 = self.value(f"trunc i64 {cch} to i32")
            flags_32 = self.value(f"trunc i64 {flags} to i32")
            result = self.value(f"call i64 @guest_GetFinalPathNameByHandleW(i64 {handle}, i64 {buf}, i32 {cch_32}, i32 {flags_32})")
        elif name == "WaitOnAddress":
            addr, cmp_addr, size, ms = (self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9"))
            ms_32 = self.value(f"trunc i64 {ms} to i32")
            result = self.value(f"call i64 @guest_WaitOnAddress(i64 {addr}, i64 {cmp_addr}, i64 {size}, i32 {ms_32})")
        elif name == "WakeByAddressSingle":
            addr = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_WakeByAddressSingle(i64 {addr})")
        elif name == "WakeByAddressAll":
            addr = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_WakeByAddressAll(i64 {addr})")
        elif name == "CreateWaitableTimerExW":
            attrs, name_ptr, flags, access = (self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9"))
            flags_32 = self.value(f"trunc i64 {flags} to i32")
            access_32 = self.value(f"trunc i64 {access} to i32")
            result = self.value(f"call i64 @guest_CreateWaitableTimerExW(i64 {attrs}, i64 {name_ptr}, i32 {flags_32}, i32 {access_32})")
        elif name == "CreateWaitableTimerW":
            attrs, name_ptr, manual = (self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8"))
            manual_32 = self.value(f"trunc i64 {manual} to i32")
            result = self.value(f"call i64 @guest_CreateWaitableTimerW(i64 {attrs}, i64 {name_ptr}, i32 {manual_32})")
        elif name == "SetWaitableTimer":
            timer, due_time, period, routine = (self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9"))
            period_32 = self.value(f"trunc i64 {period} to i32")
            result = self.value(f"call i64 @guest_SetWaitableTimer(i64 {timer}, i64 {due_time}, i32 {period_32}, i64 {routine})")
        elif name == "LoadLibraryA":
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
        elif name == "__p__wenviron":
            result = self.value("call i64 @guest_p_wenviron()")
        elif name == "__p__environ":
            result = self.value("call i64 @guest_p_environ()")
        elif name == "getenv":
            s = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_getenv(i64 {s})")
        elif name == "_set_new_mode":
            mode = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_set_new_mode(i32 {mode})")
        elif name == "wcslen":
            s = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_wcslen(i64 {s})")
        elif name == "wcsnlen":
            s = self.read_reg("rcx", 64)
            n = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_wcsnlen(i64 {s}, i64 {n})")
        elif name == "strlen":
            s = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_strlen(i64 {s})")
        elif name == "strnlen":
            s = self.read_reg("rcx", 64)
            n = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_strnlen(i64 {s}, i64 {n})")
        elif name == "memset":
            d = self.read_reg("rcx", 64)
            c = self.read_reg("rdx", 32)
            n = self.read_reg("r8", 64)
            result = self.value(f"call i64 @guest_memset(i64 {d}, i32 {c}, i64 {n})")
        elif name in {"memcpy", "memmove"}:
            d = self.read_reg("rcx", 64)
            s = self.read_reg("rdx", 64)
            n = self.read_reg("r8", 64)
            result = self.value(f"call i64 @guest_memcpy(i64 {d}, i64 {s}, i64 {n})")
        elif name == "strcmp":
            s1 = self.read_reg("rcx", 64)
            s2 = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_strcmp(i64 {s1}, i64 {s2})")
        elif name == "strncmp":
            s1 = self.read_reg("rcx", 64)
            s2 = self.read_reg("rdx", 64)
            n = self.read_reg("r8", 64)
            result = self.value(f"call i64 @guest_strncmp(i64 {s1}, i64 {s2}, i64 {n})")
        elif name == "strcpy":
            d = self.read_reg("rcx", 64)
            s = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_strcpy(i64 {d}, i64 {s})")
        elif name == "_strdup":
            s = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_strdup(i64 {s})")
        elif name == "isalnum":
            c = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_isalnum(i32 {c})")
        elif name == "isalpha":
            c = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_isalpha(i32 {c})")
        elif name == "isspace":
            c = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_isspace(i32 {c})")
        elif name == "ProcessPrng":
            buf = self.read_reg("rcx", 64)
            sz = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_process_prng(i64 {buf}, i64 {sz})")
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
        elif name in {"LoadLibraryW", "LoadLibraryExW", "GetProcAddress", "FreeLibrary"}:
            first = self.read_reg("rcx", 64)
            if name in {"LoadLibraryW", "LoadLibraryExW"}:
                reserved = self.read_reg("rdx", 64) if name == "LoadLibraryExW" else "0"
                flags = self.read_reg("r8", 32) if name == "LoadLibraryExW" else "0"
                result = self.value(f"call i64 @guest_load_library(i64 {first}, i64 {reserved}, i32 {flags})")
            elif name == "GetProcAddress":
                symbol = self.read_reg("rdx", 64)
                result = self.value(f"call i64 @guest_get_proc(i64 {first}, i64 {symbol})")
            else:
                result = self.value(f"call i64 @guest_free_library(i64 {first})")
        elif name in {"GetSystemTimeAsFileTime", "GetSystemTimePreciseAsFileTime"}:
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
        elif name == "GetHandleInformation":
            handle = self.read_reg("rcx", 64)
            flags = self.read_reg("rdx", 64)
            result = self.value(f"call i64 @guest_get_handle_info(i64 {handle}, i64 {flags})")
        elif name == "GetTickCount64":
            result = self.value("call i64 @guest_tick_count_64()")
        elif name == "GetTickCount":
            result = self.value("call i64 @guest_tick_count()")
        elif name == "QueryPerformanceFrequency":
            address = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_performance_frequency(i64 {address})")
        elif name == "IsProcessorFeaturePresent":
            feature = self.read_reg("rcx", 32)
            result = self.value(f"call i64 @guest_is_processor_feature_present(i32 {feature})")
        elif name == "UnhandledExceptionFilter":
            info = self.read_reg("rcx", 64)
            result = self.value(f"call i64 @guest_unhandled_exception_filter(i64 {info})")
        elif name == "TerminateProcess":
            h = self.read_reg("rcx", 64)
            code = self.read_reg("rdx", 32)
            result = self.value(f"call i64 @guest_terminate_process(i64 {h}, i32 {code})")
        elif name == "RaiseException":
            code, flags, count = (self.read_reg(reg, 32) for reg in ("rcx", "rdx", "r8"))
            arguments = self.read_reg("r9", 64)
            rsp = self.read_reg("rsp", 64)
            if tail:
                pc = self.value(f"call i64 @guest_load(i64 {rsp}, i32 8)")
                rsp = self.value(f"add i64 {rsp}, 8")
            else:
                pc = self.image_base + ins.address + ins.size
            self.line(f"  call void @guest_raise_exception(i32 {code}, i32 {flags}, i32 {count}, i64 {arguments}, i64 {pc}, i64 {rsp})")
            result = None
        elif name == "RtlCaptureContext":
            ctx = self.read_reg("rcx", 64)
            self.line(f"  call void @guest_rtl_capture_context(i64 {ctx})")
            result = None
        elif name == "RtlLookupFunctionEntry":
            pc = self.read_reg("rcx", 64)
            base = self.read_reg("rdx", 64)
            hist = self.read_reg("r8", 64)
            result = self.value(f"call i64 @guest_rtl_lookup_function_entry(i64 {pc}, i64 {base}, i64 {hist})")
        elif name == "RtlUnwindEx":
            arguments = [self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9")]
            rsp = self.read_reg("rsp", 64)
            for offset in (40, 48) if tail else (32, 40):
                slot = self.value(f"add i64 {rsp}, {offset}")
                arguments.append(self.value(f"call i64 @guest_load(i64 {slot}, i32 8)"))
            pc = self.image_base + ins.address + ins.size
            if tail:
                pc = self.value(f"call i64 @guest_load(i64 {rsp}, i32 8)")
                rsp = self.value(f"add i64 {rsp}, 8")
            operands = ", ".join(f"i64 {value}" for value in (*arguments, pc, rsp))
            self.line(f"  call void @guest_rtl_unwind_ex({operands})")
            self.line("  unreachable")
            return True
        elif name == "RtlVirtualUnwind":
            registers = [self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9")]
            kind = self.value(f"trunc i64 {registers[0]} to i32")
            rsp = self.read_reg("rsp", 64)
            arguments = [f"i32 {kind}", *(f"i64 {value}" for value in registers[1:])]
            for offset in range(40 if tail else 32, 72 if tail else 64, 8):
                slot = self.value(f"add i64 {rsp}, {offset}")
                value = self.value(f"call i64 @guest_load(i64 {slot}, i32 8)")
                arguments.append(f"i64 {value}")
            result = self.value(f"call i64 @guest_rtl_virtual_unwind({', '.join(arguments)})")
        elif name == "IsDebuggerPresent":
            result = self.value("add i64 0, 0")
        elif name in {"CreateFileMappingW", "MapViewOfFile"}:
            registers = [self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9")]
            rsp = self.read_reg("rsp", 64)
            offset = 40 if tail else 32
            slot = self.value(f"add i64 {rsp}, {offset}")
            stack = self.value(f"call i64 @guest_load(i64 {slot}, i32 8)")
            ints = (2, 3) if name == "CreateFileMappingW" else (1, 2, 3)
            arguments = []
            for index, value in enumerate(registers):
                if index in ints:
                    value = self.value(f"trunc i64 {value} to i32")
                arguments.append(f"i{32 if index in ints else 64} {value}")
            if name == "CreateFileMappingW":
                size = self.value(f"trunc i64 {stack} to i32")
                slot = self.value(f"add i64 {rsp}, {offset + 8}")
                label = self.value(f"call i64 @guest_load(i64 {slot}, i32 8)")
                arguments.extend((f"i32 {size}", f"i64 {label}"))
            else:
                arguments.append(f"i64 {stack}")
            result = self.value(f"call i64 @subsys_{name}({', '.join(arguments)})")
        elif name in FLOAT_1ARG_SHIMS:
            arg0 = self.load("i64", "xmm0_0")
            res_bits = self.value(f"call i64 @guest_{name}(i64 {arg0}, i64 0, i64 0, i64 0)")
            self.store("i64", res_bits, "xmm0_0")
            self.store("i64", "0", "xmm0_1")
            result = None
        elif name in FLOAT_2ARG_SHIMS:
            arg0 = self.load("i64", "xmm0_0")
            arg1 = self.load("i64", "xmm1_0")
            res_bits = self.value(f"call i64 @guest_{name}(i64 {arg0}, i64 {arg1}, i64 0, i64 0)")
            self.store("i64", res_bits, "xmm0_0")
            self.store("i64", "0", "xmm0_1")
            result = None
        elif name in {"CreateFileW", "CreateFileA"}:
            # Seven arguments: creation disposition, flags, and template are on the stack.
            registers = [self.read_reg("rcx", 64), self.read_reg("rdx", 32),
                         self.read_reg("r8", 32), self.read_reg("r9", 64)]
            stack = self.read_reg("rsp", 64)
            offset = 40 if tail else 32
            slots = [self.value(f"add i64 {stack}, {offset + i * 8}") for i in range(3)]
            creation, flags, template = (self.value(f"call i64 @guest_load(i64 {slot}, i32 {width})")
                                         for slot, width in zip(slots, (4, 4, 8)))
            creation, flags = (self.value(f"trunc i64 {value} to i32") for value in (creation, flags))
            result = self.value(
                f"call i64 @subsys_{name}(i64 {registers[0]}, i32 {registers[1]}, i32 {registers[2]}, "
                f"i64 {registers[3]}, i32 {creation}, i32 {flags}, i64 {template})")
        elif name in GENERATED_SHIMS:
            arg0 = self.read_reg("rcx", 64)
            arg1 = self.read_reg("rdx", 64)
            arg2 = self.read_reg("r8", 64)
            arg3 = self.read_reg("r9", 64)
            result = self.value(f"call i64 @guest_{name}(i64 {arg0}, i64 {arg1}, i64 {arg2}, i64 {arg3})")
        elif name == "NtReadFile":
            rsp = self.read_reg("rsp", 64)
            stack_args = self.value(f"add i64 {rsp}, {40 if tail else 32}")
            registers = [self.read_reg(reg, 64) for reg in ("rcx", "rdx", "r8", "r9")]
            args = ", ".join(f"i64 {value}" for value in (*registers, stack_args))
            result = self.value(f"call i64 @guest_nt_read_file({args})")
        elif name == "WriteFile":
            handle = self.read_reg("rcx", 64)
            buffer = self.read_reg("rdx", 64)
            size = self.read_reg("r8", 32)
            written = self.read_reg("r9", 64)
            stack = self.read_reg("rsp", 64)
            slot = self.value(f"add i64 {stack}, {40 if tail else 32}")
            overlapped = self.value(f"call i64 @guest_load(i64 {slot}, i32 8)")
            result = self.value(f"call i64 @guest_write(i64 {handle}, i64 {buffer}, "
                                f"i32 {size}, i64 {written}, i64 {overlapped})")
        else:
            raise ValueError(f"unhandled import call: {name}")
        is_float_ret = name in FLOAT_1ARG_SHIMS or name in FLOAT_2ARG_SHIMS
        for register in (*VOLATILE, *(f"xmm{i}" for i in range(6))):
            if is_float_ret and register == "xmm0":
                continue
            self.defined.pop(register, None)
            if self.shared:
                slot = f"{register}_0" if register.startswith("xmm") else register
                self.line(f"  store i8 0, ptr %{slot}_width")
        if is_float_ret:
            self.defined["xmm0"] = 128
            if self.shared:
                self.line("  store i8 128, ptr %xmm0_0_width")
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
        bound = self.runtime_functions.get(self.current) if self.shared else None
        if bound and not (self.current <= address < bound):
            if address in self.functions:
                self.line(f"  musttail call void @{self.function(address)}(ptr %cpu, i64 %return_va)")
                self.line("  ret void")
            else:
                self.return_to_caller(returns)
            return
        self.line(f"  br label {self.block(address, returns)}")

    def dynamic_call(self, target):
        values = [self.load("i64", name) if self.shared else
                  self.read_reg(name, 64) if self.defined.get(name) == 64 else "0"
                  for name in ("rcx", "rdx", "r8", "r9")]
        arguments = ", ".join(f"i64 {value}" for value in (target, *values))
        # No return address is pushed here (unlike IAT thunks): stack arguments
        # start at rsp+32. The _inline entry tells the runtime so.
        result = self.value(f"call i64 @guest_indirect_call_inline({arguments})")
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

    def bounded_switch_targets(self, jump):
        """Recognize a bounded, table-relative switch from decoded predecessors."""
        if jump.operands[0].type != x.X86_OP_REG:
            return ()
        preceding = []
        address = jump.address
        for _ in range(12):
            start = self.occupied.get(address - 1)
            instruction = self.decoded.get(start)
            if instruction is None or instruction.address + instruction.size != address:
                break
            preceding.insert(0, instruction)
            address = start
        if len(preceding) < 3:
            return ()
        lea, load, add = preceding[-3:]
        if [ins.mnemonic for ins in (lea, load, add)] != ["lea", "movsxd", "add"]:
            return ()
        l, read, a = (ins.operands for ins in (lea, load, add))
        if ([op.type for op in l] != [x.X86_OP_REG, x.X86_OP_MEM]
                or [op.type for op in read] != [x.X86_OP_REG, x.X86_OP_MEM]
                or [op.type for op in a] != [x.X86_OP_REG, x.X86_OP_REG]):
            return ()
        target = jump.operands[0].reg
        memory = read[1].mem
        if (read[0].reg != target or a[0].reg != target or a[1].reg != l[0].reg
                or l[1].mem.base != x.X86_REG_RIP or memory.segment
                or memory.base != l[0].reg or memory.scale != 4 or memory.disp
                or not memory.index):
            return ()

        count = None
        for guard in reversed(preceding[:-3]):
            if guard.mnemonic == "and" and len(guard.operands) == 2 and guard.operands[0].type == x.X86_OP_REG and guard.operands[1].type == x.X86_OP_IMM:
                count = guard.operands[1].imm + 1
                break
            elif guard.mnemonic == "cmp" and len(guard.operands) == 2 and guard.operands[0].type == x.X86_OP_REG and guard.operands[1].type == x.X86_OP_IMM:
                count = guard.operands[1].imm + 1
                break

        table = lea.address + lea.size + l[1].mem.disp
        section = self.image.get_section_by_rva(jump.address)
        bound = self.runtime_functions.get(self.current) if self.shared else None
        if count is None and not bound:
            return ()
        targets = set()
        limit = count if (count is not None and 1 <= count <= 4096) else 256
        for i in range(limit):
            data = self.image.get_data(table + i * 4, 4)
            if not data or len(data) < 4:
                break
            (offset,) = struct.unpack("<i", data)
            dest = table + offset
            if bound and not (self.current <= dest < bound):
                if count is not None:
                    return ()
                break
            if section and not section.contains_rva(dest):
                if count is not None:
                    return ()
                break
            targets.add(dest)
        return targets

    def guarded_call(self, ins, target, following, returns, *, tail=False):
        local_targets = () if ins.address in self.callback_targets else (self.bounded_switch_targets(ins) if tail else ())
        candidates = sorted(set(self.callback_targets.get(ins.address, ())) | set(local_targets))
        if candidates:
            self.counter += 1
            identifier = self.counter
            fallback = f"fallback{identifier}"
            self.line(f"  switch i64 {target}, label %{fallback} [")
            for address in candidates:
                self.line(f"    i64 {address + self.module_base}, label %callback{identifier}_{address:x}")
            self.line("  ]")
            initial = self.defined.copy()
            flags = self.zero, self.carry, self.signed, self.overflow
            bound = self.runtime_functions.get(self.current) if self.shared else None
            for address in candidates:
                self.line(f"callback{identifier}_{address:x}:")
                self.defined = initial.copy()
                self.zero, self.carry, self.signed, self.overflow = flags
                if tail and (address in local_targets or (bound and self.current <= address < bound)):
                    self.jump(address, returns)
                elif tail:
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
            guard = bytes.fromhex("4983f80f0f87")
            guarded = any(self.image.get_data(ins.address - offset, len(guard)) == guard
                          for offset in (27, 33))
            if (code.startswith(bytes.fromhex("478b8c82"))
                    and code[-6:] == bytes.fromhex("4d03ca41ffe1")
                    and guarded):
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
        args = ins.operands
        following = ins.address + ins.size
        if op.startswith("lock ") and op in {"lock inc", "lock dec", "lock add", "lock sub", "lock or", "lock and", "lock bts"} and args and args[0].type == x.X86_OP_MEM:
            width = args[0].size * 8
            addr = self.address(ins, args[0])
            ptr = self.value(f"call ptr @guest_pointer(i64 {addr}, i32 {width // 8})")
            if op == "lock inc":
                old = self.value(f"atomicrmw add ptr {ptr}, i{width} 1 seq_cst")
                val = self.value(f"add i{width} {old}, 1")
                zero = self.value(f"icmp eq i{width} {val}, 0")
                negative = self.value(f"icmp slt i{width} {val}, 0")
                boundary = (1 << (width - 1)) - 1
                overflow = self.value(f"icmp eq i{width} {old}, {boundary}")
                signed_less = self.value(f"xor i1 {negative}, {overflow}")
                self.store("i1", zero, "zf")
                self.store("i1", negative, "sf")
                self.store("i1", overflow, "of")
                self.store("i1", signed_less, "signed_less")
                self.zero = self.signed = self.overflow = True
            elif op == "lock dec":
                old = self.value(f"atomicrmw sub ptr {ptr}, i{width} 1 seq_cst")
                val = self.value(f"sub i{width} {old}, 1")
                zero = self.value(f"icmp eq i{width} {val}, 0")
                negative = self.value(f"icmp slt i{width} {val}, 0")
                boundary = 1 << (width - 1)
                overflow = self.value(f"icmp eq i{width} {old}, {boundary}")
                signed_less = self.value(f"xor i1 {negative}, {overflow}")
                self.store("i1", zero, "zf")
                self.store("i1", negative, "sf")
                self.store("i1", overflow, "of")
                self.store("i1", signed_less, "signed_less")
                self.zero = self.signed = self.overflow = True
            elif op == "lock add":
                operand = self.read(ins, args[1], width)
                old = self.value(f"atomicrmw add ptr {ptr}, i{width} {operand} seq_cst")
                val = self.value(f"add i{width} {old}, {operand}")
                zero = self.value(f"icmp eq i{width} {val}, 0")
                negative = self.value(f"icmp slt i{width} {val}, 0")
                left = self.value(f"xor i{width} {old}, {val}")
                right = self.value(f"xor i{width} {operand}, {val}")
                both = self.value(f"and i{width} {left}, {right}")
                overflow = self.value(f"icmp slt i{width} {both}, 0")
                signed_less = self.value(f"xor i1 {negative}, {overflow}")
                self.store("i1", zero, "zf")
                self.store("i1", negative, "sf")
                self.store("i1", overflow, "of")
                self.store("i1", signed_less, "signed_less")
                self.zero = self.signed = self.overflow = True
            elif op == "lock sub":
                operand = self.read(ins, args[1], width)
                old = self.value(f"atomicrmw sub ptr {ptr}, i{width} {operand} seq_cst")
                val = self.value(f"sub i{width} {old}, {operand}")
                zero = self.value(f"icmp eq i{width} {val}, 0")
                negative = self.value(f"icmp slt i{width} {val}, 0")
                signed_less = self.value(f"icmp slt i{width} {old}, {operand}")
                overflow = self.value(f"xor i1 {negative}, {signed_less}")
                self.store("i1", zero, "zf")
                self.store("i1", negative, "sf")
                self.store("i1", overflow, "of")
                self.store("i1", signed_less, "signed_less")
                self.zero = self.signed = self.overflow = True
            elif op in {"lock or", "lock and"}:
                operand = self.read(ins, args[1], width)
                fn = "or" if op == "lock or" else "and"
                old = self.value(f"atomicrmw {fn} ptr {ptr}, i{width} {operand} seq_cst")
                val = self.value(f"{fn} i{width} {old}, {operand}")
                zero = self.value(f"icmp eq i{width} {val}, 0")
                negative = self.value(f"icmp slt i{width} {val}, 0")
                self.store("i1", zero, "zf")
                self.store("i1", negative, "sf")
                self.store("i1", "false", "of")
                self.store("i1", negative, "signed_less")
                self.zero = self.signed = self.overflow = True
            elif op == "lock bts":
                index = self.read(ins, args[1], width)
                mask = self.value(f"shl i{width} 1, {index}")
                old = self.value(f"atomicrmw or ptr {ptr}, i{width} {mask} seq_cst")
                shifted = self.value(f"lshr i{width} {old}, {index}")
                self.store("i1", self.value(f"trunc i{width} {shifted} to i1"), "cf")
                self.carry = True
            self.jump(following, returns)
            return
        if op in {"lock inc", "lock dec", "lock or", "lock and", "lock cmpxchg", "lock add", "lock sub"}:
            op = op.removeprefix("lock ")
        if op == "ud2":
            self.trap(f"RVA {ins.address:#x}: ud2 instruction")
            return
        # Lifted code runs on the host FPU; control words read back as the
        # Windows x64 defaults and loads are accepted (setjmp, CRT FP setup).
        if op in {"stmxcsr", "vstmxcsr", "fnstcw"} and args and args[0].type == x.X86_OP_MEM:
            self.write(ins, args[0], "8064" if op != "fnstcw" else "895")
            self.jump(following, returns)
            return
        if op in {"ldmxcsr", "vldmxcsr", "fldcw"}:
            self.jump(following, returns)
            return
        if op == "int" and args and args[0].type == x.X86_OP_IMM and args[0].imm == 0x29:
            self.trap(f"RVA {ins.address:#x}: fast fail (int 29h)")
            return
        if op == "xchg":
            a, b = args[:2]
            width = args[0].size * 8
            if a.type == x.X86_OP_MEM or b.type == x.X86_OP_MEM:
                mem_arg, reg_arg = (a, b) if a.type == x.X86_OP_MEM else (b, a)
                addr = self.address(ins, mem_arg)
                ptr = self.value(f"call ptr @guest_pointer(i64 {addr}, i32 {width // 8})")
                val = self.read(ins, reg_arg, width)
                old = self.value(f"atomicrmw xchg ptr {ptr}, i{width} {val} seq_cst")
                self.write(ins, reg_arg, old)
            else:
                val_a = self.read(ins, a, width)
                val_b = self.read(ins, b, width)
                self.write(ins, a, val_b)
                self.write(ins, b, val_a)
            self.jump(following, returns)
            return
        if op == "call":
            operand = args[0]
            cfg_call = (operand.type == x.X86_OP_MEM and operand.mem.base == x.X86_REG_RIP
                        and not operand.mem.segment and self.address(ins, operand) in self.cfg_dispatch_slots)
            rip_slot = (int(self.address(ins, operand)) - self.module_base
                        if operand.type == x.X86_OP_MEM and operand.mem.base == x.X86_REG_RIP
                        else None)
            non_iat_mem = (operand.type == x.X86_OP_MEM and rip_slot not in self.iat_labels
                           and rip_slot not in self.imports)
            if (operand.type == x.X86_OP_REG or cfg_call or non_iat_mem
                    or ((self.module_base or self.bound_dlls) and rip_slot in self.foreign_iat)):
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
        if op in {"jmp", "je", "jne", "ja", "jae", "jb", "jbe", "jl", "jge", "jg", "jle", "jo", "jno", "js", "jns", "jp"}:
            operand = args[0]
            if self.shared and op == "jmp" and operand.type in (x.X86_OP_REG, x.X86_OP_MEM):
                if (self.module_base and operand.type == x.X86_OP_MEM
                        and operand.mem.base == x.X86_REG_RIP
                        and int(self.address(ins, operand)) - self.module_base in self.imports
                        and int(self.address(ins, operand)) - self.module_base not in self.foreign_iat):
                    if not self.import_call(ins, tail=True):
                        self.return_to_caller(returns)
                    return
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
                if bound and not self.current <= target < bound:
                    self.line(f"  musttail call void @{self.function(target)}(ptr %cpu, i64 %return_va)")
                    self.line("  ret void")
                else:
                    self.jump(target, returns)
                return
            if op == "jp":
                self.jump(following, returns)
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
        string_moves = {"movsb": 1, "movsw": 2, "movsd": 4, "movsq": 8}
        plain = op.removeprefix("rep ")
        if (plain in string_moves and len(args) == 2
                and args[0].type == args[1].type == x.X86_OP_MEM):
            # movs with DF clear: copy forward from [rsi] to [rdi] and advance both.
            width = string_moves[plain]
            dest = self.read_reg("rdi", 64)
            source = self.read_reg("rsi", 64)
            count = self.read_reg("rcx", 64) if op.startswith("rep ") else "1"
            self.line(f"  call void @guest_move_string(i64 {dest}, i64 {source}, i64 {count}, i32 {width})")
            size = self.value(f"mul i64 {count}, {width}")
            self.write_reg("rdi", 64, self.value(f"add i64 {dest}, {size}"))
            self.write_reg("rsi", 64, self.value(f"add i64 {source}, {size}"))
            if op.startswith("rep "):
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
        if op == "movss":
            dest, source = args
            if dest.type == x.X86_OP_MEM:
                value = self.load("i64", f"{ins.reg_name(source.reg)}_0")
                address = self.address(ins, dest)
                self.line(f"  call void @guest_store(i64 {address}, i64 {value}, i32 4)")
            else:
                name = ins.reg_name(dest.reg)
                if source.type == x.X86_OP_MEM:
                    value = self.value(f"zext i32 {self.read(ins, source, 32)} to i64")
                    self.store("i64", "0", f"{name}_1")
                else:
                    source_value = self.load("i64", f"{ins.reg_name(source.reg)}_0")
                    value = self.value(f"and i64 {source_value}, 4294967295")
                    previous = self.load("i64", f"{name}_0")
                    upper = self.value(f"and i64 {previous}, -4294967296")
                    value = self.value(f"or i64 {upper}, {value}")
                self.store("i64", value, f"{name}_0")
            self.jump(following, returns)
            return
        if op in {"movhps", "movhpd", "movlps", "movlpd"}:
            dest, source = args[:2]
            lane = 1 if "h" in op else 0
            if dest.type == x.X86_OP_REG and source.type == x.X86_OP_MEM:
                name = ins.reg_name(dest.reg)
                if not name.startswith("xmm"):
                    raise ValueError(f"expected XMM destination for {op}")
                val = self.read(ins, source, 64)
                self.store("i64", val, f"{name}_{lane}")
                self.defined[name] = 128
                if self.shared:
                    self.line(f"  store i8 128, ptr %{name}_0_width")
                self.jump(following, returns)
                return
            elif dest.type == x.X86_OP_MEM and source.type == x.X86_OP_REG:
                name = ins.reg_name(source.reg)
                if not name.startswith("xmm"):
                    raise ValueError(f"expected XMM source for {op}")
                val = self.load("i64", f"{name}_{lane}")
                addr = self.address(ins, dest)
                self.line(f"  call void @guest_store(i64 {addr}, i64 {val}, i32 8)")
                self.jump(following, returns)
                return
        if op in {"addsd", "subsd", "mulsd", "divsd", "sqrtsd", "maxsd", "minsd"}:
            name = ins.reg_name(args[0].reg)
            d_low = self.load("i64", f"{name}_0")
            if op == "sqrtsd":
                src = args[1] if len(args) > 1 else args[0]
                if src.type == x.X86_OP_REG:
                    s_low = self.load("i64", f"{ins.reg_name(src.reg)}_0")
                else:
                    addr = self.address(ins, src)
                    s_low = self.value(f"call i64 @guest_load(i64 {addr}, i32 8)")
                s_f = self.value(f"bitcast i64 {s_low} to double")
                res_f = self.value(f"call double @llvm.sqrt.f64(double {s_f})")
            else:
                src = args[1]
                if src.type == x.X86_OP_REG:
                    s_low = self.load("i64", f"{ins.reg_name(src.reg)}_0")
                else:
                    addr = self.address(ins, src)
                    s_low = self.value(f"call i64 @guest_load(i64 {addr}, i32 8)")
                d_f = self.value(f"bitcast i64 {d_low} to double")
                s_f = self.value(f"bitcast i64 {s_low} to double")
                if op == "addsd":
                    res_f = self.value(f"fadd double {d_f}, {s_f}")
                elif op == "subsd":
                    res_f = self.value(f"fsub double {d_f}, {s_f}")
                elif op == "mulsd":
                    res_f = self.value(f"fmul double {d_f}, {s_f}")
                elif op == "divsd":
                    res_f = self.value(f"fdiv double {d_f}, {s_f}")
                elif op == "maxsd":
                    res_f = self.value(f"call double @llvm.maxnum.f64(double {d_f}, double {s_f})")
                elif op == "minsd":
                    res_f = self.value(f"call double @llvm.minnum.f64(double {d_f}, double {s_f})")
            res_i = self.value(f"bitcast double {res_f} to i64")
            self.store("i64", res_i, f"{name}_0")
            self.jump(following, returns)
            return
        if op in {"ucomisd", "comisd"}:
            name = ins.reg_name(args[0].reg)
            d_low = self.load("i64", f"{name}_0")
            src = args[1]
            if src.type == x.X86_OP_REG:
                s_low = self.load("i64", f"{ins.reg_name(src.reg)}_0")
            else:
                addr = self.address(ins, src)
                s_low = self.value(f"call i64 @guest_load(i64 {addr}, i32 8)")
            d_f = self.value(f"bitcast i64 {d_low} to double")
            s_f = self.value(f"bitcast i64 {s_low} to double")
            eq = self.value(f"fcmp oeq double {d_f}, {s_f}")
            lt = self.value(f"fcmp olt double {d_f}, {s_f}")
            un = self.value(f"fcmp uno double {d_f}, {s_f}")
            zf = self.value(f"or i1 {eq}, {un}")
            cf = self.value(f"or i1 {lt}, {un}")
            self.store("i1", zf, "zf")
            self.store("i1", cf, "cf")
            self.store("i1", "0", "of")
            self.store("i1", "0", "sf")
            self.store("i1", "0", "signed_less")
            self.zero = self.carry = self.overflow = self.signed = True
            self.jump(following, returns)
            return
        if op == "cvtsi2sd":
            name = ins.reg_name(args[0].reg)
            src_width = args[1].size * 8
            src_val = self.read(ins, args[1], src_width)
            f_val = self.value(f"sitofp i{src_width} {src_val} to double")
            i_val = self.value(f"bitcast double {f_val} to i64")
            self.store("i64", i_val, f"{name}_0")
            self.jump(following, returns)
            return
        if op == "cvttsd2si":
            dest_width = args[0].size * 8
            src = args[1]
            if src.type == x.X86_OP_REG:
                s_low = self.load("i64", f"{ins.reg_name(src.reg)}_0")
            else:
                addr = self.address(ins, src)
                s_low = self.value(f"call i64 @guest_load(i64 {addr}, i32 8)")
            d_f = self.value(f"bitcast i64 {s_low} to double")
            i_val = self.value(f"fptosi double {d_f} to i{dest_width}")
            self.write(ins, args[0], i_val)
            self.jump(following, returns)
            return
        if op in {"fninit", "fldz", "fnstsw", "fld", "fild", "fstp", "fxch", "faddp", "fucomi", "fcompi", "fscale", "fprem", "fprem1"}:
            if op == "fninit":
                self.line("  call void @guest_fninit()")
            elif op == "fldz":
                self.line("  call void @guest_fldz()")
            elif op == "fnstsw":
                sw = self.value("call i16 @guest_fnstsw()")
                if args and args[0].type == x.X86_OP_REG and ins.reg_name(args[0].reg) in ("ax", "eax", "rax"):
                    self.write_reg("rax", 16, sw)
                elif args:
                    addr = self.address(ins, args[0])
                    self.line(f"  call void @guest_store(i64 {addr}, i64 {self.value(f'zext i16 {sw} to i64')}, i32 2)")
            elif op == "fld":
                if args[0].type == x.X86_OP_REG:
                    idx = int(ins.reg_name(args[0].reg)[3:-1]) if "(" in ins.reg_name(args[0].reg) else 0
                    self.line(f"  call void @guest_fld_st(i32 {idx})")
                else:
                    addr = self.address(ins, args[0])
                    size = args[0].size
                    if size in (10, 16):
                        self.line(f"  call void @guest_fld_f80(i64 {addr})")
                    elif size == 8:
                        self.line(f"  call void @guest_fld_f64(i64 {addr})")
                    else:
                        self.line(f"  call void @guest_fld_f32(i64 {addr})")
            elif op == "fild":
                addr = self.address(ins, args[0])
                size = args[0].size
                ival = self.value(f"call i64 @guest_load(i64 {addr}, i32 {size})")
                if size < 8:
                    ival = self.value(f"sext i{size*8} {self.value(f'trunc i64 {ival} to i{size*8}')} to i64")
                self.line(f"  call void @guest_fild(i64 {ival})")
            elif op == "fstp":
                if args[0].type == x.X86_OP_REG:
                    idx = int(ins.reg_name(args[0].reg)[3:-1]) if "(" in ins.reg_name(args[0].reg) else 0
                    self.line(f"  call void @guest_fstp_st(i32 {idx})")
                else:
                    addr = self.address(ins, args[0])
                    size = args[0].size
                    if size in (10, 16):
                        self.line(f"  call void @guest_fstp_f80(i64 {addr})")
                    elif size == 8:
                        self.line(f"  call void @guest_fstp_f64(i64 {addr})")
                    else:
                        self.line(f"  call void @guest_fstp_f32(i64 {addr})")
            elif op == "fxch":
                idx = int(ins.reg_name(args[0].reg)[3:-1]) if args and "(" in ins.reg_name(args[0].reg) else 1
                self.line(f"  call void @guest_fxch(i32 {idx})")
            elif op == "faddp":
                idx = int(ins.reg_name(args[0].reg)[3:-1]) if args and "(" in ins.reg_name(args[0].reg) else 1
                self.line(f"  call void @guest_faddp(i32 {idx})")
            elif op in {"fucomi", "fcompi"}:
                idx = int(ins.reg_name(args[0].reg)[3:-1]) if args and "(" in ins.reg_name(args[0].reg) else 1
                flags = self.value(f"call i32 @guest_fcompi(i32 {idx}, i32 1)")
                zf = self.value(f"trunc i32 {self.value(f'and i32 {flags}, 1')} to i1")
                cf = self.value(f"trunc i32 {self.value(f'lshr i32 {self.value(f'and i32 {flags}, 2')}, 1')} to i1")
                self.store("i1", zf, "zf")
                self.store("i1", cf, "cf")
                self.store("i1", "0", "of")
                self.store("i1", "0", "sf")
                self.store("i1", "0", "signed_less")
                self.zero = self.carry = self.overflow = self.signed = True
            elif op == "fscale":
                self.line("  call void @guest_fscale()")
            elif op in {"fprem", "fprem1"}:
                self.line("  call void @guest_fprem()")
            self.jump(following, returns)
            return
        if op in {"movups", "movupd", "packuswb", "pinsrw", "pextrw", "movaps", "movapd", "movdqu", "movdqa", "pxor", "xorps", "xorpd", "pand", "andps", "andpd", "por", "orps", "orpd", "pandn", "andnps", "andnpd", "punpcklqdq", "unpcklpd", "punpckhqdq", "unpckhpd", "movlhps", "movhlps", "punpckldq", "punpcklbw", "punpckhbw", "punpcklwd", "pshuflw", "pshufhw", "pshufd", "pcmpeqw", "pcmpeqb", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd", "pmovmskb", "movmskps", "movmskpd", "paddd", "paddq", "psubd", "psubq", "movd", "movq", "movsd", "shufpd", "shufps", "psrldq", "pslldq", "psllw", "psrlw", "pslld", "psrld", "psllq", "psrlq", "movddup"}:
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
            if op in {"pmovmskb", "movmskps", "movmskpd"}:
                low, high = vector(source)
                if op == "movmskpd":
                    low_bit = self.value(f"lshr i64 {low}, 63")
                    high_bit = self.value(f"lshr i64 {high}, 63")
                    high_bit = self.value(f"shl i64 {high_bit}, 1")
                    bits = self.value(f"or i64 {low_bit}, {high_bit}")
                    value = self.value(f"trunc i64 {bits} to i32")
                else:
                    fn = "guest_movmskps" if op == "movmskps" else "guest_vector_mask"
                    value = self.value(f"call i32 @{fn}(i64 {low}, i64 {high})")
                self.write(ins, dest, value)
                self.jump(following, returns)
                return
            if op in {"paddd", "psubd"}:
                output = []
                for a, b in zip(vector(dest), vector(source)):
                    left = self.value(f"bitcast i64 {a} to <2 x i32>")
                    right = self.value(f"bitcast i64 {b} to <2 x i32>")
                    math_op = "add" if op == "paddd" else "sub"
                    total = self.value(f"{math_op} <2 x i32> {left}, {right}")
                    output.append(self.value(f"bitcast <2 x i32> {total} to i64"))
                values = output
            elif op in {"paddq", "psubq"}:
                math_op = "add" if op == "paddq" else "sub"
                values = tuple(self.value(f"{math_op} i64 {a}, {b}") for a, b in zip(vector(dest), vector(source)))
            elif op in {"pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd"}:
                is_gt = op.startswith("pcmpgt")
                if dest.type == x.X86_OP_REG and source.type == x.X86_OP_REG and dest.reg == source.reg:
                    values = ("0", "0") if is_gt else ("-1", "-1")
                else:
                    lanes = 8 if op.endswith("b") else (4 if op.endswith("w") else 2)
                    elem_w = 8 if op.endswith("b") else (16 if op.endswith("w") else 32)
                    predicate = "sgt" if is_gt else "eq"
                    output = []
                    for a, b in zip(vector(dest), vector(source)):
                        left = self.value(f"bitcast i64 {a} to <{lanes} x i{elem_w}>")
                        right = self.value(f"bitcast i64 {b} to <{lanes} x i{elem_w}>")
                        cmp_res = self.value(f"icmp {predicate} <{lanes} x i{elem_w}> {left}, {right}")
                        extended = self.value(f"sext <{lanes} x i1> {cmp_res} to <{lanes} x i{elem_w}>")
                        output.append(self.value(f"bitcast <{lanes} x i{elem_w}> {extended} to i64"))
                    values = output
            elif op in {"punpcklbw", "punpckhbw", "pshuflw", "pshufhw", "pshufd"}:
                low, high = vector(source)
                unpack = op in {"punpcklbw", "punpckhbw"}
                if unpack:
                    selected = int(op == "punpckhbw")
                    other = vector(dest)[selected]
                    low = high if selected else low
                    operation, control = 0, 0
                else:
                    other = "0"
                    operation = {"pshuflw": 1, "pshufd": 2, "pshufhw": 1}[op]
                    control = args[2].imm
                    if op == "pshufhw":
                        low, high = high, low
                output = []
                for lane in range(2):
                    value = self.value(f"call i64 @guest_shuffle(i64 {low}, i64 {high}, i64 {other}, "
                                       f"i32 {operation}, i32 {control}, i32 {lane})")
                    output.append(value)
                values = output[::-1] if op == "pshufhw" else output
            elif op == "packuswb":
                packed = []
                for operand in (dest, source):
                    low, high = vector(operand)
                    packed.append(self.value(f"call i64 @guest_packuswb(i64 {low}, i64 {high})"))
                values = tuple(packed)
            elif op == "pextrw":
                word = args[2].imm & 7
                lane = vector(source)[word // 4]
                shifted = self.value(f"lshr i64 {lane}, {(word % 4) * 16}")
                unit = self.value(f"trunc i64 {shifted} to i16")
                value = self.value(f"zext i16 {unit} to i{dest.size * 8}")
                self.write(ins, dest, value)
                self.jump(following, returns)
                return
            elif op == "pinsrw":
                values = list(vector(dest))
                word = args[2].imm & 7
                lane, shift = word // 4, (word % 4) * 16
                unit = self.read(ins, source, 16 if source.type == x.X86_OP_MEM else 32)
                if source.type == x.X86_OP_REG:
                    unit = self.value(f"trunc i32 {unit} to i16")
                unit = self.value(f"zext i16 {unit} to i64")
                unit = self.value(f"shl i64 {unit}, {shift}")
                old = self.value(f"and i64 {values[lane]}, {~(65535 << shift)}")
                values[lane] = self.value(f"or i64 {old}, {unit}")
            elif op in {"punpcklqdq", "unpcklpd", "movlhps"}:
                values = (vector(dest)[0], vector(source)[0])
            elif op == "movddup":
                # The memory form reads only 64 bits.
                if source.type == x.X86_OP_MEM:
                    low = self.value(f"call i64 @guest_load(i64 {self.address(ins, source)}, i32 8)")
                else:
                    low = vector(source)[0]
                values = (low, low)
            elif op in {"punpckhqdq", "unpckhpd"}:
                values = (vector(dest)[1], vector(source)[1])
            elif op == "movhlps":
                values = (vector(source)[1], vector(dest)[1])
            elif op == "punpckldq":
                d_low = vector(dest)[0]
                s_low = vector(source)[0]
                d0 = self.value(f"and i64 {d_low}, 4294967295")
                d1 = self.value(f"lshr i64 {d_low}, 32")
                s0 = self.value(f"shl i64 {s_low}, 32")
                s1 = self.value(f"and i64 {s_low}, -4294967296")
                values = (self.value(f"or i64 {d0}, {s0}"), self.value(f"or i64 {d1}, {s1}"))
            elif op == "punpcklwd":
                d0, s0 = vector(dest)[0], vector(source)[0]
                v0 = self.value(f"call i64 @guest_punpcklwd(i64 {d0}, i64 {s0}, i32 0)")
                v1 = self.value(f"call i64 @guest_punpcklwd(i64 {d0}, i64 {s0}, i32 1)")
                values = (v0, v1)
            elif op in {"pxor", "xorps", "xorpd"}:
                values = ("0", "0") if dest.type == x.X86_OP_REG and source.type == x.X86_OP_REG and dest.reg == source.reg else tuple(
                    self.value(f"xor i64 {left}, {right}") for left, right in zip(vector(dest), vector(source)))
            elif op in {"pand", "andps", "andpd"}:
                values = tuple(self.value(f"and i64 {left}, {right}") for left, right in zip(vector(dest), vector(source)))
            elif op in {"por", "orps", "orpd"}:
                values = tuple(self.value(f"or i64 {left}, {right}") for left, right in zip(vector(dest), vector(source)))
            elif op in {"pandn", "andnps", "andnpd"}:
                values = tuple(self.value(f"and i64 {self.value(f'xor i64 {left}, -1')}, {right}") for left, right in zip(vector(dest), vector(source)))
            elif op in {"psrldq", "pslldq"}:
                shift = (args[1].imm & 255) * 8
                if shift >= 128:
                    values = ("0", "0")
                else:
                    low, high = vector(dest)
                    lo = self.value(f"zext i64 {low} to i128")
                    hi = self.value(f"zext i64 {high} to i128")
                    hi = self.value(f"shl i128 {hi}, 64")
                    wide = self.value(f"or i128 {lo}, {hi}")
                    direction = "shl" if op == "pslldq" else "lshr"
                    result = self.value(f"{direction} i128 {wide}, {shift}")
                    lo = self.value(f"trunc i128 {result} to i64")
                    hi = self.value(f"lshr i128 {result}, 64")
                    hi = self.value(f"trunc i128 {hi} to i64")
                    values = (lo, hi)
            elif op in {"psllw", "psrlw", "pslld", "psrld", "psllq", "psrlq"}:
                kind = {"psllw": 0, "psrlw": 1, "pslld": 2, "psrld": 3, "psllq": 4, "psrlq": 5}[op]
                if source.type == x.X86_OP_IMM:
                    count_val = str(source.imm)
                else:
                    count_val = vector(source)[0]
                values = tuple(self.value(f"call i64 @guest_vector_shift(i64 {val}, i64 {count_val}, i32 {kind})")
                               for val in vector(dest))
            elif op == "shufps":
                imm = args[2].imm if len(args) > 2 else 0
                d0, d1 = vector(dest)
                s0, s1 = vector(source)
                v0 = self.value(f"call i64 @guest_shufps(i64 {d0}, i64 {d1}, i64 {s0}, i64 {s1}, i32 {imm}, i32 0)")
                v1 = self.value(f"call i64 @guest_shufps(i64 {d0}, i64 {d1}, i64 {s0}, i64 {s1}, i32 {imm}, i32 1)")
                values = (v0, v1)
            elif op == "shufpd":
                imm = args[2].imm if len(args) > 2 else 0
                d_vec = vector(dest)
                s_vec = vector(source)
                values = (d_vec[imm & 1], s_vec[(imm >> 1) & 1])
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
        if op == "int3":
            self.trap("int3 breakpoint")
            return
        if op in {"nop", "pause"}:
            self.jump(following, returns)
            return
        width = args[0].size * 8 if args else 0
        if op == "cdqe":
            low = self.read_reg("rax", 32)
            self.write_reg("rax", 64, self.value(f"sext i32 {low} to i64"))
        elif op == "cdq":
            low = self.read_reg("rax", 32)
            extended = self.value(f"ashr i32 {low}, 31")
            self.write_reg("rdx", 64, self.value(f"zext i32 {extended} to i64"))
        elif op == "cqo":
            val = self.read_reg("rax", 64)
            extended = self.value(f"ashr i64 {val}, 63")
            self.write_reg("rdx", 64, extended)
        elif op == "cwde":
            low = self.read_reg("rax", 16)
            self.write_reg("rax", 64, self.value(f"zext i32 {self.value(f'sext i16 {low} to i32')} to i64"))
        elif op == "cbw":
            low = self.read_reg("rax", 8)
            self.write_reg("rax", 16, self.value(f"sext i8 {low} to i16"))
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
            value = source if source_width == width else self.value(
                f"{extension} i{source_width} {source} to i{width}")
            self.write(ins, args[0], value)
        elif op == "lea" and width in (32, 64):
            address = self.address(ins, args[1])
            if self.modules and self.shared and args[1].mem.base == x.X86_REG_RIP:
                rva = int(address) - self.module_base
                section = self.image.get_section_by_rva(rva)
                if section and section.Characteristics & 0x20000000:
                    self.function(rva)
                elif section and 0 < rva <= 0xffff:
                    # Keep low data pointers distinguishable from GetProcAddress ordinals.
                    address = str(self.image_base + rva)
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
        elif op in {"xadd", "lock xadd"}:
            if args[0].type == x.X86_OP_MEM and args[1].type == x.X86_OP_REG:
                addr = self.address(ins, args[0])
                ptr = self.value(f"call ptr @guest_pointer(i64 {addr}, i32 {width // 8})")
                right = self.read(ins, args[1], width)
                old = self.value(f"atomicrmw add ptr {ptr}, i{width} {right} seq_cst")
                total = self.value(f"add i{width} {old}, {right}")
                self.write(ins, args[1], old)
            else:
                left, right = (self.read(ins, arg, width) for arg in args)
                total = self.value(f"add i{width} {left}, {right}")
                self.write(ins, args[0], total)
                self.write(ins, args[1], left)
            self.store("i1", self.value(f"icmp eq i{width} {total}, 0"), "zf")
            self.zero = True
            self.store("i1", self.value(f"icmp slt i{width} {total}, 0"), "sf")
            self.carry = self.overflow = False
        elif op == "cmpxchg" and width in (8, 16, 32, 64) and args[1].type == x.X86_OP_REG:
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
        elif op == "imul" and len(args) == 1:
            operands = [self.read(ins, args[0], width), self.read_reg("rax", width)]
            extended = [self.value(f"sext i{width} {value} to i{width * 2}") for value in operands]
            product = self.value(f"mul i{width * 2} {extended[0]}, {extended[1]}")
            upper = self.value(f"lshr i{width * 2} {product}, {width}")
            for register, value in (("rax", product), ("rdx", upper)):
                self.write_reg(register, width, self.value(f"trunc i{width * 2} {value} to i{width}"))
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
        elif op == "idiv" and width == 32:
            parts = [self.read_reg(name, 32) for name in ("rdx", "rax")]
            high, low = (self.value(f"zext i32 {part} to i64") for part in parts)
            top = self.value(f"shl i64 {high}, 32")
            combined = self.value(f"or i64 {top}, {low}")
            denominator = self.read(ins, args[0], 32)
            self.line(f"  call void @guest_idiv32(i64 {combined}, i32 {denominator}, ptr %rax, ptr %rdx)")
            self.write_reg("rax", 64, self.load("i64", "rax"))
            self.write_reg("rdx", 64, self.load("i64", "rdx"))
            self.zero = self.carry = self.signed = self.overflow = False
        elif op == "idiv" and width == 64:
            denominator = self.read(ins, args[0], 64)
            high = self.read_reg("rdx", 64)
            low = self.read_reg("rax", 64)
            self.line(f"  call void @guest_idiv(i64 {high}, i64 {low}, i64 {denominator}, ptr %rax, ptr %rdx)")
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
            self.store("i1", overflow, "of")
            self.overflow = True
            self.zero = self.carry = self.signed = True
            self.write(ins, args[0], value)
        elif op == "bswap" and width in (32, 64):
            value = self.read(ins, args[0], width)
            self.write(ins, args[0], self.value(f"call i{width} @llvm.bswap.i{width}(i{width} {value})"))
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
                negative = self.value(f"icmp slt i{width} {value}, 0")
                if args[1].type != x.X86_OP_IMM and self.signed:
                    unchanged = self.value(f"icmp eq i{shift_width} {count}, 0")
                    prior_negative = self.load("i1", "sf")
                    negative = self.value(f"select i1 {unchanged}, i1 {prior_negative}, i1 {negative}")
                self.store("i1", negative, "sf")
                self.signed = self.signed or args[1].type == x.X86_OP_IMM
                self.carry = self.overflow = False
                shift = int(count) if args[1].type == x.X86_OP_IMM else 0
                if shift and (op != "shl" or shift <= width):
                    # CF is the last bit shifted out; OF is defined for one-bit shifts.
                    bit = width - shift if op == "shl" else shift - 1
                    source = previous if shift_width == width else self.value(
                        f"trunc i{shift_width} {previous} to i{width}")
                    carry = self.value(f"trunc i{width} " + self.value(
                        f"lshr i{width} {source}, {bit}") + " to i1")
                    if op == "shl":
                        overflow = self.value(f"xor i1 {negative}, {carry}")
                    elif op == "shr":
                        overflow = self.value(f"icmp slt i{width} {source}, 0")
                    else:
                        overflow = "false"
                    self.store("i1", carry, "cf")
                    self.store("i1", overflow, "of")
                    self.store("i1", self.value(f"xor i1 {negative}, {overflow}"), "signed_less")
                    self.carry = True
                    self.overflow = shift == 1
                else:
                    self.store("i1", negative, "signed_less")
                self.write(ins, args[0], value)
        elif op in {"shld", "shrd"} and width in (16, 32, 64):
            dest_val = self.read(ins, args[0], width)
            src_val = self.read(ins, args[1], width)
            if args[2].type == x.X86_OP_IMM:
                count_val = str(args[2].imm & (width - 1))
            else:
                byte = self.read(ins, args[2], 8)
                wide = self.value(f"zext i8 {byte} to i{width}")
                count_val = self.value(f"and i{width} {wide}, {width - 1}")
            if op == "shld":
                fn = f"@llvm.fshl.i{width}"
                arg_a, arg_b = dest_val, src_val
            else:
                fn = f"@llvm.fshr.i{width}"
                arg_a, arg_b = src_val, dest_val
            value = self.value(f"call i{width} {fn}(i{width} {arg_a}, i{width} {arg_b}, i{width} {count_val})")
            zero = self.value(f"icmp eq i{width} {value}, 0")
            negative = self.value(f"icmp slt i{width} {value}, 0")
            if args[2].type != x.X86_OP_IMM and self.zero:
                unchanged = self.value(f"icmp eq i{width} {count_val}, 0")
                prior_zero = self.load("i1", "zf")
                zero = self.value(f"select i1 {unchanged}, i1 {prior_zero}, i1 {zero}")
            if args[2].type != x.X86_OP_IMM and self.signed:
                unchanged = self.value(f"icmp eq i{width} {count_val}, 0")
                prior_negative = self.load("i1", "sf")
                negative = self.value(f"select i1 {unchanged}, i1 {prior_negative}, i1 {negative}")
            self.store("i1", zero, "zf")
            self.store("i1", negative, "sf")
            self.store("i1", negative, "signed_less")
            self.zero = self.zero or args[2].type == x.X86_OP_IMM
            self.signed = self.signed or args[2].type == x.X86_OP_IMM
            self.carry = self.overflow = False
            self.write(ins, args[0], value)
        elif (op in {"cmovs", "cmovns"} and self.signed
              or op in {"cmovo", "cmovno"} and self.overflow):
            condition = self.load("i1", "of" if op in {"cmovo", "cmovno"} else "sf")
            if op in {"cmovns", "cmovno"}:
                condition = self.value(f"xor i1 {condition}, true")
            old, candidate = (self.read(ins, arg, width) for arg in args)
            selected = self.value(f"select i1 {condition}, i{width} {candidate}, i{width} {old}")
            self.write(ins, args[0], selected)
        elif op in {"cmove", "cmovne", "cmova", "cmovb", "cmovae", "cmovbe"} and (self.zero or op in {"cmovb", "cmovae"}):
            condition = "false" if op in {"cmovb", "cmovae"} else self.load("i1", "zf")
            if op in {"cmova", "cmovb", "cmovae", "cmovbe"}:
                if not self.carry:
                    raise ValueError(f"{op} reads undefined carry")
                carry = self.load("i1", "cf")
                condition = self.value(f"or i1 {carry}, {condition}") if op in {"cmova", "cmovbe"} else carry
            if op in {"cmovne", "cmova", "cmovae"}:
                condition = self.value(f"xor i1 {condition}, true")
            old, candidate = (self.read(ins, arg, width) for arg in args)
            selected = self.value(f"select i1 {condition}, i{width} {candidate}, i{width} {old}")
            self.write(ins, args[0], selected)
        elif op in {"cmovl", "cmovge", "cmovle", "cmovg"} and self.signed:
            condition = self.load("i1", "signed_less")
            if op in {"cmovg", "cmovle"}:
                if not self.zero:
                    raise ValueError("cmovg reads undefined zero flag")
                zero = self.load("i1", "zf")
                condition = self.value(f"or i1 {condition}, {zero}")
            if op in {"cmovge", "cmovg"}:
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
                overflow = self.value(f"xor i1 {negative}, {signed_less}")
            else:
                signed_less = negative
                if op == "add":
                    left = self.value(f"xor i{width} {lhs}, {value}")
                    right = self.value(f"xor i{width} {rhs}, {value}")
                    both = self.value(f"and i{width} {left}, {right}")
                    overflow = self.value(f"icmp slt i{width} {both}, 0")
                    signed_less = self.value(f"xor i1 {negative}, {overflow}")
                else:
                    overflow = "false"
            self.store("i1", overflow, "of")
            self.store("i1", signed_less, "signed_less")
            self.signed = True
            self.overflow = True
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
        elif op in {"setl", "setge", "setle"} and self.signed:
            value = self.load("i1", "signed_less")
            if op == "setle":
                if not self.zero:
                    raise ValueError("setle reads undefined zero flag")
                zero = self.load("i1", "zf")
                value = self.value(f"or i1 {value}, {zero}")
            elif op == "setge":
                value = self.value(f"xor i1 {value}, true")
            self.write(ins, args[0], self.value(f"zext i1 {value} to i8"))
        elif op in {"seto", "setno"}:
            if not self.overflow:
                raise ValueError("seto reads undefined overflow")
            value = self.load("i1", "of")
            if op == "setno":
                value = self.value(f"xor i1 {value}, true")
            self.write(ins, args[0], self.value(f"zext i1 {value} to i8"))
        elif op == "setp":
            self.write(ins, args[0], "0")
        elif op in {"bsr", "bsf"} and width in (32, 64):
            src = self.read(ins, args[1], width)
            zero = self.value(f"icmp eq i{width} {src}, 0")
            self.store("i1", zero, "zf")
            self.zero = True
            self.carry = self.signed = self.overflow = False
            if op == "bsf":
                res = self.value(f"call i{width} @llvm.cttz.i{width}(i{width} {src}, i1 false)")
            else:
                lz = self.value(f"call i{width} @llvm.ctlz.i{width}(i{width} {src}, i1 false)")
                res = self.value(f"sub i{width} {width - 1}, {lz}")
            self.write(ins, args[0], res)
        elif op in {"tzcnt", "lzcnt"} and width in (32, 64):
            src = self.read(ins, args[1], width)
            fn = f"@llvm.cttz.i{width}" if op == "tzcnt" else f"@llvm.ctlz.i{width}"
            res = self.value(f"call i{width} {fn}(i{width} {src}, i1 false)")
            src_zero = self.value(f"icmp eq i{width} {src}, 0")
            res_zero = self.value(f"icmp eq i{width} {res}, 0")
            self.store("i1", src_zero, "cf")
            self.store("i1", res_zero, "zf")
            self.carry = True
            self.zero = True
            self.signed = self.overflow = False
            self.write(ins, args[0], res)
        elif op in {"nop", "fninit", "cld"}:
            pass
        else:
            raise ValueError("unsupported console instruction")
        self.jump(following, returns)

    def emit_console(self, entry, base, code, data, *, module=None):
        self.module_base = self.image_base if module else 0
        prefix = f"{module}_" if module else ""
        descriptors = []
        for index, (rva, blob, size, writable) in enumerate(data):
            symbol = f"@guest_section_{index}"
            if blob:
                contents = "".join(f"\\{byte:02x}" for byte in blob)
                self.line(f'{symbol} = private constant [{len(blob)} x i8] c"{contents}"')
            pointer = symbol if blob else "null"
            descriptors.append(f"{{ i64, i64, i64, ptr, i64 }} "
                               f"{{ i64 {rva + self.module_base}, i64 {size}, i64 {len(blob)}, "
                               f"ptr {pointer}, i64 {int(writable)} }}")
        count = len(descriptors)
        kind = f"[{count} x {{ i64, i64, i64, ptr, i64 }}]"
        self.line(f"@{prefix}guest_sections = constant {kind} [{', '.join(descriptors)}]")
        self.line(f"@{prefix}guest_section_count = constant i64 {count}")
        if not module:
            ranges = [(section.VirtualAddress, section.Misc_VirtualSize)
                      for section in self.image.sections if section.Characteristics & 0x20000000]
            entries = ", ".join(f"{{ i64, i64 }} {{ i64 {start}, i64 {length} }}"
                                for start, length in ranges)
            self.line(f"@guest_code_ranges = constant [{len(ranges)} x {{ i64, i64 }}] [{entries}]")
            self.line(f"@guest_code_range_count = constant i64 {len(ranges)}")
            directory = self.image.OPTIONAL_HEADER.DATA_DIRECTORY[3]
            self.line(f"@guest_exception_rva = constant i64 {directory.VirtualAddress}")
            self.line(f"@guest_exception_size = constant i64 {directory.Size}")
        self.line(f"@{prefix}guest_image_base = constant i64 {self.image_base}")
        self.line(f"@{prefix}guest_tls_start_raw = constant i64 {self.tls_start}")
        self.line(f"@{prefix}guest_tls_end_raw = constant i64 {self.tls_end}")
        self.line(f"@{prefix}guest_tls_index_va = constant i64 {self.tls_index_va}")
        self.line(f"@{prefix}guest_tls_zero_fill = constant i64 {self.tls_zero_fill}")
        self.line("declare void @guest_set_pc(i64)")
        self.line("declare void @guest_mark_fault_pc(i64)")
        self.line("declare i64 @subsys_CreateFileMappingW(i64, i64, i32, i32, i32, i64)")
        self.line("declare i64 @subsys_MapViewOfFile(i64, i32, i32, i32, i64)")
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
        self.line("declare i64 @guest_p_wenviron()")
        self.line("declare i64 @guest_p_environ()")
        self.line("declare i64 @guest_p_fmode()")
        self.line("declare i64 @guest_p_commode()")
        self.line("declare i64 @guest_set_new_mode(i32)")
        self.line("declare i64 @guest_wcslen(i64)")
        self.line("declare i64 @guest_wcsnlen(i64, i64)")
        self.line("declare i64 @guest_strlen(i64)")
        self.line("declare i64 @guest_strnlen(i64, i64)")
        self.line("declare i64 @guest_memset(i64, i32, i64)")
        self.line("declare i64 @guest_memcpy(i64, i64, i64)")
        self.line("declare i64 @guest_strcmp(i64, i64)")
        self.line("declare i64 @guest_strncmp(i64, i64, i64)")
        self.line("declare i64 @guest_strcpy(i64, i64)")
        self.line("declare i64 @guest_strdup(i64)")
        self.line("declare i64 @guest_getenv(i64)")
        self.line("declare i64 @guest_isalnum(i32)")
        self.line("declare i64 @guest_isalpha(i32)")
        self.line("declare i64 @guest_isspace(i32)")
        self.line("declare i64 @guest_process_prng(i64, i64)")
        self.line("declare i64 @guest_cexit()")
        self.line("declare i64 @guest_set_thread_stack_guarantee(i64)")
        self.line("declare i64 @guest_heap_realloc(i64, i32, i64, i64)")
        self.line("declare i64 @guest_heap_alloc(i64, i32, i64)")
        self.line("declare i64 @guest_heap_free(i64, i32, i64)")
        self.line("declare i64 @guest_malloc(i64)")
        self.line("declare i64 @guest_free(i64)")
        self.line("declare i64 @guest_realloc(i64, i64)")
        self.line("declare i64 @guest_calloc(i64, i64)")
        self.line("declare i64 @guest_memcmp(i64, i64, i64, i64)")
        self.line("declare i64 @guest_memchr(i64, i32, i64, i64)")
        self.line("declare i64 @guest_strchr(i64, i32, i64, i64)")
        self.line("declare i64 @guest_strrchr(i64, i32, i64, i64)")
        self.line("declare i64 @guest_strstr(i64, i64, i64, i64)")
        self.line("declare i64 @guest_qsort(i64, i64, i64, i64)")
        self.line("declare i64 @guest_load_library(i64, i64, i32)")
        self.line("declare i64 @guest_get_proc(i64, i64)")
        self.line("declare i64 @guest_indirect_call(i64, i64, i64, i64, i64)")
        self.line("declare i64 @guest_indirect_call_inline(i64, i64, i64, i64, i64)")
        self.line("declare i64 @guest_free_library(i64)")
        self.line("declare void @guest_trap(ptr) noreturn")
        self.line("declare void @guest_check_xcr(i32, i64)")
        self.line("declare void @guest_stack_smash_trap(i64)")
        for width in (32, 64):
            for name in ("fshr", "fshl", "cttz", "ctlz"):
                if name in ("cttz", "ctlz"):
                    self.line(f"declare i{width} @llvm.{name}.i{width}(i{width}, i1)")
                else:
                    self.line(f"declare i{width} @llvm.{name}.i{width}(i{width}, i{width}, i{width})")
        self.line("declare i32 @guest_vector_mask(i64, i64)")
        self.line("declare i32 @guest_movmskps(i64, i64)")
        self.line("declare i64 @guest_compare_words(i64, i64, i32)")
        self.line("declare i64 @guest_packuswb(i64, i64)")
        self.line("declare i64 @guest_shuffle(i64, i64, i64, i32, i32, i32)")
        self.line("declare i64 @guest_vector_shift(i64, i64, i32)")
        self.line("declare void @guest_div32(i64, i64, ptr, ptr)")
        self.line("declare void @guest_div(i64, i64, i64, ptr, ptr)")
        self.line("declare void @guest_idiv32(i64, i32, ptr, ptr)")
        self.line("declare void @guest_idiv(i64, i64, i64, ptr, ptr)")
        self.line("declare void @guest_fninit()")
        self.line("declare void @guest_fldz()")
        self.line("declare i16 @guest_fnstsw()")
        self.line("declare void @guest_fld_st(i32)")
        self.line("declare void @guest_fstp_st(i32)")
        self.line("declare void @guest_fld_f80(i64)")
        self.line("declare void @guest_fstp_f80(i64)")
        self.line("declare void @guest_fld_f64(i64)")
        self.line("declare void @guest_fstp_f64(i64)")
        self.line("declare void @guest_fld_f32(i64)")
        self.line("declare void @guest_fstp_f32(i64)")
        self.line("declare void @guest_fild(i64)")
        self.line("declare void @guest_fxch(i32)")
        self.line("declare void @guest_faddp(i32)")
        self.line("declare i32 @guest_fcompi(i32, i32)")
        self.line("declare void @guest_fscale()")
        self.line("declare void @guest_fprem()")
        self.line("declare i64 @guest_shufps(i64, i64, i64, i64, i32, i32)")
        self.line("declare i64 @guest_punpcklwd(i64, i64, i32)")
        self.line("declare double @llvm.sqrt.f64(double)")
        self.line("declare double @llvm.maxnum.f64(double, double)")
        self.line("declare double @llvm.minnum.f64(double, double)")
        self.line("declare i64 @guest_fill(i64, i64, i64, i32)")
        self.line("declare void @guest_move_string(i64, i64, i64, i32)")
        for name in ("subsys_CreateFileW", "subsys_CreateFileA"):
            self.line(f"declare i64 @{name}(i64, i32, i32, i64, i32, i32, i64)")
        self.line("declare i64 @guest_load(i64, i32)")
        self.line("declare void @guest_store(i64, i64, i32)")
        self.line("declare void @guest_check_return(i64, i64)")
        self.line("declare i64 @guest_identity(i32)")
        self.line("declare i64 @guest_performance_counter(i64)")
        self.line("declare void @guest_system_filetime(i64)")
        self.line("declare void @guest_set_last_error(i32)")
        self.line("declare i64 @guest_get_last_error()")
        self.line("declare i64 @guest_stdout(i32)")
        self.line("declare i64 @guest_nt_read_file(i64, i64, i64, i64, i64)")
        self.line("declare i64 @guest_write(i64, i64, i32, i64, i64)")
        self.line("declare i64 @guest_get_handle_info(i64, i64)")
        self.line("declare i64 @guest_tick_count_64()")
        self.line("declare i64 @guest_tick_count()")
        self.line("declare i64 @guest_performance_frequency(i64)")
        self.line("declare i64 @guest_is_processor_feature_present(i32)")
        self.line("declare i64 @guest_unhandled_exception_filter(i64)")
        self.line("declare i64 @guest_terminate_process(i64, i32)")
        self.line("declare void @guest_rtl_capture_context(i64)")
        self.line("declare void @guest_raise_exception(i32, i32, i32, i64, i64, i64)")
        self.line("declare void @guest_rtl_unwind_ex(i64, i64, i64, i64, i64, i64, i64, i64) noreturn")
        self.line("declare i64 @guest_rtl_virtual_unwind(i32, i64, i64, i64, i64, i64, i64, i64)")
        self.line("declare i64 @guest_rtl_lookup_function_entry(i64, i64, i64)")
        self.line("declare i64 @guest_unimplemented_stub(ptr, ptr)")
        for name in GENERATED_SHIMS:
            self.line(f"declare i64 @guest_{name}(i64, i64, i64, i64)")
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
                if code_sec.contains_rva(rva):
                    self.function(rva)
                unwind = row.struct.UnwindData
                header = self.image.get_data(unwind, 4)
                if len(header) == 4 and header[0] & 7 == 1 and header[0] >> 3 in (1, 2, 3):
                    field = unwind + 4 + ((header[2] + 1) & ~1) * 2
                    handler = self.image.get_dword_at_rva(field)
                    if handler is not None and code_sec.contains_rva(handler):
                        self.function(handler)
                        # C scope tables have a count followed by bounded ranges.
                        # C++ handler data starts with a FuncInfo RVA instead.
                        count = self.image.get_dword_at_rva(field + 4)
                        if count and count <= 64:
                            scopes = self.image.get_data(field + 8, count * 16)
                            if len(scopes) == count * 16:
                                entries = list(struct.iter_unpack("<IIII", scopes))
                                if all(rva <= start < end <= row.struct.EndAddress and
                                       (not landing or start <= landing < row.struct.EndAddress) and
                                       (filter_ <= 1 or code_sec.contains_rva(filter_))
                                       for start, end, filter_, landing in entries):
                                    for _, _, filter_, landing in entries:
                                        if filter_ > 1:
                                            self.function(filter_)
                                        if landing:
                                            self.resume_sites.add((rva, landing))
            for rva in discover_code_pointers(self.image):
                if code_sec.contains_rva(rva):
                    self.function(rva)
            for rva in self.tls_callbacks:
                if code_sec.contains_rva(rva):
                    self.function(rva)
        for width in (32, 64):
            self.line(f"declare i{width} @llvm.bswap.i{width}(i{width})")
        self.line("declare void @guest_exit(i32) noreturn")
        self.line("declare void @guest_require_register(i8, i8)")
        self.line("declare void @guest_set_cpu(ptr)")
        self.line("declare i64 @guest_create_thread(i64, i64, i64, i64, i32, i64)")
        self.line("declare i64 @guest_GetFinalPathNameByHandleW(i64, i64, i32, i32)")
        self.line("declare i64 @guest_WaitOnAddress(i64, i64, i64, i32)")
        self.line("declare i64 @guest_WakeByAddressSingle(i64)")
        self.line("declare i64 @guest_WakeByAddressAll(i64)")
        self.line("declare i64 @guest_CreateWaitableTimerExW(i64, i64, i32, i32)")
        self.line("declare i64 @guest_CreateWaitableTimerW(i64, i64, i32)")
        self.line("declare i64 @guest_SetWaitableTimer(i64, i64, i32, i64)")
        if module:
            self.line(f"define void @{module}_entry(ptr %cpu, i64 %return_va) {{")
            self.line("entry:")
            self.line(f"  musttail call void @{self.function(entry)}(ptr %cpu, i64 %return_va)")
            self.line("  ret void")
            self.line("}")
            exports = getattr(self.image, "DIRECTORY_ENTRY_EXPORT", None)
            for export in exports.symbols if exports else ():
                if not export.forwarder and code_sec.contains_rva(export.address):
                    self.function(export.address)
        else:
            self.emit_process_entry(entry)
        self.emit_functions(base, code)
        return self.finish_module(prefix)

    def emit_process_entry(self, entry):
        self.line("define i32 @lifted_console() {")
        self.line("entry:")
        count = len(self.cpu_slots)
        self.line(f"  %cpu = alloca [{count * 2} x i64], align 8")
        self.line(f"  store [{count * 2} x i64] zeroinitializer, ptr %cpu, align 8")
        self.cpu_pointers()
        self.line("  call void @guest_set_cpu(ptr %cpu)")
        for name in NONVOLATILE:
            self.write_reg(name, 64, "0")
        for index in range(6, 16):
            self.line(f"  store i8 128, ptr %xmm{index}_0_width")
        initial = 0x2000000 + 1048576 - 40
        self.write_reg("rsp", 64, str(initial))
        if self.bound_slots:
            # Load and attach statically imported guest DLLs before TLS callbacks and the entry point.
            self.line(f"  call void @guest_store(i64 {initial}, i64 0, i32 8)")
            self.line("  call void @guest_bind_imports()")
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

    def emit_functions(self, base, code):
        while self.function_queue:
            target = self.function_queue.pop()
            if target in self.overrides:
                self.emit_override(target, self.overrides[target])
                continue
            self.current = target
            self.blocks, self.pending = {}, []
            self.zero = self.carry = self.signed = self.overflow = False
            self.defined = {}
            self.line(f"define internal void @{self.functions[target]}(ptr %cpu, i64 %return_va) {{")
            self.line("entry:")
            self.cpu_pointers()
            self.emit_body(target, base, code, finalize=False)
        # Compile post-call entries for frames that survive a nonlocal transfer.
        # Freeze the original sites so a continuation cannot enqueue duplicates.
        for owner, address in sorted(self.resume_sites):
            if address in self.functions:
                continue
            symbol = f"guest_resume_{address:x}"
            self.functions[address] = symbol
            self.current = owner
            self.blocks, self.pending = {}, []
            self.zero = self.carry = self.signed = self.overflow = False
            self.defined = {}
            self.line(f"define internal void @{symbol}(ptr %cpu, i64 %return_va) {{")
            self.line("entry:")
            self.cpu_pointers()
            self.emit_body(address, base, code, finalize=False)
        for raw_val, name in sorted(self.iat_thunks.items()):
            if raw_val not in self.functions:
                clean_name = "".join(c if c.isalnum() else "_" for c in name)
                fn_name = f"guest_iat_{raw_val:x}_{clean_name}"
                self.functions[raw_val] = fn_name
                self.line(f"define internal void @{fn_name}(ptr %cpu, i64 %return_va) {{")
                self.line("entry:")
                if (self.module_base or self.bound_dlls) and raw_val in self.foreign_thunks:
                    slot = self.module_base + self.foreign_thunks[raw_val]
                    self.line(f"  %target = call i64 @guest_load(i64 {slot}, i32 8)")
                    self.line("  call i64 @guest_indirect_dispatch(ptr %cpu, i64 %target, i64 %return_va, i32 1)")
                    self.line("  ret void")
                    self.line("}")
                    continue
                self.line("  %rcx_ptr = getelementptr inbounds i64, ptr %cpu, i64 1")
                self.line("  %rcx = load i64, ptr %rcx_ptr")
                self.line("  %rdx_ptr = getelementptr inbounds i64, ptr %cpu, i64 2")
                self.line("  %rdx = load i64, ptr %rdx_ptr")
                self.line("  %r8_ptr = getelementptr inbounds i64, ptr %cpu, i64 3")
                self.line("  %r8 = load i64, ptr %r8_ptr")
                self.line("  %r9_ptr = getelementptr inbounds i64, ptr %cpu, i64 4")
                self.line("  %r9 = load i64, ptr %r9_ptr")
                if name in {"WideCharToMultiByte", "MultiByteToWideChar"}:
                    wide = int(name == "MultiByteToWideChar")
                    self.line("  %rsp_ptr_arg = getelementptr inbounds i64, ptr %cpu, i64 7")
                    self.line("  %rsp_arg = load i64, ptr %rsp_ptr_arg")
                    self.line("  %dest_ptr = add i64 %rsp_arg, 40")
                    self.line("  %dest = call i64 @guest_load(i64 %dest_ptr, i32 8)")
                    self.line("  %size_ptr = add i64 %rsp_arg, 48")
                    self.line("  %size = call i64 @guest_load(i64 %size_ptr, i32 4)")
                    self.line("  %rcx32 = trunc i64 %rcx to i32")
                    self.line("  %rdx32 = trunc i64 %rdx to i32")
                    self.line("  %r9_32 = trunc i64 %r9 to i32")
                    self.line(f"  %res = call i64 @guest_convert_text(i32 {wide}, i32 %rcx32, i32 %rdx32, i64 %r8, i32 %r9_32, i64 %dest, i64 %size)")
                elif name == "RtlVirtualUnwind":
                    self.line("  %stack_slot = getelementptr i64, ptr %cpu, i64 7")
                    self.line("  %stack = load i64, ptr %stack_slot")
                    self.line("  %kind = trunc i64 %rcx to i32")
                    for index in range(4):
                        self.line(f"  %slot{index} = add i64 %stack, {40 + index * 8}")
                        self.line(f"  %arg{index} = call i64 @guest_load(i64 %slot{index}, i32 8)")
                    self.line("  %res = call i64 @guest_rtl_virtual_unwind(i32 %kind, i64 %rdx, i64 %r8, i64 %r9, i64 %arg0, i64 %arg1, i64 %arg2, i64 %arg3)")
                elif name == "NtReadFile":
                    self.line("  %rsp_arg = getelementptr inbounds i64, ptr %cpu, i64 7")
                    self.line("  %stack = load i64, ptr %rsp_arg")
                    self.line("  %stack_args = add i64 %stack, 40")
                    self.line("  %res = call i64 @guest_nt_read_file(i64 %rcx, i64 %rdx, i64 %r8, i64 %r9, i64 %stack_args)")
                elif name in FLS_IMPORTS:
                    target = FLS_IMPORTS[name]
                    self.line(f"  %res = call i64 @guest_indirect_call(i64 {target}, i64 %rcx, i64 %rdx, i64 %r8, i64 %r9)")
                elif name == "malloc":
                    self.line("  %res = call i64 @guest_malloc(i64 %rcx)")
                elif name == "free":
                    self.line("  %res = call i64 @guest_free(i64 %rcx)")
                elif name == "calloc":
                    self.line("  %res = call i64 @guest_calloc(i64 %rcx, i64 %rdx)")
                elif name == "realloc":
                    self.line("  %res = call i64 @guest_realloc(i64 %rcx, i64 %rdx)")
                elif name == "strlen":
                    self.line("  %res = call i64 @guest_strlen(i64 %rcx)")
                elif name == "strcmp":
                    self.line("  %res = call i64 @guest_strcmp(i64 %rcx, i64 %rdx)")
                elif name == "strncmp":
                    self.line("  %res = call i64 @guest_strncmp(i64 %rcx, i64 %rdx, i64 %r8)")
                elif name == "strcpy":
                    self.line("  %res = call i64 @guest_strcpy(i64 %rcx, i64 %rdx)")
                elif name in {"_strdup", "strdup"}:
                    self.line("  %res = call i64 @guest_strdup(i64 %rcx)")
                elif name == "memset":
                    self.line("  %rdx32 = trunc i64 %rdx to i32")
                    self.line("  %res = call i64 @guest_memset(i64 %rcx, i32 %rdx32, i64 %r8)")
                elif name in {"memcpy", "memmove"}:
                    self.line("  %res = call i64 @guest_memcpy(i64 %rcx, i64 %rdx, i64 %r8)")
                elif name == "memcmp":
                    self.line("  %res = call i64 @guest_memcmp(i64 %rcx, i64 %rdx, i64 %r8, i64 0)")
                elif name == "memchr":
                    self.line("  %rdx32 = trunc i64 %rdx to i32")
                    self.line("  %res = call i64 @guest_memchr(i64 %rcx, i32 %rdx32, i64 %r8, i64 0)")
                elif name == "strchr":
                    self.line("  %rdx32 = trunc i64 %rdx to i32")
                    self.line("  %res = call i64 @guest_strchr(i64 %rcx, i32 %rdx32, i64 0, i64 0)")
                elif name == "strrchr":
                    self.line("  %rdx32 = trunc i64 %rdx to i32")
                    self.line("  %res = call i64 @guest_strrchr(i64 %rcx, i32 %rdx32, i64 0, i64 0)")
                elif name == "strstr":
                    self.line("  %res = call i64 @guest_strstr(i64 %rcx, i64 %rdx, i64 0, i64 0)")
                elif name == "qsort":
                    self.line("  %res = call i64 @guest_qsort(i64 %rcx, i64 %rdx, i64 %r8, i64 %r9)")
                elif name in GENERATED_SHIMS:
                    self.line(f"  %res = call i64 @guest_{name}(i64 %rcx, i64 %rdx, i64 %r8, i64 %r9)")
                else:
                    self.line(f"  %res = call i64 @guest_indirect_call(i64 {raw_val + self.module_base}, i64 %rcx, i64 %rdx, i64 %r8, i64 %r9)")
                self.line("  store i64 %res, ptr %cpu")
                self.line("  %rsp_ptr = getelementptr inbounds i64, ptr %cpu, i64 7")
                self.line("  %rsp = load i64, ptr %rsp_ptr")
                self.line("  call void @guest_check_return(i64 %rsp, i64 %return_va)")
                self.line("  %rsp_new = add i64 %rsp, 8")
                self.line("  store i64 %rsp_new, ptr %rsp_ptr")
                self.line("  ret void")
                self.line("}")

    def emit_override(self, target, name):
        """Emit a function whose body calls the runtime's implementation of name."""
        self.line(f"define internal void @{self.functions[target]}(ptr %cpu, i64 %return_va) {{")
        self.line("entry:")
        if name is None:
            self.line("  store i64 1, ptr %cpu")
        else:
            cache = f"@guest_override_cache_{target:x}"
            self.override_caches.append(cache)
            label = self.string_constant(name)
            for index, register in enumerate(("rcx", "rdx", "r8", "r9"), 1):
                self.line(f"  %{register}_ptr = getelementptr inbounds i64, ptr %cpu, i64 {index}")
                self.line(f"  %{register} = load i64, ptr %{register}_ptr")
            self.line(f"  %res = call i64 @guest_named_call(ptr {cache}, ptr @{label}, "
                      "i64 %rcx, i64 %rdx, i64 %r8, i64 %r9)")
            self.line("  store i64 %res, ptr %cpu")
        self.line("  %rsp_ptr = getelementptr inbounds i64, ptr %cpu, i64 7")
        self.line("  %rsp = load i64, ptr %rsp_ptr")
        self.line("  call void @guest_check_return(i64 %rsp, i64 %return_va)")
        self.line("  %rsp_new = add i64 %rsp, 8")
        self.line("  store i64 %rsp_new, ptr %rsp_ptr")
        self.line("  ret void")
        self.line("}")

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
        if entry == 0x87460:
            self.line("  call void @guest_stack_smash_trap(i64 %return_va)")
        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        decoder.detail = True
        self.jump(entry, ())
        while self.pending:
            state = self.pending.pop()
            address, returns, defined, self.zero, self.carry, self.signed, self.overflow = state
            bound = self.runtime_functions.get(self.current) if self.shared else None
            if bound and not (self.current <= address < bound):
                self.line(f"{self.blocks[state]}:")
                if address in self.functions:
                    self.line(f"  musttail call void @{self.function(address)}(ptr %cpu, i64 %return_va)")
                    self.line("  ret void")
                else:
                    self.return_to_caller(returns)
                continue
            self.defined = dict(defined)
            self.line(f"{self.blocks[state]}:")
            ins = self.decoded.get(address)
            if ins is None:
                offset = address - base
                if not 0 <= offset < len(code):
                    message = f"console target outside entry section at RVA {address:#x}"
                    if not self.tolerant:
                        raise ValueError(message)
                    self.trap(message)
                    continue
                ins = next(decoder.disasm(code[offset:offset + 15], address, count=1), None)
                if ins is None:
                    message = f"cannot decode console target RVA {address:#x}"
                    if not self.tolerant:
                        raise ValueError(message)
                    self.trap(message)
                    continue
                instruction_bytes = range(address, address + ins.size)
                if any(self.occupied.get(byte, address) != address for byte in instruction_bytes):
                    message = f"overlapping console instructions at RVA {address:#x}"
                    if not self.tolerant:
                        raise ValueError(message)
                    self.trap(message)
                    continue
                self.occupied.update(dict.fromkeys(instruction_bytes, address))
                self.decoded[address] = ins
            if self.trace:
                self.line(f"  call void @guest_set_pc(i64 {address})")
            if self.fault_delivery:
                self.line(f"  call void @guest_mark_fault_pc(i64 {self.image_base + address})")
            if self.fault_delivery and self.trace and ins.mnemonic == "call":
                self.resume_sites.add((self.current, address + ins.size))
            checkpoint = len(self.lines)
            try:
                self.step(ins, returns)
            except ValueError as error:
                message = f"RVA {ins.address:#x} ({ins.mnemonic} {ins.op_str}): {error}"
                if not self.tolerant:
                    raise ValueError(message) from error
                del self.lines[checkpoint:]
                self.trap(message)
        self.line("}")
        if finalize:
            return self.finish_module()

    def finish_module(self, prefix=""):
        self.line("declare i64 @guest_indirect_dispatch(ptr, i64, i64, i32)")
        if self.overrides:
            self.line("declare i64 @guest_named_call(ptr, ptr, i64, i64, i64, i64)")
        for cache in getattr(self, "override_caches", ()):
            self.line(f"{cache} = internal global i64 0")
        entries = sorted(self.functions.keys())
        table_kind = f"[{len(entries)} x {{ i64, ptr }}]"
        table_items = [f"{{ i64, ptr }} {{ i64 {addr + self.module_base}, ptr @{self.functions[addr]} }}" for addr in entries]
        self.line(f"@{prefix}guest_dispatch_table = constant {table_kind} [{', '.join(table_items)}]")
        self.line(f"@{prefix}guest_dispatch_count = constant i64 {len(entries)}")
        if self.bound_slots and not self.module_base:
            self.line("declare void @guest_bind_imports()")
            slots = ", ".join(f"i64 {slot}" for slot in self.bound_slots)
            self.line(f"@guest_bound_import_slots = constant [{len(self.bound_slots)} x i64] [{slots}]")
            self.line(f"@guest_bound_import_count = constant i64 {len(self.bound_slots)}")
        for message, symbol in self.traps.items():
            data = message.encode() + b"\0"
            content = "".join(f"\\{byte:02x}" for byte in data)
            self.line(f'{symbol} = private constant [{len(data)} x i8] c"{content}"')
        for text, (var_name, length, escaped) in self.strings.items():
            self.line(f'@{var_name} = private unnamed_addr constant [{length} x i8] c"{escaped}", align 1')
        return "\n".join(self.lines) + "\n"


def loader_requirements(image):
    return []


def read_console_image(image, *, load_base=None):
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
    # The main image uses RVAs; DLL pointers use the assigned guest base.
    # Keep the input image unchanged for the byte check and x86 oracle.
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
                    relocated = pointer if load_base is None else load_base + pointer
                    buffers[index][offset:offset + 8] = relocated.to_bytes(8, "little")
                    touched.add(index)
                    break
            else:
                raise ValueError(f"relocation outside mapped data at RVA {fixup.rva:#x}")
    mapped = [(start, bytes(buffers[i]).rstrip(b"\0") if i in touched else blob, size, writable)
              for i, (start, blob, size, writable) in enumerate(ordered)]
    return entry, base, code, mapped


def find_switch_tables(image):
    base = image.OPTIONAL_HEADER.ImageBase
    code = image.get_section_by_rva(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    if not code:
        return {}
    c_start = code.VirtualAddress
    c_end = code.VirtualAddress + code.Misc_VirtualSize
    raw = code.get_data()
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

    switches = {}
    for row in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", ()):
        fn_start = row.struct.BeginAddress
        fn_end = row.struct.EndAddress
        if not (c_start <= fn_start < c_end):
            continue
        off = fn_start - c_start
        size = fn_end - fn_start
        if size <= 0 or off + size > len(raw):
            continue
        insns = list(md.disasm(raw[off:off + size], base + fn_start))
        boundaries = {ins.address - base for ins in insns}
        leas = {}
        for idx, i in enumerate(insns):
            if i.mnemonic == "lea" and "rip" in i.op_str:
                reg = i.op_str.split(",")[0].strip()
                m = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]", i.op_str)
                if m:
                    sign = 1 if m.group(1) == "+" else -1
                    disp = int(m.group(2), 0) * sign
                    table_rva = i.address - base + i.size + disp
                    leas[reg] = table_rva

            table_rva = None
            jmp_ins = None
            scale = 0
            idx_reg = None
            if i.mnemonic == "movsxd" and "4" in i.op_str:
                m = re.search(r"\[(\w+)\s*\+\s*(\w+)", i.op_str)
                if m and m.group(1) in leas:
                    table_rva = leas[m.group(1)]
                    idx_reg = m.group(2)
                    scale = 4
                    target_reg = i.op_str.split(",", 1)[0].strip()
                    for next_i in insns[idx + 1:idx + 9]:
                        if next_i.mnemonic == "jmp" and next_i.op_str == target_reg:
                            jmp_ins = next_i
                            break
            elif i.mnemonic == "jmp" and "8" in i.op_str:
                m = re.search(r"\[(\w+)\s*\+\s*(\w+)", i.op_str)
                if m and m.group(1) in leas:
                    table_rva = leas[m.group(1)]
                    idx_reg = m.group(2)
                    scale = 8
                    jmp_ins = i

            if table_rva and jmp_ins:
                sec = image.get_section_by_rva(table_rva)
                if sec:
                    bound = 256
                    norm_idx = idx_reg.lower().lstrip("r").lstrip("e") if idx_reg else ""
                    clobbered = False
                    for prev in reversed(insns[max(0, idx - 12):idx]):
                        parts = [p.strip() for p in prev.op_str.split(",")]
                        dst = parts[0].lower().lstrip("r").lstrip("e") if parts else ""
                        if prev.mnemonic == "cmp" and not clobbered:
                            if norm_idx and dst == norm_idx:
                                m_cmp = re.search(r",\s*(0x[0-9a-fA-F]+|\d+)", prev.op_str)
                                if m_cmp:
                                    try:
                                        val = int(m_cmp.group(1), 0)
                                        if 0 < val <= 4096:
                                            bound = val + 1
                                            break
                                    except Exception:
                                        pass
                        elif dst == norm_idx and prev.mnemonic not in ("cmp", "test"):
                            clobbered = True
                    t_off = table_rva - sec.VirtualAddress
                    t_data = sec.get_data()
                    targets = set()
                    count = 0
                    while count < bound and t_off + scale <= len(t_data):
                        if scale == 4:
                            diff = struct.unpack_from("<i", t_data, t_off)[0]
                            tgt = table_rva + diff
                        else:
                            tgt = struct.unpack_from("<Q", t_data, t_off)[0] - base
                        if tgt not in boundaries:
                            break
                        targets.add(tgt)
                        t_off += scale
                        count += 1
                    if targets:
                        jmp_rva = jmp_ins.address - base
                        switches.setdefault(jmp_rva, set()).update(targets)

    return switches


def discover_code_pointers(image):
    """Read candidate RVAs from relocated and raw data sections pointing into .text."""
    base = image.OPTIONAL_HEADER.ImageBase
    code = image.get_section_by_rva(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    if not code:
        return set()
    candidates = set()
    for block in getattr(image, "DIRECTORY_ENTRY_BASERELOC", ()):
        for fixup in block.entries:
            if fixup.type != 10:
                continue
            pointer = image.get_qword_at_rva(fixup.rva)
            if pointer is not None and code.contains_rva(pointer - base):
                candidates.add(pointer - base)
    for sec in image.sections:
        name = sec.Name.rstrip(b"\0")
        if name in (b".rdata", b".data", b".rodata"):
            data = sec.get_data()
            if not data:
                continue
            for off in range(0, len(data) - 7, 8):
                val = struct.unpack_from("<Q", data, off)[0]
                if code.contains_rva(val - base):
                    candidates.add(val - base)
    return candidates


def relocated_code_pointers(image):
    return discover_code_pointers(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--trace", action="store_true", help="trap unsupported instructions at runtime")
    parser.add_argument("--stub-unknown", dest="stub_unknown", action=argparse.BooleanOptionalAction, default=True,
                        help="stub unknown Windows imports found in wine_api_db.json")
    args = parser.parse_args()
    try:
        image = pefile.PE(str(args.pe))
        entry, base, code, data = read_console_image(image)
        requirements = loader_requirements(image)
        if requirements:
            raise ValueError(f"unsupported Windows loader requirements: {', '.join(requirements)}")
        ir = ConsoleLift(image, trace=args.trace, stub_unknown=args.stub_unknown).emit_console(entry, base, code, data)
        args.output.write_text(ir)
    except (ValueError, pefile.PEFormatError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
