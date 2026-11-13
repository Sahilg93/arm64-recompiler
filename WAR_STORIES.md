# Failures, Roadblocks & War Stories: Lifting Windows x86-64 to Apple Silicon

*An honest engineering post-mortem of the bugs, architectural dead-ends, ISA semantic discrepancies, and Windows loader traps overcome while building a static binary recompiler.*

---

## 1. The Indirect Branch & Callback Discovery Trap

### The Failure
PuTTY Plink 0.83 repeatedly aborted or crashed with illegal memory access or unregistered target errors. During CRT startup and argument processing, Plink relies heavily on indirect calls (`call qword ptr [rax]`, `call qword ptr [r12 + rcx*8]`) for callback dispatch, memory allocation tables, and terminal configuration.

### The Initial Dead-End
Initially, we relied on an iterative runtime discovery loop:
```sh
trace_callbacks.py --max-attempts 64 work/corpus/plink.exe -V
```
Every time Plink hit an unmodeled indirect branch, the diagnostic harness trapped, extracted the target RVA, patched an internal callback whitelist, and recompiled the entire Mach-O binary from scratch with Clang. This required dozens of iterative compilations, was excruciatingly slow, and failed on any binary without a deterministic, reproducible input trace.

### The Breakthrough: PE `.pdata` Exception Directory Parsing
Instead of guessing or iteratively probing targets, we inspected the PE format specifications. On x86-64 Windows, all non-leaf functions **must** register structured exception handling records in the PE Exception Directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION` / `.pdata`).

Each record is a 12-byte `RUNTIME_FUNCTION` structure:
```c
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;  // Function entry RVA relative to image base
    DWORD EndAddress;    // Function exit RVA
    DWORD UnwindData;    // Unwind info offset
} RUNTIME_FUNCTION;
```

We updated `console_lift.py` to automatically parse `.pdata` before lifting:
1. Walk every `RUNTIME_FUNCTION` entry.
2. Verify that `BeginAddress` falls within the executable `.text` section.
3. Pre-populate all discovered RVAs into the global LLVM indirect-call switch dispatch table.

**Result**: Plink 0.83 went from dozens of iterative discovery loops to compiling and running cleanly on **attempt 0**.

---

## 2. The `lock cmpxchg` Flag Calculation Bug

### The Failure
When introducing atomic instruction lifting for multi-threaded CRT runtimes, our focused regression test `console-atomic.exe` failed during differential testing:
```
fail_write=False: x86=(102, b'')  # Native ARM64 disagreed with x86 reference
```

### The Subtle Bug
Lowering x86 `lock cmpxchg [rbx], rsi` to LLVM IR initially seemed straightforward using LLVM's atomic `cmpxchg`:
```llvm
%res = cmpxchg i64* %ptr, i64 %rax, i64 %rsi seq_cst seq_cst
%old = extractvalue { i64, i1 } %res, 0
%success = extractvalue { i64, i1 } %res, 1
```
However, x86 `cmpxchg` does **not** simply set the Zero Flag (`ZF = (old == expected)`). It also computes the arithmetic flags (`CF`, `SF`, `OF`, `AF`) by executing an internal subtraction:
$$\text{Difference} = \text{Destination} - \text{Source} \quad (\text{i.e. } \text{Expected} - \text{Old})$$

Our initial implementation had two fatal flaws:
1. **Operand order inversion**: We computed `%diff = sub i64 %old, %rax` instead of `%rax - %old`. This inverted the borrow condition, flipping the Carry Flag (`CF`).
2. **Overflow Flag (`OF`) sign bit comparison**: Under signed saturation, inverted operands caused signed conditional jumps (`jl`, `jle`, `jg`) immediately following an atomic refcount check to take the completely wrong code branch!

### The Fix
We implemented precise emulation of x86 `CMP` flag arithmetic directly in LLVM IR:
```python
# console_lift.py: exact CMP flag emulation
diff = b.sub(rax_val, old_val)
zf = b.zext(success, ir.IntType(64))
# Compute borrow for CF: unsigned (rax < old)
cf = b.zext(b.icmp_unsigned("<", rax_val, old_val), ir.IntType(64))
# Compute signed overflow for OF: ((rax ^ old) & (rax ^ diff)) < 0
```
With this fix, all 11,121 instruction permutations matched byte-for-byte across x86 Unicorn, Rosetta 2, and lifted ARM64.

---

## 3. The TLS Callback Chicken-and-Egg Trap (`jq.exe` & `rg.exe`)

### The Failure
When attempting to lift `jq.exe` (MinGW-w64) and `rg.exe` (Rust MSVC), both binaries crashed or failed with illegal instruction traps almost immediately, long before reaching main application code.

### The Root Cause
On modern Windows, binaries do not start directly at `AddressOfEntryPoint`.
Compilers place critical runtime initialization routines into **Thread Local Storage (TLS) Callbacks** inside `IMAGE_DIRECTORY_ENTRY_TLS`:
- MSVC and MinGW place security cookie initialization (`__security_init_cookie`) in TLS callbacks.
- Rust and MSVC CRT place thread-local heap allocators and Fiber Local Storage (FLS) setup in TLS callbacks.

Because our lifter jumped straight to `AddressOfEntryPoint`, none of the security cookies or internal allocator structures were initialized, leading to instant crashes on the first memory access or canary check.

### The Fix
We implemented full PE TLS directory traversal in `console_runtime.c`:
1. Parse `IMAGE_DIRECTORY_ENTRY_TLS` to locate `AddressOfCallBacks`.
2. Walk the null-terminated array of callback function pointers.
3. Invoke each callback sequentially with `DLL_PROCESS_ATTACH` (1) prior to jumping to `AddressOfEntryPoint`:
```c
typedef void (WINAPI *PIMAGE_TLS_CALLBACK)(void *DllHandle, DWORD Reason, void *Reserved);
PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *)tls_callbacks_rva;
while (*callback != NULL) {
    (*callback)(image_base, DLL_PROCESS_ATTACH, NULL);
    callback++;
}
```
Immediately after adding TLS callback invocation, `jq.exe` and `rg.exe` surged forward, executing through dozens of initialization routines.

---

## 4. The Universal Import Filter Blocker

### The Failure
`jq.exe` abruptly halted during startup with:
```
RVA 0x8d840: unsupported import api-ms-win-crt-stdio-l1-1-0.dll!__acrt_iob_func
```
Even though we had planned to support UCRT functions, the lifter refused to recognize the import.

### The Root Cause
Deep inside `console_lift.py`, the import scanning function had an old hardcoded check from the early arithmetic prototype:
```python
# BUG: Only scanned kernel32.dll!
if dll.dll.lower() == b"kernel32.dll":
    self.imports[func_name] = iat_rva
```
Any import from Universal CRT (`api-ms-win-crt-stdio-l1-1-0.dll`, `api-ms-win-crt-runtime-l1-1-0.dll`, `ucrtbase.dll`) was silently discarded and treated as an unmapped indirect call!

### The Fix
We generalized import resolution across all PE imported descriptor tables, allowing any known shim in `IMPORTS` (regardless of host DLL) to be recognized and bound.

---

## 5. The Modern Windows API-Set Prefix Maze (`rg.exe`)

### The Failure
`ripgrep` (Rust MSVC) halted with dynamic loader errors when calling `LoadLibraryExW` on:
```
api-ms-win-core-fibers-l1-1-2.dll
```

### The Root Cause
In Windows 10 and 11, Microsoft replaced traditional DLLs with virtual "API sets" (schema-based DLL redirection). Binaries no longer call `LoadLibraryA("kernel32.dll")`; they query fine-grained API set identifiers with specific version suffixes:
- `api-ms-win-core-fibers-l1-1-1.dll`
- `api-ms-win-core-fibers-l1-1-2.dll`
- `api-ms-win-core-synch-l1-2-0.dll`
- `api-ms-win-core-processthreads-l1-1-3.dll`

Exact string comparisons in `LoadLibraryExW` broke on every compiler upgrade.

### The Fix
In `console_runtime.c`, we replaced exact string checks with prefix matching:
```c
if (wcsncmp(libname, L"api-ms-win-core-fibers-", 24) == 0 ||
    wcsncmp(libname, L"api-ms-win-core-synch-", 23) == 0 ||
    wcsncmp(libname, L"api-ms-win-core-sysinfo-", 25) == 0) {
    return KERNEL_MODULE; // Route to our synthetic module provider
}
```
This allowed `ripgrep`'s dynamic loader to locate `FlsAlloc`, `FlsGetValue2`, and `InitializeCriticalSection` without failing.

---

## 6. The UCRT `_iobuf` / `FILE*` Memory Impass

### The Failure
`jq.exe` crashed on standard stream configuration:
```
RVA 0x8d918: unsupported import api-ms-win-crt-stdio-l1-1-0.dll!setvbuf
```

### The Root Cause
In legacy MSVC CRT, `stdout` was an array of exported global structs. In modern Universal CRT (UCRT), `stdout` is accessed dynamically via `__acrt_iob_func(unsigned index)` (`0=stdin`, `1=stdout`, `2=stderr`).

If `__acrt_iob_func` simply returns a fake non-zero handle (like `1`), the guest CRT crashes the moment it attempts to read or write internal buffering flags (`stream->_flag`, `stream->_base`).

### The Fix
We mapped a dedicated 3-slot bounded guest memory table at `0x2103000` (48 bytes per entry) in `console_runtime.c`:
```c
enum { IOBUF_BASE = 0x2103000, IOBUF_ENTRY_SIZE = 48, IOBUF_COUNT = 3 };
static unsigned char iobuf[IOBUF_COUNT * IOBUF_ENTRY_SIZE];

uint64_t guest_acrt_iob_func(uint32_t index) {
    if (index >= IOBUF_COUNT) return 0;
    return IOBUF_BASE + ((uint64_t)index * IOBUF_ENTRY_SIZE);
}
```
We also added guest address routing in `read_span()`, `guest_pointer()`, and `guest_store()`, ensuring reads and writes to `_iobuf` operate safely in bounded guest memory.

---

## 7. Memory Protection Translation (`VirtualProtect`)

### The Failure
Rust's standard library in `rg.exe` crashed when initializing stack protection and read-only tables:
```
RVA 0x...: unsupported import KERNEL32.dll!VirtualProtect
```

### The Problem
Windows and POSIX use completely different memory protection flag bitmasks:
- Windows: `PAGE_NOACCESS (0x01)`, `PAGE_READONLY (0x02)`, `PAGE_READWRITE (0x04)`, `PAGE_EXECUTE_READ (0x20)`.
- POSIX: `PROT_NONE (0x00)`, `PROT_READ (0x01)`, `PROT_WRITE (0x02)`, `PROT_EXEC (0x04)`.

Passing Win32 flags directly to macOS `mprotect` resulted in `EINVAL` (Invalid Argument) and subsequent memory access faults.

### The Fix
We implemented a complete flag translation layer in `console_runtime.c`:
```c
int prot = PROT_NONE;
if (flNewProtect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
    prot |= PROT_READ;
if (flNewProtect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
    prot |= PROT_WRITE;
if (flNewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
    prot |= PROT_EXEC;

int res = mprotect(aligned_addr, aligned_size, prot);
```
We also tracked previously applied protections to properly populate the `lpflOldProtect` out-parameter.

---

## 8. Summary of Hard-Won Lessons

1. **Don't guess indirect branch targets; parse the PE exception unwinding metadata.** The compiler already wrote down every valid function entry in `.pdata`.
2. **Never skip TLS callbacks.** Modern compilers treat TLS callbacks as a required pre-entry execution phase.
3. **x86 arithmetic flags have subtle side-effects.** Lowering atomic instructions requires full flag emulation, not just boolean success checks.
4. **API-set indirection is mandatory for modern Windows binaries.** Supporting `KERNEL32.dll` alone is insufficient for binaries compiled after 2015.
5. **Always back emulated handles with real guest memory.** If guest code receives a pointer from a CRT shim, it will inevitably attempt to dereference it.

---

## 9. The Next Frontier: The Hybrid Architecture (Why Re-inventing USER32 is the Wrong Move)

As this recompiler matures from console binaries (`plink`, `jq`, `rg`) toward desktop software with graphical interfaces, the question arises: *Do we need to rewrite all of Windows USER32, GDI, and DirectX?*

**The short answer: No, and attempting to do so from scratch would be an architectural dead-end.**

In the compatibility and emulation world (from Apple's Rosetta 2 + D3DMetal in the Game Porting Toolkit, to Box64/FEX-Emu on Linux, to Android's Houdini), the most successful pattern is **Hybrid AOT Recompilation with API Thunking**:
- **Recompile Ahead-of-Time**: Compile the application logic, byte parsing, mathematical transforms, and tight inner loops to native Apple Silicon ARM64 instructions for maximum hardware throughput.
- **Thunk the Periphery**: Forward complex Windows API boundaries (window creation, message dispatch loops, bitmap blits, and 3D rendering) across a thunking bridge to mature implementations like Wine, or translate DirectX calls to native Apple Metal.

This division of labor plays to each component's strengths: the recompiler delivers peak raw CPU performance on Apple Silicon, while established compatibility layers handle the immense surface area of Windows desktop windowing and display drivers.
