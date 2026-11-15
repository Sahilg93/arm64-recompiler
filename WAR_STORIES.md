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

## 8. The Pointer That Was Not Equal to Itself (PuTTY's Key Exchange)

### The Failure
Lifted Plink connected to an OpenSSH server, exchanged version strings, and then died on one of PuTTY's own assertions:
```
Assertion failed: false && "don't have a name for this classical alg", file .../crypto/kex-hybrid.c, line 44
```
The code behind it is a plain chain of pointer comparisons: `if (alg->classical == &ssh_ec_kex_curve25519) ... else if (... == &ssh_ec_kex_nistp256) ...`. Every comparison failed, although the static data was correct.

### The Root Cause
A debugger showed the pointer in `rcx` was `0xc1de0`: an image-relative address with no image base. The lifter had inherited an early design in which the main program's addresses were RVAs. Code had since moved to real guest addresses (`lea` yields image base + RVA), but the loader step that applies base relocations to the program's *data* still rewrote every stored pointer to an RVA. The runtime accepts both forms when it reads memory, so loads and calls through such pointers worked and nothing noticed.

What cannot work is equality. A pointer read from a static table (an RVA) never equals the address the code computes for the same object (a real address).

### The Fix
`build_console_modules.py` now relocates the program's data to its real load address, exactly as lifted DLLs already were. Any program that compares a stored pointer with a computed one was affected; PuTTY was simply the first to assert on it.

---

## 9. The Function That Returned Halfway Through (Chained Unwind Ranges)

### The Failure
The PuTTY GUI opened its configuration dialog, but starting a session aborted with the runtime's stack check:
```
guest return address mismatch
actual 0x104f5b230 != expected 0x140035137 at rsp 0x104f5b050
```
A function had returned without running its epilogue.

### The Root Cause
The culprit was an SSE2 string routine from the MSVC CRT. Two things had to line up to expose it.

First, the routine dispatches through a jump table in the standard MSVC form: a table of image-relative addresses, `mov ecx, [rbase + index*4 + table]; add rcx, rbase; jmp rcx`. The lifter did not recognise that form, so the jump fell into the fallback x86 interpreter, which stopped on the first `psrldq`. That failure hid everything behind it.

Second, once the table was recovered and the routine ran as lifted code, the real bug appeared. MSVC splits one function into several unwind ranges (`.pdata` entries) that jump into each other's middles. The lifter bounds each lifted function by its unwind range, and a jump that left the range to an address that was not a known function start was emitted as *return to caller*. A conditional branch into the next fragment therefore became a `ret` with 0x28 bytes still on the stack.

### The Fix
- `find_switch_tables` recovers the MSVC image-relative table, including when the image-base register was loaded in a parent fragment.
- A jump into the middle of another unwind range now lifts the rest of that range as a function of its own and tail-calls it.
- The return-address check reports the last traced guest address. That single line is what located the bug.

---

## 10. Critical Sections That Were Not Locks

### The Failure
Plink's raw TCP session printed the server's greeting and then aborted with `unsupported critical section ownership state`.

### The Root Cause
The runtime's `EnterCriticalSection` updated the owner and recursion fields in guest memory and trapped if another thread already owned the section. That was a deliberate early simplification, and it held as long as no two threads ever wanted the same section at once. Plink reads standard input on a second thread, and in a live session that thread and the main thread met on one section.

### The Fix
Critical sections are real locks. The owner field is claimed with a compare-and-swap directly in guest memory, so the uncontended path takes no host lock. A thread that finds the section owned waits on a shared condition variable, which a leaving owner signals only when a waiter is registered. `TryEnterCriticalSection` uses the same compare-and-swap and no longer races between its check and its enter.

---

## 11. The Build Machine That Deleted the Source

### The Failure
In the middle of a session, `grep` on a 270 KB source file hung forever. So did `clang`, and then the lifted program itself, silently, before printing anything.

### The Root Cause
The repository lived in an iCloud-synced `Documents` folder on a nearly full disk. macOS had uploaded files and evicted the local copies: `ls -lO` showed `console_runtime.c`, `console_lift.py` and one of the freshly built module libraries as `dataless`. Any read blocks until the file is downloaded again, and `dlopen` of an evicted library blocks the same way.

### The Fix
`brctl download <file>` brings a file back. The shared module store moved out of the source tree to `~/Library/Caches/arm64-recompiler/modules`: it is a per-user cache of large binaries, which is exactly what a sync service evicts first. The lesson is not specific to this project, but it meant chasing a "hang" in code that was never running.

---

## 12. Summary of Hard-Won Lessons

1. **Don't guess indirect branch targets; parse the PE exception unwinding metadata.** The compiler already wrote down every valid function entry in `.pdata`.
2. **Never skip TLS callbacks.** Modern compilers treat TLS callbacks as a required pre-entry execution phase.
3. **x86 arithmetic flags have subtle side-effects.** Lowering atomic instructions requires full flag emulation, not just boolean success checks.
4. **API-set indirection is mandatory for modern Windows binaries.** Supporting `KERNEL32.dll` alone is insufficient for binaries compiled after 2015.
5. **Always back emulated handles with real guest memory.** If guest code receives a pointer from a CRT shim, it will inevitably attempt to dereference it.
6. **A pointer has one representation.** Accepting two forms of the same address on reads hides the bug until something compares them.
7. **An unwind range is not a function.** MSVC splits functions into chained ranges; a jump out of one is a jump, not a return.
8. **A simplification that traps is a debt with a due date.** The single-threaded critical section was fine until the first second thread.
9. **Make the failure name the place.** Reporting the last traced address on a stack mismatch, and the name of an unimplemented stub, turned hour-long hunts into single runs.

---

## 13. The Next Frontier: The Hybrid Architecture (Why Re-inventing USER32 is the Wrong Move)

As this recompiler matures from console binaries (`plink`, `jq`, `rg`) toward desktop software with graphical interfaces, the question arises: *Do we need to rewrite all of Windows USER32, GDI, and DirectX?*

**The short answer: No, and attempting to do so from scratch would be an architectural dead-end.**

In the compatibility and emulation world (from Apple's Rosetta 2 + D3DMetal in the Game Porting Toolkit, to Box64/FEX-Emu on Linux, to Android's Houdini), the most successful pattern is **Hybrid AOT Recompilation with API Thunking**:
- **Recompile Ahead-of-Time**: Compile the application logic, byte parsing, mathematical transforms, and tight inner loops to native Apple Silicon ARM64 instructions for maximum hardware throughput.
- **Thunk the Periphery**: Forward complex Windows API boundaries (window creation, message dispatch loops, bitmap blits, and 3D rendering) across a thunking bridge to mature implementations like Wine, or translate DirectX calls to native Apple Metal.

This division of labor plays to each component's strengths: the recompiler delivers peak raw CPU performance on Apple Silicon, while established compatibility layers handle the immense surface area of Windows desktop windowing and display drivers.

**Update:** the GUI half now exists as hosted mode (`wine-host/`). It goes further than thunking: Wine's Windows-side DLLs are lifted with the program, and only Wine's unix-side syscall layer runs as native code. Stories 8 to 11 above come from getting the PuTTY GUI and SSH working on it.
