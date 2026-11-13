# Windows x64 to Apple Silicon Recompiler

This project recompiles original Windows x86-64 PE binaries into LLVM IR and compiles that IR into native macOS ARM64 Mach-O executables and libraries.

The primary whole-program milestone is the original Windows release of **PuTTY Plink 0.83**, which runs `-V` natively on Apple Silicon through full CRT startup, argument parsing, standard output, and process shutdown. Its native output matches the original Windows binary running under Wine and Rosetta byte-for-byte, exiting status 0 with a **6.20× speedup** (42.31 ms vs. 262.23 ms) and a **68.9% smaller memory footprint** (5.51 MB vs. 17.74 MB RSS).

---

## Directory Overview

| Path | Contents |
| --- | --- |
| [`console_lift.py`](console_lift.py) | Whole-program PE x86-64 lifter emitting LLVM IR |
| [`console_runtime.c`](console_runtime.c) | Minimal Win32 / CRT runtime shim (memory, TEB/PEB, TLS, FLS, sync, stdio) |
| [`../../work/corpus/`](../../work/corpus/) | Original Windows x64 release binaries (`plink.exe`, `jq.exe`, `rg.exe`) |
| [`../../work/`](../../work/) | Test environments, diagnostic traces, and generated builds |

---

## Quickstart & Verification

From the project root on an Apple Silicon Mac with Clang and Python:

### 1. Run the Regression Test Suite
Exercises 11,121 arithmetic & control-flow instruction permutations, atomic `lock cmpxchg`, data relocations, and console tests:
```sh
PYTHON="$PWD/work/venv/bin/python3" outputs/arm64-recompiler/run.sh
```

### 2. Reproduce the Plink Milestone
Recompiles the original `plink.exe` and verifies `-V` output and exit status:
```sh
PYTHON="$PWD/work/venv/bin/python3" \
  outputs/arm64-recompiler/test_plink_startup.sh "$PWD/work/corpus/plink.exe"
```
With automatic `.pdata` function discovery, this succeeds on **attempt 0**, printing `plink: Release 0.83` and exiting with status 0.

### 3. Trace Startup of Corpus Binaries
Trace native execution and inspect the stopping point for other Windows binaries:
```sh
# jq 1.7.1
$PWD/work/venv/bin/python3 outputs/arm64-recompiler/trace_callbacks.py --max-attempts 1 work/corpus/jq.exe --version

# ripgrep 14.1.1
$PWD/work/venv/bin/python3 outputs/arm64-recompiler/trace_callbacks.py --max-attempts 1 work/corpus/rg.exe --version
```

---

## Performance Milestone (Plink `-V`)

Measurements taken on Apple Silicon across 30 runs per variant (after 2 warmups) with optimized static ARM64 Mach-O:

| Variant | Min / Median / P95 Latency | Speedup vs. Wine | Peak RSS |
| --- | ---: | ---: | ---: |
| **Recompiled Native ARM64 (`-O2`)** | **41.72 / 42.31 / 44.04 ms** | **6.20×** | **5.51 MB** |
| Original Windows binary (Wine + Rosetta) | 248.24 / 262.23 / 383.70 ms | 1.00× | 17.74 MB |
| Upstream macOS ARM64 build | 6.87 / 7.41 / 7.98 ms | 35.39× | 2.23 MB |

Both the recompiled ARM64 executable and Wine + Rosetta matched stdout byte-for-byte and exited with status 0.

---

## Architecture & Lifter Capabilities

### Whole-Program Lifter (`console_lift.py`)
- **PE Decoding & IR Generation**: Uses Capstone to decode x86-64 instructions into LLVM IR functions that share unified register/flag context across guest calls.
- **Automatic `.pdata` Function Discovery**: Parses the PE Exception Directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION` / `RUNTIME_FUNCTION` entries) to automatically extract and register valid function entry RVAs in the runtime indirect-call dispatch table.
- **Atomics**: Supports `lock cmpxchg` (32-bit and 64-bit `r/m, reg`) lowered to LLVM atomic `cmpxchg seq_cst` with exact x86 `CMP` flag emulation (`ZF`, `CF`, `SF`, `OF`).
- **Cross-DLL Import Resolution**: Resolves imports across multiple DLLs (`KERNEL32.dll`, `api-ms-win-crt-*`, etc.), mapping them to runtime implementations or dispatch stubs.
- **Call & Return Integrity**: Simulates the x86 stack return slot and validates return target consistency before executing returns.

### Runtime Environment (`console_runtime.c`)
- **TLS & Callbacks**: Parses PE `IMAGE_DIRECTORY_ENTRY_TLS` and executes TLS callback routines (`DLL_PROCESS_ATTACH`) before the program entry point.
- **Fiber Local Storage (FLS)**: Full support for `FlsAlloc`, `FlsFree`, `FlsGetValue`, `FlsSetValue`, and `FlsGetValue2`.
- **Memory & Protection**: Emulates bounded guest sections, heap (`HeapAlloc`, `HeapReAlloc`, `HeapFree`), and `VirtualProtect` (mapping Win32 page protections to POSIX `mprotect`).
- **Synchronization**: Emulates critical sections (`InitializeCriticalSection`, `InitializeCriticalSectionAndSpinCount`, `EnterCriticalSection`, `LeaveCriticalSection`, `DeleteCriticalSection`).
- **Dynamic API Sets**: Prefix-based routing in `LoadLibraryExW` / `GetModuleHandleW` for `api-ms-win-core-*` (fibers, synch, localization, datetime, processthreads, sysinfo).
- **UCRT Stdio**: Implements `__acrt_iob_func` with standard stream `_iobuf` structures (`stdin`, `stdout`, `stderr`), `_errno`, `fwrite`, `fputs`, `fflush`, `fputc`, `putchar`, and `puts`.
- **Environment & Process Setup**: Emulates `GetCommandLineW`, `CommandLineToArgvW`, `GetEnvironmentStringsW`, `GetModuleHandleW`, and `GetProcAddress`.

---

## Corpus Status & Support Frontier

| Binary | Startup Status | Current Frontier / Stopping Point |
| --- | --- | --- |
| **`plink.exe`** (0.83) | **Fully functional (`-V`)** | Prints `plink: Release 0.83` and exits 0 on attempt 0. |
| **`jq.exe`** (1.7.1) | Advanced past TLS, atomics, and CRT initialization | Reaches `api-ms-win-crt-stdio-l1-1-0.dll!setvbuf` (RVA `0x8d918`). |
| **`rg.exe`** (14.1.1) | Advanced past TLS, API-set loading, and FLS | Reaches `KERNEL32.dll!AddVectoredExceptionHandler` (RVA `0x10467c`). |

---

## Additional Documentation

- [Start Here & Quick Reference](START.md) — Detailed environment setup and command-line usage.
- [Corpus Audit Notes](CORPUS.md) — Detailed analysis of external Windows release binaries.
- [Export Lifting Experiments](EXPORTS.md) — Function-level translation for SQLite and xxHash DLL exports.
- [Wine Reference Setup](WINDOWS.md) — Setup notes for the comparison baseline.
