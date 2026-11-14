# Windows x64 to Apple Silicon Recompiler

This project recompiles original Windows x86-64 PE binaries into LLVM IR and compiles that IR into native macOS ARM64 Mach-O executables and libraries.

The primary whole-program milestone is the original Windows release of **PuTTY Plink 0.83**, which runs `-V` natively on Apple Silicon through full CRT startup, argument parsing, standard output, and process shutdown. Its native output matches the original Windows binary running under Wine and Rosetta byte-for-byte, exiting status 0 with a **6.20× speedup** (42.31 ms vs. 262.23 ms) and a **68.9% smaller memory footprint** (5.51 MB vs. 17.74 MB RSS).

---

## Directory Overview

| Path | Contents |
| --- | --- |
| [`outputs/arm64-recompiler/`](outputs/arm64-recompiler/) | Core lifters, runtime emulation, diagnostics, and test harness |
| [`outputs/arm64-recompiler/console_lift.py`](outputs/arm64-recompiler/console_lift.py) | Whole-program PE x86-64 lifter emitting LLVM IR |
| [`outputs/arm64-recompiler/console_runtime.c`](outputs/arm64-recompiler/console_runtime.c) | Minimal Win32 / CRT runtime shim (memory, TEB/PEB, TLS, FLS, sync, stdio) |
| [`WAR_STORIES.md`](WAR_STORIES.md) | **Deep-dive post-mortem of failures, subtle bugs, and engineering war stories** |
| [`work/corpus/`](work/corpus/) | Original Windows x64 release binaries (`plink.exe`, `jq.exe`, `rg.exe`) |
| [`work/`](work/) | Test environments, diagnostic traces, and generated builds |

---

## 💥 Failures, Roadblocks & War Stories

Static binary recompilation from Windows x86-64 to Apple Silicon is full of edge cases and undocumented runtime behaviors. 

Check out [**`WAR_STORIES.md`**](WAR_STORIES.md) for an honest, detailed breakdown of the real failures faced and how they were solved:
1. **The Indirect Branch & Callback Discovery Trap** (How PE `.pdata` exception directory parsing replaced multi-pass discovery).
2. **The `lock cmpxchg` Flag Calculation Bug** (How an inverted operand in x86 `CMP` flag emulation broke atomic spinlocks).
3. **The TLS Callback Chicken-and-Egg Trap** (Why `jq` and `rg` crashed before `AddressOfEntryPoint` without pre-main TLS callbacks).
4. **The Universal Import Filter Blocker** (Why hardcoding `KERNEL32.dll` silently dropped Universal CRT functions).
5. **The Modern Windows API-Set Prefix Maze** (Navigating schema-based virtual DLL indirection in MSVC/Rust).
6. **The UCRT `_iobuf` / `FILE*` Memory Impass** (Why fake stream handles crash guest code and how bounded `_iobuf` tables fixed it).
7. **Virtual Memory Protection Translation** (Mapping Win32 page protection bitmasks to POSIX `mprotect`).

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

### 3. Build and Verify jq 1.8.2

From the repository root on Apple Silicon, use the Python environment above
and a matching LLVM 22 Clang and `llvm-link`. Set `LLVM_BIN` to their bin
directory if LLVM is installed outside `/opt/homebrew/opt/llvm@22/bin`.
The parity test takes the [macOS ARM64 jq 1.8.2 release](https://github.com/jqlang/jq/releases/tag/jq-1.8.2)
as its reference. If you need to set up the Python environment, create it with
`python3 -m venv work/venv` and install dependencies with
`work/venv/bin/python3 -m pip install -r outputs/arm64-recompiler/requirements.txt`.

```sh
PYTHON="$PWD/work/venv/bin/python3" \
  outputs/arm64-recompiler/build_jq.sh work/corpus/jq.exe work/build/jq-arm64
curl -fsSL https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-macos-arm64 \
  -o work/build/jq-reference
chmod +x work/build/jq-reference
work/venv/bin/python3 outputs/arm64-recompiler/test_jq.py work/build/jq-arm64 work/build/jq-reference
```

The test checks stdout, stderr, and exit codes for stdin, file input, Unicode
filenames, sorting, regex, malformed JSON, and jq's `-e` behavior.

### 4. Verify Runtime DLL Loading

The fixture builds a Windows EXE and DLL, recompiles them to ARM64, and checks
runtime loading, named exports, callbacks, thread-local storage, and unload
on the main thread and on a worker thread. Run from the repository root:

```sh
PYTHON="$PWD/work/venv/bin/python3" \
  outputs/arm64-recompiler/fixtures/dynamic_dll/test.sh
```

### 5. Trace Startup of Corpus Binaries
Trace native execution and inspect the stopping point for other Windows binaries:
```sh
# jq 1.8.2
$PWD/work/venv/bin/python3 outputs/arm64-recompiler/trace_callbacks.py --max-attempts 1 work/corpus/jq.exe --version

# ripgrep 14.1.1
$PWD/work/venv/bin/python3 outputs/arm64-recompiler/run_exe.py --trace work/corpus/rg.exe --threads 1 --no-config --no-heading --sort path -n PATTERN DIRECTORY
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
| **`gui_showcase.exe`** | **Fully functional (Hybrid GUI)** | Executes Win32 `MessageBoxA` natively on macOS, displaying alert and exiting 0. |
| **`jq.exe`** (1.8.2) | Runs real jq workloads | Verified for stdin, file input, sorting, regex, and error handling. See the jq parity test above. |
| **`rg.exe`** (14.1.1) | Completes a single-threaded recursive search via the launcher in diagnostic mode | Both expected matches and exit status agree with Wine using `--no-heading --sort path`. |

---

## 🔮 Future Roadmap: Hybrid Native AOT + GUI Thunking

The long-term vision for this project is to expand beyond console utilities and run complex Windows software with **native Apple Silicon performance** without having to reimplement decades of Windows display infrastructure from scratch.

### The Hybrid Architecture

Rather than trying to write a custom replacement for millions of lines of Windows GUI subsystems (USER32, GDI, Direct3D, Direct2D, COM, WinUI), the planned trajectory is a **Hybrid AOT + API Thunking Model**:

```
┌────────────────────────────────────────────────────────┐
│             Windows x86-64 PE Application             │
└──────────────────────────┬─────────────────────────────┘
                           │
             [Static LLVM IR Recompiler]
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│           Native Apple Silicon ARM64 Mach-O            │
│  • Application Business Logic & Math (Full AOT Speed)   │
│  • Memory Management & Heap Allocator (Native macOS)   │
│  • Multi-threading & Atomics (Native Hardware CAS)     │
└────────────┬───────────────────────────────┬───────────┘
             │                               │
    [System & File I/O]             [GUI & Graphics Calls]
             │                               │
             ▼                               ▼
┌─────────────────────────┐     ┌────────────────────────┐
│   Native POSIX Shims    │     │   Wine / Rosetta /     │
│   (Console, FS, Net)    │     │   Metal Thunking Layer │
└─────────────────────────┘     │ (USER32, GDI, Direct3D)│
                                └────────────────────────┘
```

### Why This Architecture?
- **Raw CPU Performance Where It Matters**: The computational core, physics, audio processing, parsing, and inner loops run natively on Apple Silicon with zero translation or emulation overhead.
- **Pragmatic Graphics & Windowing**: Wine has spent over 30 years battle-testing USER32/GDI window message loops, font rasterization, and display servers on macOS. Thunking GUI calls across the boundary into Wine—or bridging Direct3D calls to native Apple Metal (similar to Apple's Game Porting Toolkit / DXMT approach)—delivers full graphical application support without duplicating multi-decade wheel re-inventions.
- **Best of Both Worlds**: Near-native CPU throughput paired with battle-tested Windows desktop compatibility.

---

## Additional Documentation

- [Start Here & Quick Reference](outputs/arm64-recompiler/START.md) — Detailed environment setup and command-line usage.
- [Corpus Audit Notes](outputs/arm64-recompiler/CORPUS.md) — Detailed analysis of external Windows release binaries.
- [Export Lifting Experiments](outputs/arm64-recompiler/EXPORTS.md) — Function-level translation for SQLite and xxHash DLL exports.
- [Wine Reference Setup](outputs/arm64-recompiler/WINDOWS.md) — Setup notes for the comparison baseline.
