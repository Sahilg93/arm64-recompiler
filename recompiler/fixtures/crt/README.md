# Real ucrtbase.dll fixture

From the repository root on Apple Silicon:

```sh
PYTHON="$PWD/work/venv/bin/python3" XWIN_SDK="$PWD/work/xwin-sdk" \
  CLANG_CL=/opt/homebrew/opt/llvm/bin/clang-cl \
  recompiler/fixtures/crt/test.sh
```

Set `WINE` and `WINEPREFIX` to compare with Wine first. `UCRTBASE_DLL` picks
the DLL. By default the script uses the `ucrtbase.dll` from the Wine install
or prefix. With `CRT_FIXTURE_BUILD=<dir>`, it keeps its build directory.

`main.c` is built with `clang-cl` against the Windows SDK's `ucrt.lib`. It has
no CRT startup code, so its only CRT is the DLL. It uses `printf`,
`malloc`/`free`, `qsort` (with a callback into the program), `strtod`, and
`fopen`/`fwrite`/`fread`/`remove`. Wine's x64 `ucrtbase.dll` ships beside it.
The ARM64 launcher lifts that DLL as a guest module, in place of its own CRT
shims. The run exercises these PE loader features:

- **API sets.** The program's CRT imports name `api-ms-win-crt-*-l1-1-0.dll`
  contracts, which resolve to `ucrtbase.dll`. `api-ms-win-core-*` contracts
  resolve to runtime-implemented system code.
- **Import by ordinal.** `ordinal.def` imports `strlen` from `ucrtbase.dll`
  by ordinal only. The ordinal is read from the shipped DLL.
- **Forwarded exports.** `__threadid` is forwarded to
  `kernel32.GetCurrentThreadId`. It resolves to a named runtime token.
- **DllMain order.** `crtorder.dll`'s `DllMain` formats a string with
  `malloc`/`sprintf`, so it only works if `ucrtbase.dll` attached first.
  Attach runs bottom-up before the entry point. `ExitProcess` sends
  `DLL_PROCESS_DETACH` in reverse order, and the CRT flushes stdout there.

Both runs must print `expected.txt`. The launcher run also traces imports
(`ARM64_RECOMPILER_TRACE_IMPORTS=1`). The test checks two things in that trace:
the CRT imports are bound into `ucrtbase.dll`, and no runtime CRT shim was
called.

Debugging aids:
- `ARM64_RECOMPILER_WINE_DEBUG=1` prints Wine's debug channels.
- `ARM64_RECOMPILER_TRACE_MODULES=1` lifts on-demand DLLs with PC tracing.
- `ARM64_RECOMPILER_PC_LOG=<file>` records every traced PC.
