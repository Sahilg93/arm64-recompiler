# Windows exception and system API fixture

From the repository root on Apple Silicon:

```sh
PYTHON="$PWD/work/venv/bin/python3" outputs/arm64-recompiler/fixtures/exception/test.sh
```

Set `WINE` to a Wine executable and `WINEPREFIX` to a configured prefix to run
the same Windows binary under Wine before running it through the ARM64 launcher.

The fixture checks a vectored handler, a table-driven handler, and a
`STATUS_UNWIND_CONSOLIDATE` transfer across a frame with a cleanup handler.
It verifies cleanup runs before the consolidation callback and execution
reaches the callback's returned continuation. It also checks a registry
query, dynamic lookup of the system RNG, and a TCP loopback exchange.

The fixture also performs a guest null read. A vectored handler checks the
Windows access-violation parameters and redirects the guest instruction pointer
to a compiled continuation. The runner delivers this fault from its checked
memory access path.

For the MSVC acceptance case, build `msvc.cpp` in an x64 Visual Studio
Developer Command Prompt with `cl /nologo /EHsc /MD /O2 msvc.cpp /Fe:msvc-exception.exe`.
Use the same EXE and its matching CRT dependencies with Wine and the ARM64
launcher. It also reads a `VirtualAlloc` `PAGE_NOACCESS` page inside
`__try`/`__except`, which on the launcher is a real Darwin hardware fault
routed to the MSVC SEH handler. Expected stdout is `C++ cleanup, rethrow, and SEH passed` and expected
exit status is zero. This case requires the Microsoft C++ runtime.

The Mac cross-build uses Homebrew LLVM, LLD, and a Microsoft SDK/CRT tree
prepared by xwin. Set `sdk` to that tree and use separate compile and link steps:

```sh
clang-cl --target=x86_64-pc-windows-msvc /EHa /O1 /MT /c \
  /imsvc "$sdk/crt/include" /imsvc "$sdk/sdk/include/ucrt" \
  /imsvc "$sdk/sdk/include/um" /imsvc "$sdk/sdk/include/shared" \
  /Fomsvc.obj msvc.cpp
lld-link "/libpath:$sdk/crt/lib/x86_64" "/libpath:$sdk/sdk/lib/ucrt/x86_64" \
  "/libpath:$sdk/sdk/lib/um/x86_64" /out:msvc.exe msvc.obj
```

The main fixture additionally writes to a read-only mapped view. On Darwin,
the runtime delivers the resulting hardware fault from a trampoline entered
after the signal handler returns. The fixture checks the write flag and
fault address, then resumes at a compiled continuation.
