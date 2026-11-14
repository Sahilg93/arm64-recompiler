# Dynamic DLL and worker-thread fixture

The x64 Windows EXE checks that it can load and release a Kernel32 handle.
It then loads a sibling DLL with `LoadLibraryW`. The plugin imports a second
DLL and calls its export during process attach to verify initialization
order. The EXE then starts a worker. The
worker resolves a named export with `GetProcAddress`. The DLL stores a value
in its TLS slot, calls back into the EXE on the worker, and reads the value
back. The EXE checks the result, callback thread, and callback count. After
waiting for the worker, it checks that the worker's TLS value is absent on
the main thread, then unloads the DLL.

## Native ARM64 regression test

From the repository root, using Clang and the Python environment from
`outputs/arm64-recompiler/requirements.txt`:

```sh
PYTHON="$PWD/work/venv/bin/python3" \
  outputs/arm64-recompiler/fixtures/dynamic_dll/test.sh
```

This builds and runs the main-thread and worker-thread variants with the
registered DLL. It also checks on-demand translation and the handling of
missing, changed, and unrelated DLL files.

## Launch with on-demand DLL translation

From the repository root, after building the fixture:

```sh
work/venv/bin/python3 outputs/arm64-recompiler/run_exe.py work/dynamic-dll/fixture.exe
```

The launcher starts the translated EXE in its own directory. When the
guest calls `LoadLibraryW` for a supported DLL in that directory, the
runner translates the requested file to ARM64, maps its guest sections,
and runs `DllMain`. Other DLLs in the directory are left alone. The
launcher passes through arguments and returns the guest exit status.

## Reproduce manually or compare with Wine

```sh
tool=outputs/arm64-recompiler
fixture="$PWD/work/dynamic-dll"
export PYTHON="$PWD/work/venv/bin/python3"
"$tool/fixtures/dynamic_dll/build.sh" "$fixture"
"$PYTHON" "$tool/build_console_modules.py" "$fixture/fixture.exe" \
  "$fixture/fixture-arm64" "$fixture/fixture_plugin.dll" "$fixture/fixture_dependency.dll"
(cd "$fixture" && ./fixture-arm64)
(cd "$fixture" && wine ./fixture.exe)
```

Run the EXE from the build directory so the relative DLL path resolves.
Use `fixture-main-thread.exe` as the build input to exercise the same
DLL calls on the main thread.

| Exit | Meaning |
| --- | --- |
| 0 | DLL load, export call, TLS, callback, and unload succeeded |
| 10 | DLL load failed |
| 11 | Worker creation failed |
| 12 | Worker wait or exit-code lookup failed |
| 13 | DLL unload failed |
| 14 | Kernel32 load or release failed |
| 15 | Main-thread TLS value mismatched |
| 21 | Export lookup failed |
| 22 | Callback count or calculated result mismatched |

The build command precompiles each supplied DLL and records its original
bytes. `LoadLibraryW` maps its sections and runs `DllMain` when the guest
requests a registered DLL and the file on disk matches. The supported DLL
subset supports relocation when preferred image bases overlap, code exports,
acyclic application DLL dependencies, and the built-in
Kernel32 TLS APIs. The thread fixture requests a 2 MiB stack and a thread ID, uses a
thread-local guest stack and TLS, and a wait before unloading the DLL.

Both build paths currently share the same supported DLL subset. Broader DLL
compatibility requires support for more system imports, forwarded exports, and other
Windows loader features.
