# Windows export recompiler for Apple Silicon

Build a native macOS library from a supported Windows x64 DLL export with one
command. The tool decodes the DLL, emits LLVM IR, compiles it with Clang, and
checks the result against the original x86 code in Unicorn. It publishes the
library only after the comparison passes. The generated library runs natively
on macOS. Unicorn is used at build time for verification.

## Batch conversion

Use Apple Silicon macOS, Xcode command-line tools, and native Python 3.10+.
From the extracted directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r product-requirements.txt
.venv/bin/python convert.py "/path/to/windows-files" -o converted
```

Pass any mix of individual files and folders. Folders are scanned recursively
for `.exe` and `.dll`. The command detects x64 PE files, discovers recognized
DLL exports, and attempts compatible console programs. Every published output
passes a comparison against the original x86 bytes. The console comparison
uses modeled Windows imports and checks stdout and process status for both
successful and failed writes. Existing output binaries are preserved.
The command writes `conversion-report.json` and exits with status 1 if
any input fails or converts partially. Successful outputs are still usable.

The batch accepts multiple DLL builds with the same supported function
signatures. It also supports a subset of no-argument console executables
with direct calls, branches, stack locals, writable image data, and
64-bit relocations for in-image data pointers. The runtime models a subset of
`GetStdHandle`, `WriteFile`, and `ExitProcess`, plus `SetLastError` and
`GetLastError` for the single-threaded console mode. General GUI programs,
arbitrary DLL signatures, and Windows loader services such as TLS and
general Windows startup are outside current coverage.

## Quick start

Use Apple Silicon macOS with Xcode command-line tools and native Python 3.10+
from this directory.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r product-requirements.txt
curl -fL https://sqlite.org/2025/sqlite-dll-win-x64-3500400.zip -o sqlite.zip
unzip sqlite.zip -d sqlite-win
.venv/bin/python recompile.py sqlite-win/sqlite3.dll sqlite3_stricmp -o build/compare.dylib
.venv/bin/python use_library.py build/compare.dylib compare Hello hello
```

The comparison checks 69,732 input pairs. The example prints `0`.

## Supported exports

- `sqlite3_stricmp` verified on published SQLite 3.50.4 and 3.53.4 Windows x64 DLLs and a local Clang build.
- `XXH32_canonicalFromHash`, `XXH64_canonicalFromHash`, and
  `XXH128_canonicalFromHash` from the tested MSYS2 MinGW x64 xxHash 0.8.4-1 DLL.

For xxHash, extract `mingw64/bin/libxxhash.dll` from the
[pinned MSYS2 package](https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-xxhash-0.8.4-1-any.pkg.tar.zst).

```sh
.venv/bin/python recompile.py mingw64/bin/libxxhash.dll XXH64_canonicalFromHash -o build/xxh64.dylib
.venv/bin/python use_library.py build/xxh64.dylib encode 64 0123456789abcdef
```

The example prints `0123456789abcdef`. Existing output files are preserved.

## Calling from your own code

The native comparison wrapper exports
`int32_t compare_export(const unsigned char *a, size_t a_len, const unsigned char *b, size_t b_len)`.
Lengths include the terminating NUL. The xxHash wrapper exports
`void write_export(unsigned char *out, size_t out_len, uint64_t scalar, const unsigned char *in, size_t in_len)`.
For 32- and 64-bit hashes, pass the hash in `scalar` and use a null input
pointer and zero input length. For a 128-bit hash, pass a 16-byte little-endian
input and set `scalar` to zero. The output length must fit the encoded hash.

Use trusted input files. This release targets the listed exports and their bounded
buffer contracts. Whole Windows applications, arbitrary DLL exports, and
Windows loader behavior are outside its supported workflow.
[Experiment details](EXPORTS.md)

## Try the bundled libraries

The ZIP includes the four verified ARM64 libraries in `libraries/`. Run the
examples below from the extracted directory with native Python. These examples
use Python's standard library and require no package installation.

```sh
python3 use_library.py libraries/compare.dylib compare Hello hello
python3 use_library.py libraries/xxh64.dylib encode 64 0123456789abcdef
```

For original Windows executables, see [Run with Wine](WINDOWS.md).

The native console runtime also supports Windows wall-clock timestamps,
monotonic performance counters, and process and thread IDs in the supported
single-threaded execution mode. See [release coverage](CORPUS.md).
