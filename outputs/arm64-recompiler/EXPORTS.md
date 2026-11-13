# Recovering a function from a published Windows DLL

The input is SQLite 3.50.4's published x64 Windows DLL. The lifter resolves the
`sqlite3_stricmp` export at RVA `0x198d`, follows its jump to `0x149d0`, and
lowers the reachable instructions into LLVM IR. It reads the case-folding
table from the DLL's read-only data. The output is an ARM64 macOS dylib with
a wrapper accepting two byte buffers and their lengths, including terminators.

The test compared exact signed return values on 69,732 pairs. It included
all 65,536 pairs of single-byte values, empty strings, embedded NULs, long
strings, case-equivalent strings, and null pointers as observed in this build.
Unicorn executed the original x86 instructions and recorded zero guest memory
writes. The native ABI exposes only bounded read operations on input and
image data. Tests did not use the Windows DLL loader.

The export mode is for leaf functions with two read-only buffer arguments and
an integer return. It rejects guest stores and calls. It shares the existing
console control-flow emitter. The case-folding lookup is indexed data access,
and every branch in this routine has a direct target. This result establishes
a deterministic baseline on a published binary. It gives no measurement of
AI-assisted recovery or support for functions that write guest memory.

## Reproduce

Download the [SQLite 3.50.4 x64 Windows DLL archive](https://sqlite.org/2025/sqlite-dll-win-x64-3500400.zip)
and extract `sqlite3.dll`. Its SHA-256 is
`70450594d9f5743484723e8a27b08f76257e32854fbe6943c96b2aefcdf1ce3b`.

From the project directory, with the README's Python environment:

```bash
export PYTHONDONTWRITEBYTECODE=1
mkdir -p build
.venv/bin/python export_lift.py /path/to/sqlite3.dll sqlite3_stricmp build/stricmp.ll
clang -arch arm64 -O2 -Wno-override-module -dynamiclib build/stricmp.ll \
  export_runtime.c -o build/stricmp.dylib
.venv/bin/python verify_export.py /path/to/sqlite3.dll build/stricmp.dylib
```

## Recovering functions that write to caller buffers

The MSYS2 MinGW x64 xxHash 0.8.4-1 DLL provides three canonical hash encoders.
The lifter reads their instructions from the export addresses and lowers
their byte swaps to LLVM intrinsics. The 32-bit and 64-bit exports take a
scalar hash. The Windows x64 calling convention passes the 128-bit aggregate
by pointer, which the ARM64 wrapper maps into a separate read-only region.
The wrapper bounds each store to the supplied destination length.

| Export | Cases with matching full output buffers |
| --- | ---: |
| `XXH32_canonicalFromHash` | 5,035 |
| `XXH64_canonicalFromHash` | 5,067 |
| `XXH128_canonicalFromHash` | 5,131 |

Each test compares all 96 arena bytes against both original x86 execution in
Unicorn and an independent big-endian encoding. The test varies destination
alignment and the bytes before and after the destination. The Unicorn write
trace must cover exactly the destination bytes, and the native 128-bit input
must remain byte-identical. An additional run passed a 15-byte destination to
the native 128-bit encoder and confirmed the bounds guard aborted.

These exports return void. Their only observable result under the tested ABI
is the output buffer. They are straight-line functions, so this experiment
measures memory effects and ABI handling. Windows DLL loading, performance,
and AI-assisted branch recovery remain untested.

Download the [pinned MSYS2 package](https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-xxhash-0.8.4-1-any.pkg.tar.zst)
and extract `mingw64/bin/libxxhash.dll`. The DLL SHA-256 is
`350044d51d1ecd18e57eccc73924aad8666c989e6f874dd7cd79f7153fb97915`.

```bash
export PYTHONDONTWRITEBYTECODE=1
mkdir -p build
dll=/path/to/libxxhash.dll
for width in 32 64 128; do
    prefix="build/xxh$width"
    .venv/bin/python export_lift.py "$dll" "XXH${width}_canonicalFromHash" "$prefix.ll" --writer
    clang -arch arm64 -O2 -Wno-override-module -dynamiclib "$prefix.ll" \
        writer_runtime.c -o "$prefix.dylib"
    .venv/bin/python verify_writer.py "$dll" "$prefix.dylib" "$width"
done
```

## Indirect branch in the published SQLite DLL

The pinned SQLite DLL's `sqlite3_complete` export contains a two-level
dispatch at RVA `0x3ee75`. An unsigned guard admits byte values 9 through
96. The first table maps those 88 values to compact indices, and the second
table maps the indices to seven destination RVAs. The other byte values
take the guard's default branch.

`verify_dispatch.py` recognizes the exact instruction pattern in the pinned
build and reads both tables from the DLL. It executes the original dispatch
in Unicorn with each possible input byte. It also emits an LLVM switch,
compiles it to ARM64, and checks the selected RVA for every input byte.
Both implementations matched the recovered mapping on all 256 inputs.
The native test returns the selected RVA. The case bodies and the rest of
`sqlite3_complete` are outside this experiment.

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python verify_dispatch.py /path/to/sqlite3.dll
```

The [recorded output](dispatch-results.json) lists the targets. Deterministic
analysis covers the entire domain for this site. A useful model comparison
requires held-out dispatch layouts where the baseline misses targets, and an
independent check of each proposed mapping.

### Second release and alternate compiler

The baseline also handled the [published SQLite 3.53.4 DLL](https://sqlite.org/2026/sqlite-dll-win-x64-3530400.zip).
It recovered seven destinations and matched all 256 bytes on x86 and ARM64.
I then built the same release with Zig 0.15.2's Clang frontend. The baseline
rejected that build because the export starts directly in the function body.
The dispatch itself also differs: it uses one table of signed 32-bit offsets
relative to the table address.

I inferred that mapping from disassembly and encoded it as a separate
candidate. It recovered eight destinations and matched all 256 bytes against
the original x86 dispatch and ARM64 output. The x86 verifier observes the
first instruction reached after the taken guard or indirect jump before
comparing it with the predicted target.

This is one assisted adaptation to a different compiler layout. The candidate
uses offsets and instruction patterns specific to that build. It does not
measure automation or compare the model against a human analyst or a general
jump-table analyzer. The case bodies are still outside the experiment.

```bash
.venv/bin/python -m ziglang cc -target x86_64-windows-gnu -shared -O2 \
    '-DSQLITE_API=__declspec(dllexport)' /path/to/sqlite3.c -o sqlite-clang.dll
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python verify_dispatch.py sqlite-clang.dll --clang-proposal
```

Use the [SQLite 3.53.4 amalgamation](https://sqlite.org/2026/sqlite-amalgamation-3530400.zip).
The recorded mappings and binary fingerprints are in
[dispatch-35304-results.json](dispatch-35304-results.json) and
[dispatch-clang-results.json](dispatch-clang-results.json).

### Recognizing the relative layout without fixed offsets

The `--relative` mode now searches the first 512 bytes of the export for
the signed relative table idiom. It derives the bound, registers, table
address, and branch destinations from decoded operands and PE data. It
requires a unique matching site and verifies the inferred mapping against
x86 and ARM64 execution. The older `--clang-proposal` spelling is an alias.

The same recognizer passed on Zig/Clang `-O1`, `-O2`, and `-O3` builds of
SQLite 3.53.4 with all 256 input values per build. These builds share the same
dispatch address and mapping. The `-Os` build begins with direct comparisons
and produced no matching relative table in the search window. Both published
DLLs still pass the two-level path. See [the compiler matrix](dispatch-matrix.json).

The relative recognizer is an instruction-pattern scan. The x86 verification
seeds registers at the dispatch, so the experiment verifies the local
transition. It does not prove that the table register has the same value
on every path through the full function.
