# First audit of independent Windows releases

I selected three published x86-64 Windows console executables built outside this
project. Each was inspected as data. The audit records the first error when
lifting from the PE entry point and separately inspects loader requirements.
The binaries were neither executed nor redistributed. The Windows reference
run is still pending because the local VM requires a password.

| Published binary | First instruction-level failure | Other requirements |
| --- | --- | --- |
| jq 1.8.2 | `0x1467`, store through `RAX` | Writable image sections, three TLS callbacks, 214 import slots |
| PuTTY Plink 0.83 | `0x852e0`, save `RBX` | Writable image data, 152 import slots |
| ripgrep 15.1.0, MSVC | `0x2d0158`, save `RBX` | Writable image data, one TLS callback, 130 import slots |

Import counts describe PE metadata. They do not measure the imports exercised
by a particular command. The three existing shims match two jq slots and
three slots in each of the other binaries. Import-name matching does not
establish that the shims cover every use.

A temporary diagnostic probe recognized the nonvolatile register names and
immediate `movabs`. Plink advanced to an `and` on a frame-pointer-relative
location, and ripgrep advanced to a frame-pointer-relative `lea`. The probe
was used only to expose subsequent diagnostics. No resulting IR was executed,
and the probe changes were not added to the translator.

At the time of this audit the console translator rejected TLS and writable
sections. It now supports bounded writable sections and still rejects TLS. The audit still reports the first instruction it cannot lift.
This lets us distinguish a small instruction gap from a missing loader feature
without treating the startup code as an ordinary fixture.

## What to test next

These three files are a small startup sample. They show that AI-assisted branch
recovery would leave the observed blockers in place. For a whole-program
product, test a PE loader and a Windows compatibility layer before accumulating
startup opcodes and API shims one at a time. For an initial demonstration of
source recovery, test a documented computational function from an independent
binary and compare inputs, outputs, and memory writes against the original.
That experiment can isolate instruction lifting and branch recovery from OS
compatibility.

## Reproduce

Download the pinned releases below, then run
`PYTHONDONTWRITEBYTECODE=1 .venv/bin/python audit_pe.py /path/to/jq.exe /path/to/plink.exe /path/to/rg.exe`.
SHA-256 fingerprints and individual results are in
[corpus-results.json](corpus-results.json).

- [jq 1.8.2 Windows AMD64 executable](https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-windows-amd64.exe)
- [PuTTY 0.83 Windows x64 Plink executable](https://the.earth.li/~sgtatham/putty/0.83/w64/plink.exe)
- [ripgrep 15.1.0 Windows x64 MSVC archive](https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep-15.1.0-x86_64-pc-windows-msvc.zip)

## Writable data follow-up

The `console-data` regression fixture sets and reads the Windows last-error
value, follows a relocated pointer in writable image data, edits the pointed-to
message, and increments a global initialized to zero. The native version and
x86 execution with modeled imports agreed on stdout and exit status for
successful and forced-failure writes.

On the release batch, jq and ripgrep still stopped at the TLS check. Plink
advanced to its call to `GetSystemTimeAsFileTime` at RVA `0x8530c`.
The tool has not converted any of those three release executables.

## Native startup follow-up

The native runtime now maps `GetSystemTimeAsFileTime`,
`GetCurrentProcessId`, `GetCurrentThreadId`, and
`QueryPerformanceCounter`. The console-data regression checks nonzero IDs
and clock values before exercising the writable PE data and output paths.
The x86 test models these imports independently. The comparison checks
observable stdout and exit status, since timestamps and IDs can differ.

Plink lifts past these imports and stops at `CPUID` at RVA `0x85697`.
Supporting it requires a guest feature profile consistent with the x86
instructions the lifter implements. jq and ripgrep still stop at TLS.
No native artifact was published for these three applications.

## Guest CPU profile

Native console lifting supports a synthetic `CPUID` profile with a vendor
identifier and no optional feature bits. The x86 verifier supplies the same
profile in Unicorn. The console-data fixture checks the basic, feature,
and extended-limit leaves before running its usual output checks. The
translator also tracks carry for unsigned branches and register `BT`.

Plink now lifts past the initial CPU feature queries and stops at a signed
`JL` at RVA `0x8574a`. The lifter analyzes both sides of conditional branches,
including paths that may be unreachable under the synthetic profile.
jq and ripgrep still stop at TLS startup.

## Signed branch follow-up

The lifter now tracks the signed condition used by JL, JGE, JG, and JLE
and supports immediate indices for register BT. The native console suite
checks a signed comparison. Plink now lifts to XGETBV at RVA 0x857ad.
This is a translation diagnostic. Plink has not run as a lifted executable.
