# Raw VirtualAlloc fault delivery fixture

From the repository root on Apple Silicon:

```sh
PYTHON="$PWD/work/venv/bin/python3" recompiler/fixtures/vm_fault/test.sh
```

Set `WINE` (and `WINEPREFIX`) to also run the same EXE under Wine first.

`VirtualAlloc` hands the guest untagged host `mmap` addresses. The runtime
records each region, so guest loads and stores to it run as host copies with
the Darwin `SIGSEGV`/`SIGBUS` handler armed (`SA_SIGINFO` on a per-thread
`sigaltstack`). A fault there is translated back to the guest address and
read/write flag and dispatched as `EXCEPTION_ACCESS_VIOLATION`.

The fixture checks, in order:

1. A read from a `MEM_RESERVE` / `PAGE_NOACCESS` region reaches a vectored
   handler with a read flag and the exact faulting address.
2. `MEM_COMMIT` inside that reservation returns the same base, and the page
   becomes writable without losing the reservation.
3. After `VirtualProtect(PAGE_READONLY)` (old value `PAGE_READWRITE`), a write
   reaches the vectored handler with a write flag, and the store has no effect.
4. With the vectored handler removed and the page `PAGE_NOACCESS`, a read
   inside `seh_read` (`seh.s`) reaches its table-driven handler through
   `.pdata`/`.xdata`. The handler pops `seh_read`'s frame and resumes at
   `seh_resume`, which returns into the middle of the C caller. No compiled
   entry starts there, so the launcher finishes that function in its x86
   interpreter.
5. `VirtualProtect` reports `PAGE_NOACCESS` as the old value, the data written
   in step 2 is intact, and `VirtualFree(MEM_RELEASE)` succeeds.

Exit status 0 means every step passed. Each failure has its own status.
Running with `ARM64_RECOMPILER_FAULT_SIGNALS=0` disables delivery, and the
first fault then terminates the process with `SIGBUS`.

The vectored handlers resume at continuation functions that never return.
