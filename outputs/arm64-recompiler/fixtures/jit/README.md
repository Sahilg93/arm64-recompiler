# Runtime-generated code fixture

From the repository root on Apple Silicon:

```sh
PYTHON="$PWD/work/venv/bin/python3" outputs/arm64-recompiler/fixtures/jit/test.sh
```

Set `WINE` (and `WINEPREFIX`) to also run the same EXE under Wine first. Wine
runs the payload natively, so it checks the expected values in `main.c`.

`payload.s` is assembled, and `embed_text.py` copies its `.text` bytes into
`main.c`. It rejects relocations, so the payload is position-independent.
The fixture then checks:

1. The payload, copied into a `PAGE_READWRITE` buffer and switched to
   `PAGE_EXECUTE_READ`, runs when called through a function pointer. The
   lifter never saw this code, so `guest_indirect_dispatch` hands it to the x86
   interpreter. The payload covers the 0x80/0x81/0x83 ALU-immediate group,
   movsx/movzx, shifts and rotates, cmovcc, setcc, mul/imul/idiv, `rep stosb`,
   SSE `movq`, a counted loop, and a call back into compiled guest code.
   Each of its 34 results must match.
2. A `PAGE_EXECUTE_READWRITE` stub returns a constant, is patched in place,
   and returns the new constant without a protection change.
3. After `VirtualProtect(PAGE_READWRITE)`, calling the payload raises
   `EXCEPTION_ACCESS_VIOLATION` with `ExceptionInformation[0] == 8` (execute)
   at the buffer address, as Windows does under DEP.

Guest pages are never mapped `PROT_EXEC` on the host, because only the
interpreter reads them. The runtime tracks execute permission per page.
Exit status 0 means every step passed. `100 + i` names a wrong `out[i]`.
