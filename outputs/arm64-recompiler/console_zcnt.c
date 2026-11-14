typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "tzcnt and lzcnt passed\n";

void entry(void) {
    // 1. 32-bit tzcnt on nonzero
    unsigned int src32 = 0x00000010; // bit 4
    unsigned int dst32 = 0;
    char cf = 0, zf = 0;
    __asm__ volatile(
        "tzcntl %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst32), "=r"(cf), "=r"(zf)
        : "r"(src32)
        : "cc"
    );
    if (dst32 != 4 || cf != 0 || zf != 0)
        ExitProcess(101);

    // 2. 32-bit tzcnt on zero
    src32 = 0;
    dst32 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "tzcntl %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst32), "=r"(cf), "=r"(zf)
        : "r"(src32)
        : "cc"
    );
    if (dst32 != 32 || cf != 1 || zf != 0)
        ExitProcess(102);

    // 3. 64-bit tzcnt on nonzero
    unsigned long long src64 = 1ULL << 40;
    unsigned long long dst64 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "tzcntq %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst64), "=r"(cf), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (dst64 != 40 || cf != 0 || zf != 0)
        ExitProcess(103);

    // 4. 64-bit tzcnt on zero
    src64 = 0;
    dst64 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "tzcntq %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst64), "=r"(cf), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (dst64 != 64 || cf != 1 || zf != 0)
        ExitProcess(104);

    // 5. 32-bit lzcnt on bit 31
    src32 = 0x80000000;
    dst32 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "lzcntl %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst32), "=r"(cf), "=r"(zf)
        : "r"(src32)
        : "cc"
    );
    if (dst32 != 0 || cf != 0 || zf != 1)
        ExitProcess(105);

    // 6. 32-bit lzcnt on zero
    src32 = 0;
    dst32 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "lzcntl %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst32), "=r"(cf), "=r"(zf)
        : "r"(src32)
        : "cc"
    );
    if (dst32 != 32 || cf != 1 || zf != 0)
        ExitProcess(106);

    // 7. 64-bit lzcnt on bit 63
    src64 = 1ULL << 63;
    dst64 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "lzcntq %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst64), "=r"(cf), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (dst64 != 0 || cf != 0 || zf != 1)
        ExitProcess(107);

    // 8. 64-bit lzcnt on zero
    src64 = 0;
    dst64 = 0;
    cf = 0; zf = 0;
    __asm__ volatile(
        "lzcntq %3, %0\n\t"
        "setb %1\n\t"
        "sete %2"
        : "=r"(dst64), "=r"(cf), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (dst64 != 64 || cf != 1 || zf != 0)
        ExitProcess(108);

    DWORD written;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
