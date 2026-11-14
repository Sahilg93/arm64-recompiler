typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "bsr and bsf passed\n";

void entry(void) {
    // 1. 64-bit bsf
    unsigned long long src64 = 0x800000000ULL; // bit 35
    unsigned long long dst64 = 0;
    char zf = 0;
    __asm__ volatile(
        "bsfq %2, %0\n\t"
        "sete %1"
        : "=r"(dst64), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (zf || dst64 != 35)
        ExitProcess(101);

    // 2. 64-bit bsr
    src64 = (1ULL << 62) | (1ULL << 10);
    dst64 = 0;
    zf = 0;
    __asm__ volatile(
        "bsrq %2, %0\n\t"
        "sete %1"
        : "=r"(dst64), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (zf || dst64 != 62)
        ExitProcess(102);

    // 3. 32-bit bsf
    unsigned int src32 = 0x00000080; // bit 7
    unsigned int dst32 = 0;
    zf = 0;
    __asm__ volatile(
        "bsfl %2, %0\n\t"
        "sete %1"
        : "=r"(dst32), "=r"(zf)
        : "r"(src32)
        : "cc"
    );
    if (zf || dst32 != 7)
        ExitProcess(103);

    // 4. 32-bit bsr
    src32 = 0x00400004; // bit 22
    dst32 = 0;
    zf = 0;
    __asm__ volatile(
        "bsrl %2, %0\n\t"
        "sete %1"
        : "=r"(dst32), "=r"(zf)
        : "r"(src32)
        : "cc"
    );
    if (zf || dst32 != 22)
        ExitProcess(104);

    // 5. Zero source sets ZF
    src64 = 0;
    zf = 0;
    __asm__ volatile(
        "bsfq %2, %0\n\t"
        "sete %1"
        : "=r"(dst64), "=r"(zf)
        : "r"(src64)
        : "cc"
    );
    if (!zf)
        ExitProcess(105);

    DWORD written;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
