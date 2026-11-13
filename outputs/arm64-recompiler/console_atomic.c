typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static volatile unsigned long long mem64 = 0x1122334455667788ULL;
static volatile unsigned int mem32 = 0x12345678U;
static char output[] = "atomic cmpxchg passed\n";

void entry(void) {
    // 1. 64-bit memory lock cmpxchg match
    unsigned long long expected64 = 0x1122334455667788ULL;
    unsigned long long new64 = 0x8877665544332211ULL;
    unsigned long long rax_out64 = expected64;
    char zf = 0;
    __asm__ volatile(
        "lock cmpxchgq %3, %1\n\t"
        "sete %0"
        : "=r"(zf), "+m"(mem64), "+a"(rax_out64)
        : "r"(new64)
        : "cc"
    );
    if (!zf || mem64 != new64 || rax_out64 != expected64)
        ExitProcess(101);

    // 2. 64-bit memory lock cmpxchg mismatch (with borrow/carry: expected < old)
    mem64 = 20ULL;
    expected64 = 10ULL;
    new64 = 99ULL;
    rax_out64 = expected64;
    zf = 1;
    char cf = 0, sf = 0;
    __asm__ volatile(
        "lock cmpxchgq %5, %1\n\t"
        "sete %0\n\t"
        "setb %2\n\t"
        "sets %3"
        : "=r"(zf), "+m"(mem64), "=r"(cf), "=r"(sf), "+a"(rax_out64)
        : "r"(new64)
        : "cc"
    );
    if (zf || mem64 != 20ULL || rax_out64 != 20ULL || !cf || !sf)
        ExitProcess(102);

    // 3. 32-bit memory lock cmpxchg match (verify upper 32 bits of rax cleared)
    unsigned int expected32 = 0x12345678U;
    unsigned int new32 = 0x87654321U;
    unsigned long long rax32 = 0xffffffff00000000ULL | expected32;
    zf = 0;
    __asm__ volatile(
        "lock cmpxchgl %3, %1\n\t"
        "sete %0"
        : "=r"(zf), "+m"(mem32), "+a"(rax32)
        : "r"(new32)
        : "cc"
    );
    if (!zf || mem32 != new32 || rax32 != (unsigned long long)expected32)
        ExitProcess(103);

    // 4. 32-bit memory lock cmpxchg mismatch
    expected32 = 0x11111111U;
    new32 = 0x22222222U;
    rax32 = 0xffffffff00000000ULL | expected32;
    zf = 1;
    __asm__ volatile(
        "lock cmpxchgl %3, %1\n\t"
        "sete %0"
        : "=r"(zf), "+m"(mem32), "+a"(rax32)
        : "r"(new32)
        : "cc"
    );
    if (zf || mem32 != 0x87654321U || rax32 != 0x87654321ULL)
        ExitProcess(104);

    // 5. 64-bit register cmpxchg match and mismatch
    unsigned long long r_dest = 100ULL;
    expected64 = 100ULL;
    rax_out64 = expected64;
    zf = 0;
    __asm__ volatile(
        "cmpxchgq %3, %1\n\t"
        "sete %0"
        : "=r"(zf), "+r"(r_dest), "+a"(rax_out64)
        : "r"(200ULL)
        : "cc"
    );
    if (!zf || r_dest != 200ULL || rax_out64 != 100ULL)
        ExitProcess(105);

    // 6. 32-bit register cmpxchg match
    unsigned int r_dest32 = 300U;
    expected32 = 300U;
    rax32 = 0xffffffff00000000ULL | expected32;
    zf = 0;
    __asm__ volatile(
        "cmpxchgl %3, %1\n\t"
        "sete %0"
        : "=r"(zf), "+r"(r_dest32), "+a"(rax32)
        : "r"(400U)
        : "cc"
    );
    if (!zf || r_dest32 != 400U || rax32 != 300ULL)
        ExitProcess(106);

    DWORD written;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
