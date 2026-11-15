typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "seto and setno passed\n";

void entry(void) {
    // 1. mul with overflow
    unsigned long long a = 0x8000000000000000ULL;
    unsigned long long b = 2ULL;
    char of1 = 0, nof1 = 0;
    __asm__ volatile(
        "mulq %3\n\t"
        "seto %0\n\t"
        "setno %1"
        : "=r"(of1), "=r"(nof1), "+a"(a)
        : "r"(b)
        : "rdx", "cc"
    );
    if (!of1 || nof1)
        ExitProcess(101);

    // 2. mul without overflow
    a = 10ULL;
    b = 20ULL;
    char of2 = 1, nof2 = 1;
    __asm__ volatile(
        "mulq %3\n\t"
        "seto %0\n\t"
        "setno %1"
        : "=r"(of2), "=r"(nof2), "+a"(a)
        : "r"(b)
        : "rdx", "cc"
    );
    if (of2 || !nof2)
        ExitProcess(102);

    // 3. add with signed overflow
    long long s1 = 0x7fffffffffffffffLL;
    char of3 = 0, nof3 = 0;
    __asm__ volatile(
        "addq $1, %2\n\t"
        "seto %0\n\t"
        "setno %1"
        : "=r"(of3), "=r"(nof3), "+r"(s1)
        :
        : "cc"
    );
    if (!of3 || nof3)
        ExitProcess(103);

    // 4. sub with signed overflow
    long long s2 = -0x7fffffffffffffffLL - 1LL;
    char of4 = 0, nof4 = 0;
    __asm__ volatile(
        "subq $1, %2\n\t"
        "seto %0\n\t"
        "setno %1"
        : "=r"(of4), "=r"(nof4), "+r"(s2)
        :
        : "cc"
    );
    if (!of4 || nof4)
        ExitProcess(104);

    // NEG overflows only for the minimum signed value.
    unsigned long long minimum = 0x8000000000000000ULL;
    unsigned long long positive = 1;
    char neg_overflow, neg_normal;
    __asm__ volatile("negq %1; seto %0" : "=q"(neg_overflow), "+r"(minimum) :: "cc");
    __asm__ volatile("negq %1; seto %0" : "=q"(neg_normal), "+r"(positive) :: "cc");
    if (!neg_overflow || neg_normal)
        ExitProcess(105);

    DWORD written;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
