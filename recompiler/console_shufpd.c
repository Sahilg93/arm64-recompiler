typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "shufpd passed\n";

static const unsigned long long mem_data[2] = { 0x3333333333333333ULL, 0x4444444444444444ULL };

void entry(void) {
    unsigned long long d[2] = { 0x1111111111111111ULL, 0x2222222222222222ULL };
    unsigned long long s[2] = { 0x3333333333333333ULL, 0x4444444444444444ULL };
    unsigned long long res[2] = { 0, 0 };

    // Test 1: shufpd with reg-reg, imm = 0 (dst[0], src[0])
    __asm__ volatile(
        "movdqu (%1), %%xmm0\n\t"
        "movdqu (%2), %%xmm1\n\t"
        "shufpd $0, %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, (%0)\n\t"
        :
        : "r"(res), "r"(d), "r"(s)
        : "xmm0", "xmm1", "memory"
    );
    if (res[0] != d[0] || res[1] != s[0]) ExitProcess(101);

    // Test 2: shufpd with mem, imm = 2 (dst[0], mem[1])
    // The exact rg.exe pattern: shufpd xmm, [mem], 2
    __asm__ volatile(
        "movdqu (%1), %%xmm0\n\t"
        "shufpd $2, %2, %%xmm0\n\t"
        "movdqu %%xmm0, (%0)\n\t"
        :
        : "r"(res), "r"(d), "m"(mem_data[0])
        : "xmm0", "memory"
    );
    if (res[0] != d[0] || res[1] != mem_data[1]) ExitProcess(102);

    // Test 3: shufpd with reg-reg, imm = 3 (dst[1], src[1])
    __asm__ volatile(
        "movdqu (%1), %%xmm0\n\t"
        "movdqu (%2), %%xmm1\n\t"
        "shufpd $3, %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, (%0)\n\t"
        :
        : "r"(res), "r"(d), "r"(s)
        : "xmm0", "xmm1", "memory"
    );
    if (res[0] != d[1] || res[1] != s[1]) ExitProcess(103);

    DWORD written = 0;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
