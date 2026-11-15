typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "pcmpeq passed\n";

__attribute__((aligned(16))) static unsigned int a32[4] = { 10, 20, 30, 40 };
__attribute__((aligned(16))) static unsigned int b32[4] = { 10, 99, 30, 88 };
__attribute__((aligned(16))) static unsigned int r32[4] = { 0 };

__attribute__((aligned(16))) static unsigned short a16[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
__attribute__((aligned(16))) static unsigned short b16[8] = { 1, 0, 3, 0, 5, 0, 7, 0 };
__attribute__((aligned(16))) static unsigned short r16[8] = { 0 };

__attribute__((aligned(16))) static unsigned char a8[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
__attribute__((aligned(16))) static unsigned char b8[16] = { 1,0,3,0,5,0,7,0,9, 0,11, 0,13, 0,15, 0 };
__attribute__((aligned(16))) static unsigned char r8[16] = { 0 };

void entry(void) {
    // 1. pcmpeqd self-comparison
    unsigned long long self_res[2] = {0};
    __asm__ volatile(
        "pcmpeqd %%xmm0, %%xmm0\n\t"
        "movdqu %%xmm0, %0"
        : "=m"(self_res)
        :
        : "xmm0"
    );
    if (self_res[0] != 0xffffffffffffffffULL || self_res[1] != 0xffffffffffffffffULL)
        ExitProcess(101);

    // 2. pcmpeqd vector comparison
    __asm__ volatile(
        "movdqu %1, %%xmm0\n\t"
        "movdqu %2, %%xmm1\n\t"
        "pcmpeqd %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, %0"
        : "=m"(r32)
        : "m"(a32), "m"(b32)
        : "xmm0", "xmm1"
    );
    if (r32[0] != 0xffffffff || r32[1] != 0 || r32[2] != 0xffffffff || r32[3] != 0)
        ExitProcess(102);

    // 3. pcmpeqw vector comparison
    __asm__ volatile(
        "movdqu %1, %%xmm0\n\t"
        "movdqu %2, %%xmm1\n\t"
        "pcmpeqw %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, %0"
        : "=m"(r16)
        : "m"(a16), "m"(b16)
        : "xmm0", "xmm1"
    );
    if (r16[0] != 0xffff || r16[1] != 0 || r16[2] != 0xffff || r16[3] != 0 ||
        r16[4] != 0xffff || r16[5] != 0 || r16[6] != 0xffff || r16[7] != 0)
        ExitProcess(103);

    // 4. pcmpeqb vector comparison
    __asm__ volatile(
        "movdqu %1, %%xmm0\n\t"
        "movdqu %2, %%xmm1\n\t"
        "pcmpeqb %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, %0"
        : "=m"(r8)
        : "m"(a8), "m"(b8)
        : "xmm0", "xmm1"
    );
    if (r8[0] != 0xff || r8[1] != 0 || r8[2] != 0xff || r8[3] != 0)
        ExitProcess(104);

    DWORD written;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
