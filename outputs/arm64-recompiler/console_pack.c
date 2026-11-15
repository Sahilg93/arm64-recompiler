typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "pack and bit tests passed\n";

__attribute__((aligned(16))) static short w1[8] = { 1, -1, 127, 128, -128, -129, 32767, -32768 };
__attribute__((aligned(16))) static short w2[8] = { 0, 200, -200, 5, -5, 300, -300, 64 };
__attribute__((aligned(16))) static signed char rb[16];

__attribute__((aligned(16))) static int d1[4] = { 1, -1, 32767, 32768 };
__attribute__((aligned(16))) static int d2[4] = { -32768, -32769, 2147483647, -2147483647 - 1 };
__attribute__((aligned(16))) static short rw[8];

static unsigned int flags32 = 0x80000001u;
static unsigned long long flags64 = 0x8000000000000080ull;

void entry(void) {
    // 1. packsswb: signed words to signed-saturated bytes, destination then source.
    __asm__ volatile(
        "movdqu %1, %%xmm0\n\t"
        "movdqu %2, %%xmm1\n\t"
        "packsswb %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, %0"
        : "=m"(rb) : "m"(w1), "m"(w2) : "xmm0", "xmm1");
    static const signed char eb[16] = { 1, -1, 127, 127, -128, -128, 127, -128,
                                        0, 127, -128, 5, -5, 127, -128, 64 };
    for (int i = 0; i < 16; ++i)
        if (rb[i] != eb[i])
            ExitProcess(101);

    // 2. packssdw: signed doublewords to signed-saturated words.
    __asm__ volatile(
        "movdqu %1, %%xmm2\n\t"
        "movdqu %2, %%xmm3\n\t"
        "packssdw %%xmm3, %%xmm2\n\t"
        "movdqu %%xmm2, %0"
        : "=m"(rw) : "m"(d1), "m"(d2) : "xmm2", "xmm3");
    static const short ew[8] = { 1, -1, 32767, 32767, -32768, -32768, 32767, -32768 };
    for (int i = 0; i < 8; ++i)
        if (rw[i] != ew[i])
            ExitProcess(102);

    // 3. bts/btr/bt on memory with an immediate index: carry is the old bit.
    unsigned char c1, c2, c3, c4;
    __asm__ volatile(
        "btsl $26, %0\n\t setc %1\n\t"
        "btsl $0, %0\n\t setc %2\n\t"
        "btrl $31, %0\n\t setc %3\n\t"
        "btl $31, %0\n\t setc %4"
        : "+m"(flags32), "=&q"(c1), "=&q"(c2), "=&q"(c3), "=&q"(c4) : : "cc");
    if (flags32 != 0x04000001u || c1 != 0 || c2 != 1 || c3 != 1 || c4 != 0)
        ExitProcess(103);
    __asm__ volatile(
        "btrq $7, %0\n\t setc %1\n\t"
        "btsq $40, %0\n\t setc %2"
        : "+m"(flags64), "=&q"(c1), "=&q"(c2) : : "cc");
    if (flags64 != 0x8000010000000000ull || c1 != 1 || c2 != 0)
        ExitProcess(104);

    // 4. An 8-bit rotate by CL.
    unsigned char value = 0x81, count = 3;
    __asm__ volatile("rorb %%cl, %0" : "+q"(value) : "c"(count) : "cc");
    if (value != 0x30)
        ExitProcess(105);
    count = 12; /* masked to 4 for an 8-bit operand */
    __asm__ volatile("rolb %%cl, %0" : "+q"(value) : "c"(count) : "cc");
    if (value != 0x03)
        ExitProcess(106);

    // 5. A 192-bit add and subtract with carries through registers and memory.
    static unsigned long long a[3] = { 0xffffffffffffffffull, 0xffffffffffffffffull, 0x1 };
    static unsigned long long b[3] = { 0x1, 0x0, 0x7ffffffffffffffeull };
    unsigned long long r0, r1, r2;
    unsigned char overflow, carry;
    __asm__ volatile(
        "movq %5, %%rax\n\t movq 8+%5, %%rbx\n\t movq 16+%5, %%rdx\n\t"
        "clc\n\t"
        "adcq %6, %%rax\n\t"      /* memory source */
        "movq 8+%6, %%rsi\n\t"
        "adcq %%rsi, %%rbx\n\t"   /* register source */
        "adcq 16+%6, %%rdx\n\t"
        "seto %3\n\t setc %4\n\t"
        "movq %%rax, %0\n\t movq %%rbx, %1\n\t movq %%rdx, %2"
        : "=m"(r0), "=m"(r1), "=m"(r2), "=m"(overflow), "=m"(carry)
        : "m"(a), "m"(b) : "rax", "rbx", "rdx", "rsi", "cc");
    if (r0 != 0 || r1 != 0 || r2 != 0x8000000000000000ull || overflow != 1 || carry != 0)
        ExitProcess(107);
    __asm__ volatile(
        "movq %3, %%rax\n\t movq 8+%3, %%rbx\n\t movq 16+%3, %%rdx\n\t"
        "stc\n\t"
        "sbbq %4, %%rax\n\t"
        "movq 8+%4, %%rsi\n\t"
        "sbbq %%rsi, %%rbx\n\t"
        "sbbq %%rdx, 16+%4\n\t"   /* memory destination: b[2] -= a[2] + borrow */
        "movq %%rax, %0\n\t movq %%rbx, %1\n\t setc %2"
        : "=m"(r0), "=m"(r1), "=m"(carry)
        : "m"(a), "m"(b) : "rax", "rbx", "rdx", "rsi", "cc", "memory");
    if (r0 != 0xfffffffffffffffdull || r1 != 0xffffffffffffffffull || b[2] != 0x7ffffffffffffffdull || carry != 0)
        ExitProcess(108);

    DWORD written;
    int ok = WriteFile(GetStdHandle((DWORD)-11), output, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
