typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) DWORD GetCurrentProcessId(void);
__declspec(dllimport) DWORD GetCurrentThreadId(void);
__declspec(dllimport) int QueryPerformanceCounter(long long *);
typedef struct { DWORD low, high; } FILETIME;
__declspec(dllimport) void GetSystemTimeAsFileTime(FILETIME *);
__declspec(dllimport) void SetLastError(DWORD);
__declspec(dllimport) DWORD GetLastError(void);
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

static char output[] = "xello from writable PE\n";
static char *volatile output_pointer = output;
static volatile DWORD writes;

static unsigned cpu_leaf(unsigned leaf) {
    unsigned eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                             : "0"(leaf), "2"(0));
    return eax;
}

void entry(void) {
    volatile unsigned expected = 0x80000000u;
    unsigned extended = cpu_leaf(expected);
    if (cpu_leaf(0) != 1 || cpu_leaf(1) != 0 || extended != expected)
        ExitProcess(13);
    int signed_input = -1;
    __asm__ volatile("cmpl $1, %0; jl 1f; movl $2, %0; 1:" : "+r"(signed_input) : : "cc");
    if (signed_input != -1)
        ExitProcess(14);
    unsigned xcr_low, xcr_high;
    __asm__ volatile("xgetbv" : "=a"(xcr_low), "=d"(xcr_high) : "c"(0));
    if (xcr_low != 3 || xcr_high)
        ExitProcess(15);
    unsigned long long teb, peb, stack_top, stack_limit, thread_id;
    __asm__ volatile("movq %%gs:0x30, %0" : "=r"(teb));
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    __asm__ volatile("movq %%gs:0x08, %0" : "=r"(stack_top));
    __asm__ volatile("movq %%gs:0x10, %0" : "=r"(stack_limit));
    __asm__ volatile("movq %%gs:0x48, %0" : "=r"(thread_id));
    if (!teb || !peb || !stack_top || !stack_limit || !thread_id)
        ExitProcess(16);
    DWORD written;
    long long ticks;
    if (!GetCurrentProcessId() || !GetCurrentThreadId())
        ExitProcess(11);
    if (!QueryPerformanceCounter(&ticks) || !ticks)
        ExitProcess(12);
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    if (now.high == 0)
        ExitProcess(10);
    SetLastError(1234);
    if (GetLastError() != 1234)
        ExitProcess(9);
    char *message = output_pointer;
    message[0] = 'h';
    writes += 1;
    if (writes != 1)
        ExitProcess(8);
    int ok = WriteFile(GetStdHandle((DWORD)-11), message, sizeof(output) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(output) - 1);
}
