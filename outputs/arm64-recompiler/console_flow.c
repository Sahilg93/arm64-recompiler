typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

__attribute__((noinline))
static int print_message(HANDLE handle, const char *message, DWORD size) {
    DWORD written;
    volatile int status = 7;
    if (WriteFile(handle, message, size, &written, 0)) {
        status = 9;
        if (written == size)
            status = 0;
    }
    return status;
}

void entry(void) {
    static const char message[] = "hello through an internal call\n";
#ifdef REPEAT
    HANDLE handle = GetStdHandle((DWORD)-11);
    volatile unsigned remaining = REPEAT;
    do {
        int status = print_message(handle, message, sizeof(message) - 1);
        if (status)
            ExitProcess(status);
        --remaining;
    } while (remaining != 0);
    ExitProcess(0);
#else
    int status = print_message(GetStdHandle((DWORD)-11), message, sizeof(message) - 1);
    ExitProcess(status);
#endif
}
