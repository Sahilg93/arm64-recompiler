typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __attribute__((noreturn)) void ExitProcess(DWORD);

#ifndef MESSAGE
#define MESSAGE "hello from PE"
#endif

void entry(void) {
    static const char message[] = MESSAGE "\n";
    DWORD written;
    HANDLE stdout_handle = GetStdHandle((DWORD)-11);
    int ok = WriteFile(stdout_handle, message, sizeof(message) - 1, &written, 0);
    ExitProcess(!ok || written != sizeof(message) - 1);
}
