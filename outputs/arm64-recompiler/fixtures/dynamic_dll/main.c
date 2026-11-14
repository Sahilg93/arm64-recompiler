#include "win32.h"


typedef DWORD (WINAPI *Callback)(DWORD);
typedef DWORD (WINAPI *Plugin)(DWORD, Callback);
typedef DWORD (WINAPI *ReadTls)(void);

static DWORD main_thread;
static DWORD callback_count;

static DWORD WINAPI callback(DWORD value) {
#ifdef RUN_ON_MAIN_THREAD
    if (GetCurrentThreadId() != main_thread)
#else
    if (GetCurrentThreadId() == main_thread)
#endif
        return 0;
    ++callback_count;
    return value * 2;
}

static DWORD WINAPI worker(LPVOID module) {
    Plugin plugin = (Plugin)GetProcAddress(module, "call_plugin");
    if (!plugin)
        return 1;
    return plugin(7, callback) == 21 && callback_count == 1 ? 0 : 2;
}

void entry(void) {
    HMODULE system = LoadLibraryW(L"kernel32.dll");
    if (!system || !FreeLibrary(system))
        ExitProcess(14);

    main_thread = GetCurrentThreadId();
    HMODULE module = LoadLibraryW(L".\\fixture_plugin.dll");
    if (!module)
        ExitProcess(10);

#ifdef RUN_ON_MAIN_THREAD
    DWORD status = worker(module);
    if (status)
        status += 20;
#else
    DWORD status = 11;
    DWORD worker_id = 0;
    HANDLE thread = CreateThread(NULL, 2097152, worker, module, 0, &worker_id);
    if (thread) {
        if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0 || !worker_id ||
                !GetExitCodeThread(thread, &status))
            status = 12;
        else if (status)
            status += 20;
        CloseHandle(thread);
    }
#endif
#ifdef RUN_ON_MAIN_THREAD
    const DWORD expected_tls_value = 7;
#else
    const DWORD expected_tls_value = 0;
#endif
    ReadTls read_tls = (ReadTls)GetProcAddress(module, "read_plugin_tls");
    if (status == 0 && (!read_tls || read_tls() != expected_tls_value))
        status = 15;
    if (!FreeLibrary(module) && status == 0)
        status = 13;
    ExitProcess(status);
}
