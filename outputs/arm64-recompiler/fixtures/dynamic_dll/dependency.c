#include "win32.h"

static DWORD ready;
static DWORD *volatile ready_pointer = &ready;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        ready = 42;
    return TRUE;
}

__declspec(dllexport) DWORD WINAPI dependency_ready(void) {
    return *ready_pointer;
}
