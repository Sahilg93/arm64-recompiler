/*
 * DllMain formats a string with the CRT. Windows attaches DLLs bottom-up, so
 * ucrtbase.dll is initialized before this runs; otherwise malloc/sprintf fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static char *message;

__declspec(dllexport) const char *order_message(void) {
    return message ? message : "not attached";
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        message = malloc(64);
        if (!message)
            return FALSE;
        sprintf(message, "attached after the CRT (%d)", 42);
    }
    return TRUE;
}
