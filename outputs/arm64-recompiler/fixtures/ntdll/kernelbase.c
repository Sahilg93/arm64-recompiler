/*
 * Calls Wine's kernelbase.dll lifted on top of the lifted ntdll.dll: its
 * DllMain runs for real, and its exports run as lifted Wine code.
 */
#include <stddef.h>
#include <stdint.h>

#define WINAPI __stdcall
#define IMPORT __declspec(dllimport)
typedef uint32_t DWORD;
typedef uint16_t WCHAR;

IMPORT __declspec(noreturn) void WINAPI ExitProcess(DWORD);
IMPORT WCHAR *WINAPI PathFindFileNameW(const WCHAR *);
IMPORT int WINAPI PathIsRelativeW(const WCHAR *);
IMPORT int WINAPI StrToIntW(const WCHAR *);
IMPORT int32_t WINAPI PathCchCombine(WCHAR *, size_t, const WCHAR *, const WCHAR *);

static int equal(const WCHAR *a, const WCHAR *b) {
    while (*a && *a == *b) ++a, ++b;
    return *a == *b;
}

void entry(void) {
    const WCHAR *path = L"C:\\Windows\\System32\\kernelbase.dll";
    if (!equal(PathFindFileNameW(path), L"kernelbase.dll")) ExitProcess(30);
    if (PathIsRelativeW(path) || !PathIsRelativeW(L"dir\\file")) ExitProcess(31);
    if (StrToIntW(L"-1234xyz") != -1234) ExitProcess(32);
    WCHAR out[64];
    if (PathCchCombine(out, 64, L"C:\\a\\b", L"..\\c") || !equal(out, L"C:\\a\\c")) ExitProcess(33);
    ExitProcess(0);
}
