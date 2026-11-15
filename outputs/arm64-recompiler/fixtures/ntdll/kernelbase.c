/*
 * Calls Wine's kernelbase.dll lifted on top of the lifted ntdll.dll: its
 * DllMain runs for real, and its exports run as lifted Wine code. The kernel32
 * imports below have no runtime shim, so they fall back to kernelbase.
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
IMPORT DWORD WINAPI GetUserDefaultLCID(void);
IMPORT int WINAPI GetLocaleInfoW(DWORD, DWORD, WCHAR *, int);
IMPORT int WINAPI CompareStringOrdinal(const WCHAR *, int, const WCHAR *, int, int);
IMPORT int WINAPI lstrcmpiW(const WCHAR *, const WCHAR *);
IMPORT DWORD WINAPI ExpandEnvironmentStringsW(const WCHAR *, WCHAR *, DWORD);

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

    /* kernel32 fallbacks into kernelbase: locale data from Wine's NLS tables. */
    if (GetUserDefaultLCID() != 0x409) ExitProcess(34);
    if (GetLocaleInfoW(0x409, 0x59 /* LOCALE_SISO639LANGNAME */, out, 64) != 3 || !equal(out, L"en"))
        ExitProcess(35);
    if (CompareStringOrdinal(L"Straße", -1, L"STRASSE", -1, 1) == 2 ||
        CompareStringOrdinal(L"abc", -1, L"ABC", -1, 1) != 2 /* CSTR_EQUAL */)
        ExitProcess(36);
    if (lstrcmpiW(L"hello", L"HELLO") != 0 || lstrcmpiW(L"apple", L"Banana") >= 0) ExitProcess(37);
    /* The environment block comes from PEB->ProcessParameters. */
    if (ExpandEnvironmentStringsW(L"%SystemRoot%\\x", out, 64) != 13 || !equal(out, L"C:\\Windows\\x"))
        ExitProcess(38);
    ExitProcess(0);
}
