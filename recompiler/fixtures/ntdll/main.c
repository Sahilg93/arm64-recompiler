/*
 * Calls Wine's ntdll.dll lifted as a guest module. Rtl string, conversion and
 * formatting routines run as lifted Wine code; heap, last-error and syscall
 * entry points are runtime-owned overrides that must stay coherent with the
 * runtime's kernel32. Each failed check exits with its own code.
 */
#include <stddef.h>
#include <stdint.h>

#define WINAPI __stdcall
#define IMPORT __declspec(dllimport)
typedef uint32_t DWORD;
typedef int32_t NTSTATUS;
typedef uint16_t WCHAR;
typedef void *HANDLE;
typedef struct { uint16_t Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct { uint16_t Length, MaximumLength; char *Buffer; } ANSI_STRING;
typedef struct { int16_t Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday; } TIME_FIELDS;

IMPORT __declspec(noreturn) void WINAPI ExitProcess(DWORD);
IMPORT HANDLE WINAPI GetProcessHeap(void);
IMPORT int WINAPI HeapFree(HANDLE, DWORD, void *);
IMPORT void WINAPI SetLastError(DWORD);
IMPORT DWORD WINAPI GetLastError(void);
IMPORT HANDLE WINAPI GetModuleHandleW(const WCHAR *);

IMPORT void WINAPI RtlInitUnicodeString(UNICODE_STRING *, const WCHAR *);
IMPORT NTSTATUS WINAPI RtlUnicodeStringToAnsiString(ANSI_STRING *, const UNICODE_STRING *, uint8_t);
IMPORT void WINAPI RtlFreeAnsiString(ANSI_STRING *);
IMPORT int32_t WINAPI RtlCompareUnicodeString(const UNICODE_STRING *, const UNICODE_STRING *, uint8_t);
IMPORT NTSTATUS WINAPI RtlCharToInteger(const char *, DWORD, DWORD *);
IMPORT void WINAPI RtlTimeToTimeFields(const int64_t *, TIME_FIELDS *);
IMPORT DWORD WINAPI RtlNtStatusToDosError(NTSTATUS);
IMPORT void *WINAPI RtlAllocateHeap(HANDLE, DWORD, size_t);
IMPORT DWORD WINAPI RtlGetLastWin32Error(void);
IMPORT int __cdecl _snprintf(char *, size_t, const char *, ...);
IMPORT NTSTATUS WINAPI NtQuerySystemTime(int64_t *);
IMPORT NTSTATUS WINAPI NtAllocateVirtualMemory(HANDLE, void **, uintptr_t, size_t *, DWORD, DWORD);
IMPORT NTSTATUS WINAPI NtFreeVirtualMemory(HANDLE, void **, size_t *, DWORD);
IMPORT NTSTATUS WINAPI NtCreateKeyedEvent(HANDLE *, DWORD, void *, DWORD);
IMPORT NTSTATUS WINAPI LdrGetDllHandle(const WCHAR *, DWORD, const UNICODE_STRING *, HANDLE *);
IMPORT NTSTATUS WINAPI LdrGetProcedureAddress(HANDLE, const ANSI_STRING *, DWORD, void **);

static int equal(const char *a, const char *b) {
    while (*a && *a == *b) ++a, ++b;
    return *a == *b;
}

void entry(void) {
    UNICODE_STRING hello, other;
    RtlInitUnicodeString(&hello, L"Hello, ntdll");
    if (hello.Length != 24 || hello.MaximumLength != 26) ExitProcess(10);

    /* Wine's conversion allocates through RtlAllocateHeap: the runtime heap. */
    ANSI_STRING ansi;
    if (RtlUnicodeStringToAnsiString(&ansi, &hello, 1) || !equal(ansi.Buffer, "Hello, ntdll")) ExitProcess(11);
    RtlFreeAnsiString(&ansi);

    RtlInitUnicodeString(&other, L"HELLO, NTDLL");
    if (RtlCompareUnicodeString(&hello, &other, 1) != 0 || RtlCompareUnicodeString(&hello, &other, 0) <= 0)
        ExitProcess(12);

    DWORD value = 0;
    if (RtlCharToInteger("0x7fff", 0, &value) || value != 0x7fff) ExitProcess(13);

    int64_t time = 132223104000000000LL; /* 2020-01-01 00:00:00 */
    TIME_FIELDS fields;
    RtlTimeToTimeFields(&time, &fields);
    if (fields.Year != 2020 || fields.Month != 1 || fields.Day != 1 || fields.Weekday != 3) ExitProcess(14);

    if (RtlNtStatusToDosError((NTSTATUS)0xC0000034) != 2) ExitProcess(15);

    char text[64];
    if (_snprintf(text, sizeof text, "%s %d %05x %ls", "fmt", -42, 0xbeef, L"wide") != 18 ||
        !equal(text, "fmt -42 0beef wide"))
        ExitProcess(16);

    /* One heap: ntdll allocations free through kernel32, and vice versa. */
    void *block = RtlAllocateHeap(GetProcessHeap(), 8, 64);
    if (!block || ((unsigned char *)block)[63] || !HeapFree(GetProcessHeap(), 0, block)) ExitProcess(17);

    /* One last error: TEB->LastErrorValue. */
    SetLastError(1234);
    if (RtlGetLastWin32Error() != 1234 || GetLastError() != 1234) ExitProcess(18);

    /* Syscalls reach the runtime. */
    int64_t now = 0;
    if (NtQuerySystemTime(&now) || now < time) ExitProcess(19);
    void *base = 0;
    size_t size = 0x3000;
    if (NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, 0x3000, 4) || !base || size != 0x3000) ExitProcess(20);
    ((volatile char *)base)[0x2fff] = 1;
    size = 0;
    if (NtFreeVirtualMemory((HANDLE)-1, &base, &size, 0x8000)) ExitProcess(21);
    HANDLE event;
    if (NtCreateKeyedEvent(&event, 0, 0, 0) != (NTSTATUS)0xC0000002) ExitProcess(22);

    /* Loader entry points use the runtime's module list. */
    UNICODE_STRING ntdll_name;
    RtlInitUnicodeString(&ntdll_name, L"ntdll.dll");
    HANDLE ntdll = 0;
    if (LdrGetDllHandle(0, 0, &ntdll_name, &ntdll) || ntdll != GetModuleHandleW(L"ntdll.dll")) ExitProcess(23);
    ANSI_STRING symbol = {13, 14, "RtlInitString"};
    void *address = 0;
    if (LdrGetProcedureAddress(ntdll, &symbol, 0, &address) || !address) ExitProcess(24);
    ExitProcess(0);
}
