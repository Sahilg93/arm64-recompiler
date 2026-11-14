#include "../dynamic_dll/win32.h"

struct exception_record {
    DWORD code, flags;
    void *nested, *address;
    DWORD count;
    ULONG_PTR arguments[15];
};
struct exception_pointers {
    struct exception_record *record;
    void *context;
};

IMPORT void WINAPI RaiseException(DWORD, DWORD, DWORD, const ULONG_PTR *);
IMPORT void *WINAPI AddVectoredExceptionHandler(DWORD, long (WINAPI *)(struct exception_pointers *));
IMPORT unsigned long WINAPI RemoveVectoredExceptionHandler(void *);

typedef long (WINAPI *Random)(void *, unsigned char *, DWORD, DWORD);
IMPORT long WINAPI RegOpenKeyExW(HANDLE, const wchar_t *, DWORD, DWORD, HANDLE *);
IMPORT long WINAPI RegQueryValueExW(HANDLE, const wchar_t *, DWORD *, DWORD *,
                                   unsigned char *, DWORD *);
IMPORT long WINAPI RegCloseKey(HANDLE);

typedef ULONG_PTR SOCKET;
struct address {
    unsigned short family, port;
    DWORD ip;
    unsigned char padding[8];
};
IMPORT int WINAPI WSAStartup(unsigned short, void *);
IMPORT int WINAPI WSACleanup(void);
IMPORT int WINAPI WSAGetLastError(void);
IMPORT SOCKET WINAPI socket(int, int, int);
IMPORT int WINAPI bind(SOCKET, const struct address *, int);
IMPORT int WINAPI getsockname(SOCKET, struct address *, int *);
IMPORT int WINAPI listen(SOCKET, int);
IMPORT int WINAPI connect(SOCKET, const struct address *, int);
IMPORT SOCKET WINAPI accept(SOCKET, struct address *, int *);
IMPORT int WINAPI send(SOCKET, const char *, int, int);
IMPORT int WINAPI recv(SOCKET, char *, int, int);
IMPORT int WINAPI closesocket(SOCKET);

static void loopback(void) {
    const SOCKET invalid = (SOCKET)-1;
    unsigned char data[408];
    if (WSAStartup(0x202, data) || data[0] != 2 || data[1] != 2)
        ExitProcess(7);
    if (closesocket(invalid) != -1 || WSAGetLastError() != 10038)
        ExitProcess(8);
    SOCKET listener = socket(2, 1, 6), client = socket(2, 1, 6);
    struct address address = {2, 0, 0x0100007f, {0}};
    int length = sizeof address;
    if (listener == invalid || client == invalid ||
        bind(listener, &address, length) || getsockname(listener, &address, &length) ||
        listen(listener, 1) || connect(client, &address, length))
        ExitProcess(9);
    SOCKET server = accept(listener, NULL, NULL);
    char received = 0;
    if (server == invalid || send(client, "x", 1, 0) != 1 ||
        recv(server, &received, 1, 0) != 1 || received != 'x')
        ExitProcess(10);
    if (closesocket(server) || closesocket(client) || closesocket(listener) || WSACleanup())
        ExitProcess(11);
}

static volatile DWORD observed;

static long WINAPI handler(struct exception_pointers *info) {
    if (info->record->code != 0xe0001234 || info->record->count != 1 ||
        info->record->arguments[0] != 17 || !info->context)
        return 0;
    ++observed;
    return -1;
}

void raise_in_frame(void);

int language_handler(struct exception_record *record, ULONG_PTR frame, void *context, void *dispatcher) {
    if (record->code != 0xe0001235 || !frame || !context || !dispatcher)
        return 1;
    ++observed;
    return 0;
}

static unsigned char unwind_context[0x4d0] __attribute__((aligned(16)));
static struct exception_record unwind_record;

__declspec(noreturn) void begin_consolidation(ULONG_PTR, void *, ULONG_PTR, struct exception_record *);
static long WINAPI fault_handler(struct exception_pointers *);
void fault_read(void);

static void continuation(void) {
    if (observed != 4 || !AddVectoredExceptionHandler(1, fault_handler))
        ExitProcess(13);
    fault_read();
    ExitProcess(17);
}

static ULONG_PTR consolidate(struct exception_record *record) {
    if (record != &unwind_record || observed != 3)
        ExitProcess(14);
    ++observed;
    return (ULONG_PTR)continuation;
}

int cleanup_handler(struct exception_record *record, ULONG_PTR frame, void *context, void *dispatcher) {
    if (record != &unwind_record || !(record->flags & 2) || !frame || !context || !dispatcher || observed != 2)
        ExitProcess(15);
    ++observed;
    return 1;
}

IMPORT HANDLE WINAPI CreateFileMappingW(HANDLE, void *, DWORD, DWORD, DWORD, const wchar_t *);
IMPORT void *WINAPI MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, ULONG_PTR);
static void *read_only_view;

static void after_signal(void) {
    ExitProcess(observed == 6 ? 0 : 16);
}

static void after_fault(void) {
    HANDLE map = CreateFileMappingW((HANDLE)(intptr_t)-1, NULL, 4, 0, 4096, NULL);
    if (!map)
        ExitProcess(18);
    read_only_view = MapViewOfFile(map, 4, 0, 0, 0);
    if (!read_only_view)
        ExitProcess(19);
    *(volatile char *)read_only_view = 1;
    ExitProcess(20);
}

static long WINAPI fault_handler(struct exception_pointers *info) {
    struct exception_record *record = info->record;
    if (record->code != 0xc0000005 || record->count != 2 || !record->address)
        return 0;
    ULONG_PTR *rip = (ULONG_PTR *)((unsigned char *)info->context + 0xf8);
    if (observed == 4 && !record->arguments[0] && !record->arguments[1])
        *rip = (ULONG_PTR)after_fault;
    else if (observed == 5 && record->arguments[0] == 1 &&
             record->arguments[1] == (ULONG_PTR)read_only_view)
        *rip = (ULONG_PTR)after_signal;
    else
        return 0;
    ++observed;
    return -1;
}

void entry(void) {
    void *registration = AddVectoredExceptionHandler(1, handler);
    if (!registration)
        ExitProcess(1);
    const ULONG_PTR argument = 17;
    RaiseException(0xe0001234, 0, 1, &argument);
    if (observed != 1 || !RemoveVectoredExceptionHandler(registration))
        ExitProcess(2);
    raise_in_frame();
    if (observed != 2)
        ExitProcess(12);
    unsigned char random[32];
    HMODULE crypto = LoadLibraryW(L"bcrypt.dll");
    if (!crypto)
        ExitProcess(3);
    Random generate = (Random)GetProcAddress(crypto, "BCryptGenRandom");
    if (!generate || generate(NULL, random, sizeof random, 2) || !FreeLibrary(crypto))
        ExitProcess(3);
    HANDLE key = NULL;
    DWORD size = 0, type = 0;
    if (RegOpenKeyExW((HANDLE)(intptr_t)(int32_t)0x80000002, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, 0x20019, &key))
        ExitProcess(4);
    if (RegQueryValueExW(key, L"SystemRoot", NULL, &type, NULL, &size) || type != 1 || size < 4)
        ExitProcess(5);
    wchar_t root[64];
    size = sizeof root;
    if (RegQueryValueExW(key, L"SystemRoot", NULL, &type, (unsigned char *)root, &size) ||
        !root[0] || root[size / sizeof *root - 1] || RegCloseKey(key))
        ExitProcess(6);
    loopback();
    unwind_record.code = 0x80000029;
    unwind_record.count = 1;
    unwind_record.arguments[0] = (ULONG_PTR)consolidate;
    begin_consolidation(0, unwind_context, (ULONG_PTR)continuation, &unwind_record);
}
