/*
 * Runtime-generated code in VirtualAlloc memory.
 *
 * 1. payload.s is copied into a PAGE_READWRITE buffer, switched to
 *    PAGE_EXECUTE_READ, and called through a function pointer. It runs in the
 *    launcher's x86 interpreter and calls back into compiled code.
 * 2. A PAGE_EXECUTE_READWRITE stub is called, patched in place, and called
 *    again without changing its protection.
 * 3. Calling into the payload after VirtualProtect(PAGE_READWRITE) raises an
 *    execute access violation (ExceptionInformation[0] == 8) at the buffer.
 *
 * Exit status 0 means every step passed; 100 + i names a wrong out[i].
 */
#include "../dynamic_dll/win32.h"

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define RESULTS 34

struct exception_record {
    DWORD code, flags;
    void *nested, *address;
    DWORD count;
    ULONG_PTR arguments[15];
};
struct exception_pointers {
    struct exception_record *record;
    unsigned char *context;
};

IMPORT void *WINAPI AddVectoredExceptionHandler(DWORD, long (WINAPI *)(struct exception_pointers *));
IMPORT void *WINAPI VirtualAlloc(void *, size_t, DWORD, DWORD);
IMPORT BOOL WINAPI VirtualFree(void *, size_t, DWORD);
IMPORT BOOL WINAPI VirtualProtect(void *, size_t, DWORD, DWORD *);

typedef void (*Payload)(uint64_t *, uint64_t (*)(uint64_t));
typedef DWORD (*Stub)(void);

static const unsigned char payload[] = {
#include "payload.inc"
};

static const uint64_t expected[RESULTS] = {
    0x1233, 0x7ff0, 0x180, 16, 6, 0xf0f0f0f0, 956,
    0xffffffffffffff80, 0x12, 0xffff8001, 0xffffffff80000000, 0xbeef,
    0xfffffffffffffffe, 0x10000000, 0x18000000, 9, 0xffffffff, 7,
    0x0100010100010001, 0x0100010001000001,
    0xffffffd6, 0x100000000, 1, 0xfffffffffffffff2, 2, 4, 55, 42, 0x28, 234,
    0x10000, 0xabababababababab, 0x1122334455667788, 0x77,
};

static uint64_t out[RESULTS];
static volatile unsigned char *code;
static volatile unsigned faults;

__attribute__((noinline)) uint64_t callback(uint64_t value) {
    return value + 1;
}

/* Byte loop instead of memcpy: the fixture has no CRT. */
static void copy(volatile unsigned char *destination, const unsigned char *source, size_t size) {
    for (size_t i = 0; i < size; ++i)
        destination[i] = source[i];
}

static void after_execute_fault(void) {
    if (faults != 1 || !VirtualFree((void *)code, 0, MEM_RELEASE))
        ExitProcess(40);
    ExitProcess(0);
}

static long WINAPI on_fault(struct exception_pointers *info) {
    struct exception_record *record = info->record;
    if (record->code != 0xc0000005 || record->count != 2 || record->arguments[0] != 8 ||
        record->arguments[1] != (ULONG_PTR)code || record->address != (void *)code)
        return 0;
    ++faults;
    ULONG_PTR *rsp = (ULONG_PTR *)(info->context + 0x98);
    *rsp = (*rsp & ~(ULONG_PTR)15) - 8;
    *(ULONG_PTR *)(info->context + 0xf8) = (ULONG_PTR)after_execute_fault;
    return -1;
}

void entry(void) {
    DWORD old = 0;
    code = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!code)
        ExitProcess(10);
    copy(code, payload, sizeof payload);
    if (!VirtualProtect((void *)code, 0x10000, PAGE_EXECUTE_READ, &old) || old != PAGE_READWRITE)
        ExitProcess(11);
    ((Payload)code)(out, callback);
    for (unsigned i = 0; i < RESULTS; ++i)
        if (out[i] != expected[i])
            ExitProcess(100 + i);

    /* mov eax, imm32; ret */
    static const unsigned char stub[] = {0xb8, 0x11, 0, 0, 0, 0xc3};
    volatile unsigned char *rwx = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!rwx)
        ExitProcess(20);
    copy(rwx, stub, sizeof stub);
    if (((Stub)rwx)() != 0x11)
        ExitProcess(21);
    rwx[1] = 0x22;
    if (((Stub)rwx)() != 0x22)
        ExitProcess(22);
    if (!VirtualFree((void *)rwx, 0, MEM_RELEASE))
        ExitProcess(23);

    if (!AddVectoredExceptionHandler(1, on_fault))
        ExitProcess(30);
    if (!VirtualProtect((void *)code, 0x10000, PAGE_READWRITE, &old) || old != PAGE_EXECUTE_READ)
        ExitProcess(31);
    ((Payload)code)(out, callback);
    ExitProcess(32);
}
