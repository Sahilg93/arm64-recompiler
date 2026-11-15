/*
 * Hardware faults on raw VirtualAlloc memory must reach guest handlers.
 *
 * VirtualAlloc returns untagged host mmap addresses. Every access below that
 * faults is a real SIGSEGV/SIGBUS on Darwin: the runtime turns it into
 * EXCEPTION_ACCESS_VIOLATION with the guest address and read/write flag, then
 * dispatches it to the vectored handler or, for the last case, to the
 * table-driven handler attached to seh_read in seh.s.
 *
 * Each step exits with a distinct status so a failure names the step.
 */
#include "../dynamic_dll/win32.h"

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define REGION_SIZE 0x10000

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
IMPORT unsigned long WINAPI RemoveVectoredExceptionHandler(void *);
IMPORT void *WINAPI VirtualAlloc(void *, size_t, DWORD, DWORD);
IMPORT BOOL WINAPI VirtualFree(void *, size_t, DWORD);
IMPORT BOOL WINAPI VirtualProtect(void *, size_t, DWORD, DWORD *);

int seh_read(volatile int *);
int seh_resume(void);

static volatile unsigned char *region;
static volatile unsigned step;
static void *registration;

/* CONTEXT offsets for x64. */
static ULONG_PTR *context_slot(unsigned char *context, unsigned offset) {
    return (ULONG_PTR *)(context + offset);
}

/* Resume in a fresh frame: Rip at a continuation, Rsp aligned as after a call. */
static void redirect(unsigned char *context, void (*target)(void)) {
    ULONG_PTR *rsp = context_slot(context, 0x98);
    *rsp = (*rsp & ~(ULONG_PTR)15) - 8;
    *context_slot(context, 0xf8) = (ULONG_PTR)target;
}

static int is_violation(const struct exception_record *record, ULONG_PTR writing, ULONG_PTR address) {
    return record->code == 0xc0000005 && record->count == 2 && record->address &&
           record->arguments[0] == writing && record->arguments[1] == address;
}

static void after_read_only_write(void);
static void after_no_access_read(void);

static long WINAPI vectored(struct exception_pointers *info) {
    if (step == 1 && is_violation(info->record, 0, (ULONG_PTR)(region + 0x40)))
        redirect(info->context, after_no_access_read);
    else if (step == 2 && is_violation(info->record, 1, (ULONG_PTR)(region + 0x80)))
        redirect(info->context, after_read_only_write);
    else
        return 0; /* EXCEPTION_CONTINUE_SEARCH */
    ++step;
    return -1; /* EXCEPTION_CONTINUE_EXECUTION */
}

/* Language-specific handler for seh_read, reached only through .pdata/.xdata. */
int seh_handler(struct exception_record *record, ULONG_PTR frame, unsigned char *context, void *dispatcher) {
    if (step != 3 || !frame || !dispatcher || !is_violation(record, 0, (ULONG_PTR)(region + 0xc0)))
        return 1; /* ExceptionContinueSearch */
    ++step;
    /* Pop seh_read's 40-byte frame and finish the call in seh_resume, which
       returns 0x73 into the middle of after_read_only_write. */
    *context_slot(context, 0x98) += 40;
    *context_slot(context, 0xf8) = (ULONG_PTR)seh_resume;
    return 0; /* ExceptionContinueExecution */
}

static void finish(void) {
    DWORD old = 0;
    if (!VirtualProtect((void *)region, REGION_SIZE, PAGE_READWRITE, &old) || old != PAGE_NOACCESS)
        ExitProcess(40);
    if (region[0x40] != 0x5a || region[0x80] != 0)
        ExitProcess(41);
    if (!VirtualFree((void *)region, 0, MEM_RELEASE))
        ExitProcess(42);
    ExitProcess(0);
}

/*
 * The vectored continuations below never return. The table-driven case does:
 * seh_resume returns into the middle of after_read_only_write, which the
 * launcher runs in its x86 interpreter because no compiled entry starts there.
 */
static void after_read_only_write(void) {
    DWORD old = 0;
    if (step != 3 || region[0x40] != 0x5a || region[0x80] != 0)
        ExitProcess(30);
    if (!RemoveVectoredExceptionHandler(registration))
        ExitProcess(31);
    if (!VirtualProtect((void *)region, REGION_SIZE, PAGE_NOACCESS, &old) || old != PAGE_READONLY)
        ExitProcess(32);
    if (seh_read((volatile int *)(region + 0xc0)) != 0x73 || step != 4)
        ExitProcess(33);
    finish();
}

static void after_no_access_read(void) {
    DWORD old = 0;
    if (step != 2)
        ExitProcess(20);
    if (VirtualAlloc((void *)region, REGION_SIZE, MEM_COMMIT, PAGE_READWRITE) != region)
        ExitProcess(21);
    region[0x40] = 0x5a;
    if (region[0x40] != 0x5a)
        ExitProcess(22);
    if (!VirtualProtect((void *)region, REGION_SIZE, PAGE_READONLY, &old) || old != PAGE_READWRITE)
        ExitProcess(23);
    region[0x80] = 1;
    ExitProcess(24);
}

void entry(void) {
    registration = AddVectoredExceptionHandler(1, vectored);
    if (!registration)
        ExitProcess(10);
    region = VirtualAlloc(NULL, REGION_SIZE, MEM_RESERVE, PAGE_NOACCESS);
    if (!region || ((ULONG_PTR)region >> 56))
        ExitProcess(11);
    step = 1;
    (void)region[0x40];
    ExitProcess(12);
}
