#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dlfcn.h>
#include <math.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdatomic.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <malloc/malloc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/resource.h>
#include <spawn.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>

#include "console_modules.h"
__attribute__((weak)) struct guest_module *guest_modules;
__attribute__((weak)) const size_t guest_module_count = 0;
/*
 * Lifted DLLs built as shared libraries (build_console_modules.py): one file
 * name per guest_modules entry, and the module store they were built into.
 * NULL when the modules are linked into the program.
 */
__attribute__((weak)) const char *const *guest_module_libraries;
__attribute__((weak)) const char *guest_module_store;
extern const struct section guest_sections[];
extern const uint64_t guest_section_count;
static unsigned char **image;
static uint32_t *section_protection;
static _Thread_local void *current_cpu = NULL;
void guest_set_cpu(void *cpu) { current_cpu = cpu; }
/*
 * Guest memory is identity-mapped: a guest address is the host address of the
 * same byte. macOS maps nothing below 4 GiB in an arm64 process, so smaller
 * values are never memory (null, handles, call tokens, legacy bare RVAs).
 */
#define GUEST_HOST_FLOOR UINT64_C(0x100000000)
extern const uint64_t guest_image_base;
extern uint32_t lifted_console(void);

void guest_init_critical(uint64_t address, uint32_t spin_count);
void guest_critical_section(uint64_t address, uint32_t entering);
static bool guest_try_critical_section(uint64_t address);
uint64_t guest_virtual_protect(uint64_t address, uint64_t size, uint32_t new_protect, uint64_t old_protect_ptr);
void *guest_pointer(uint64_t addr, uint32_t width);
uint64_t guest_acrt_iob_func(uint32_t index);
uint64_t guest_errno(void);
uint64_t guest_fwrite(uint64_t buffer, uint64_t size, uint64_t count, uint64_t stream);
uint64_t guest_fputs(uint64_t str, uint64_t stream);
uint64_t guest_fflush(uint64_t stream);
uint64_t guest_fputc(uint32_t ch, uint64_t stream);
uint64_t guest_putchar(uint32_t ch);
uint64_t guest_puts(uint64_t str);
uint64_t guest_setvbuf(uint64_t stream, uint64_t buffer, uint32_t mode, uint64_t size);
uint64_t guest_add_vectored_exception_handler(uint32_t first, uint64_t handler);
uint64_t guest_remove_vectored_exception_handler(uint64_t handle);
uint64_t guest_message_box_a(uint64_t hwnd, uint64_t text_ptr, uint64_t caption_ptr, uint32_t type);
uint64_t guest_message_box_w(uint64_t hwnd, uint64_t text_ptr, uint64_t caption_ptr, uint32_t type);
uint64_t guest_crt_atexit(uint64_t fn);
uint64_t guest_register_onexit(uint64_t table, uint64_t fn);
uint64_t guest_init_onexit(uint64_t table);
uint64_t guest_exec_onexit(uint64_t table);
uint64_t guest_initterm(uint64_t start, uint64_t end);
uint64_t guest_initterm_e(uint64_t start, uint64_t end);
uint64_t guest_configure_argv(uint32_t mode);
uint64_t guest_init_env(void);
uint64_t guest_get_initial_env(void);
uint64_t guest_set_app_type(uint32_t type);
uint64_t guest_seh_filter_exe(uint32_t code, uint64_t info);
uint64_t guest_set_invalid_param(uint64_t handler);
uint64_t guest_p_argc(void);
uint64_t guest_p_wargv(void);
uint64_t guest_p_argv(void);
uint64_t guest_p_fmode(void);
uint64_t guest_p_commode(void);
uint64_t guest_p_wenviron(void);
uint64_t guest_p_environ(void);
uint64_t guest_cexit(void);
uint64_t guest_set_thread_stack_guarantee(uint64_t size_ptr);
uint64_t guest_set_new_mode(uint32_t mode);
uint64_t guest_wcslen(uint64_t str);
uint64_t guest_wcsnlen(uint64_t str, uint64_t maxlen);
uint64_t guest_strlen(uint64_t str);
uint64_t guest_strnlen(uint64_t str, uint64_t maxlen);
uint64_t guest_memset(uint64_t dest, uint32_t c, uint64_t count);
uint64_t guest_memcpy(uint64_t dest, uint64_t src, uint64_t count);
uint64_t guest_strcmp(uint64_t s1, uint64_t s2);
uint64_t guest_strncmp(uint64_t s1, uint64_t s2, uint64_t n);
uint64_t guest_strcpy(uint64_t dest, uint64_t src);
uint64_t guest_strdup(uint64_t str);
uint64_t guest_isalnum(uint32_t c);
uint64_t guest_isalpha(uint32_t c);
uint64_t guest_isspace(uint32_t c);
uint64_t guest_process_prng(uint64_t buffer, uint64_t size);
uint64_t guest_performance_counter(uint64_t address);
void guest_system_filetime(uint64_t address);
uint64_t guest_command_line(uint32_t wide);
uint64_t guest_convert_text(uint32_t wide, uint32_t page, uint32_t flags,
                            uint64_t source, int32_t length, uint64_t dest, uint64_t size);
void guest_set_last_error(uint32_t value);
uint64_t guest_get_last_error(void);
uint64_t guest_stdout(uint32_t selector);
uint64_t guest_qsort(uint64_t base, uint64_t num, uint64_t width, uint64_t compar);
uint64_t guest_identity(uint32_t thread);
uint64_t guest_exception_filter(uint64_t handler);
uint64_t guest_write(uint64_t handle, uint64_t address, uint32_t count, uint64_t written, uint64_t overlapped);
uint64_t guest_get_handle_info(uint64_t handle, uint64_t flags_ptr);
uint64_t guest_tick_count_64(void);
uint64_t guest_tick_count(void);
uint64_t guest_performance_frequency(uint64_t address);
uint64_t guest_is_processor_feature_present(uint32_t feature);
uint64_t guest_unhandled_exception_filter(uint64_t info);
uint64_t guest_terminate_process(uint64_t handle, uint32_t exit_code);
void guest_rtl_capture_context(uint64_t ctx);
void guest_raise_exception(uint32_t, uint32_t, uint32_t, uint64_t, uint64_t, uint64_t);
static bool guest_code_contains(uint64_t, uint64_t);
uint64_t guest_rtl_lookup_function_entry(uint64_t pc, uint64_t image_base_ptr, uint64_t history_table);
uint64_t guest_rtl_virtual_unwind(uint32_t handler_type, uint64_t image_base, uint64_t control_pc,
                                  uint64_t entry, uint64_t ctx, uint64_t data, uint64_t frame, uint64_t pointers);

__attribute__((weak)) const uint64_t guest_tls_start_raw = 0;
__attribute__((weak)) const uint64_t guest_tls_end_raw = 0;
__attribute__((weak)) const uint64_t guest_tls_index_va = 0;
__attribute__((weak)) const uint64_t guest_tls_zero_fill = 0;

enum {
    STACK_SIZE = 1048576,
    IOBUF_ENTRY_SIZE = 48, IOBUF_COUNT = 3,
    RUNTIME_DATA_SIZE = 4096,
    TLS_SIZE = 1048576
};
/* Guest memory backed by host arrays: keep it 16-byte aligned so aligned guest
   accesses (including lifted atomics, which fault when misaligned) stay aligned. */
static _Alignas(16) unsigned char stack[STACK_SIZE];
/* Larger than a real TEB (0x1838 bytes): lifted ntdll writes fields such as LastStatusValue at 0x1250. */
static _Thread_local _Alignas(16) unsigned char teb_storage[0x4000];
static _Alignas(16) unsigned char peb_storage[4096];
/*
 * Hosted on Wine's unix side (ARM64_RECOMPILER_WINE_HOST, see wine-host/), the
 * TEB and PEB are the ones Wine allocated: its native code and the lifted
 * Windows code share them (thread info, last error, callback table).
 */
static bool wine_hosted;
static _Thread_local unsigned char *host_teb;
static unsigned char *host_peb;
#define teb (host_teb ? host_teb : teb_storage)
#define peb (host_peb ? host_peb : peb_storage)
static _Alignas(16) unsigned char iobuf[IOBUF_COUNT * IOBUF_ENTRY_SIZE];
static _Thread_local int guest_errno_storage;
static _Alignas(16) unsigned char runtime_data[RUNTIME_DATA_SIZE];
static _Thread_local _Alignas(16) unsigned char tls_storage[TLS_SIZE];
/* These regions are identity-mapped: the guest address is the host address. */
#define GUEST_ADDRESS(object) ((uint64_t)(uintptr_t)(object))
#define STACK_BASE GUEST_ADDRESS(stack)
#define TEB_BASE GUEST_ADDRESS(teb)
#define PEB_BASE GUEST_ADDRESS(peb)
#define IOBUF_BASE GUEST_ADDRESS(iobuf)
#define ERRNO_BASE GUEST_ADDRESS(&guest_errno_storage)
#define RUNTIME_DATA_BASE GUEST_ADDRESS(runtime_data)
#define ARGC_BASE (RUNTIME_DATA_BASE + 0x00)
#define ARGV_BASE (RUNTIME_DATA_BASE + 0x10)
#define WARGV_BASE (RUNTIME_DATA_BASE + 0x20)
#define FMODE_BASE (RUNTIME_DATA_BASE + 0x30)
#define COMMODE_BASE (RUNTIME_DATA_BASE + 0x38)
#define WENVIRON_BASE (RUNTIME_DATA_BASE + 0x40)
#define ENVIRON_BASE (RUNTIME_DATA_BASE + 0x48)
#define TLS_BASE GUEST_ADDRESS(tls_storage)
/* Size of the primary image mapping at guest_image_base (set in main). */
static uint64_t guest_image_span = 0x20000000;
/* The primary image's range, for lifted code's inlined store fast path (console_lift.py). */
extern const uint64_t guest_image_base;
uint64_t guest_primary_base, guest_primary_span;

/*
 * Windows keeps its shared user data page at 0x7ffe0000 and lifted system code
 * reads it there. Nothing can be mapped below 4 GiB, so hosted Wine keeps the
 * page 4 GiB higher and the slow paths redirect to it.
 */
static inline uint64_t guest_low_alias(uint64_t addr) {
    return wine_hosted && addr - UINT64_C(0x7ffe0000) < 0x1000 ? addr + UINT64_C(0x100000000) : addr;
}

/* True when addr is its own host pointer: at or above the host floor and outside
   the primary image, whose accesses keep their per-section protection checks. */
static inline bool guest_direct(uint64_t addr) {
    return addr >= GUEST_HOST_FLOOR && addr - guest_image_base >= guest_image_span;
}

/* The current thread's TEB (the guest GS base) and the main thread's stack top. */
uint64_t guest_teb(void) { return TEB_BASE; }
uint64_t guest_initial_stack(void) { return STACK_BASE + STACK_SIZE; }

static int host_argc;
static char **host_argv;

static void init_runtime_data(void) {
    memset(runtime_data, 0, sizeof runtime_data);
    int argc = host_argc > 0 ? host_argc : 1;
    if (argc > 32) argc = 32;
    memcpy(runtime_data + 0x00, &argc, sizeof argc);
    uint64_t argv_ptr = RUNTIME_DATA_BASE + 0x100;
    memcpy(runtime_data + 0x10, &argv_ptr, sizeof argv_ptr);
    uint64_t wargv_ptr = RUNTIME_DATA_BASE + 0x200;
    memcpy(runtime_data + 0x20, &wargv_ptr, sizeof wargv_ptr);
    uint64_t wenviron_ptr = RUNTIME_DATA_BASE + 0x0a0;
    memcpy(runtime_data + 0x40, &wenviron_ptr, sizeof wenviron_ptr);
    uint64_t environ_ptr = RUNTIME_DATA_BASE + 0x0c0;
    memcpy(runtime_data + 0x48, &environ_ptr, sizeof environ_ptr);

    uint64_t str_offset = 0x400;
    for (int i = 0; i < argc; ++i) {
        const char *arg = (host_argv && host_argv[i]) ? host_argv[i] : (i == 0 ? "app.exe" : "");
        size_t len = strlen(arg);
        if (str_offset + len + 1 >= RUNTIME_DATA_SIZE) break;

        uint64_t arg_addr = RUNTIME_DATA_BASE + str_offset;
        memcpy(runtime_data + 0x100 + i * 8, &arg_addr, 8);
        memcpy(runtime_data + str_offset, arg, len + 1);
        str_offset += len + 1;

        if (str_offset & 1) str_offset++;
        if (str_offset + (len + 1) * 2 >= RUNTIME_DATA_SIZE) break;

        uint64_t warg_addr = RUNTIME_DATA_BASE + str_offset;
        memcpy(runtime_data + 0x200 + i * 8, &warg_addr, 8);
        for (size_t c = 0; c <= len; ++c) {
            uint16_t w = (uint16_t)(unsigned char)arg[c];
            memcpy(runtime_data + str_offset + c * 2, &w, 2);
        }
        str_offset += (len + 1) * 2;
        str_offset = (str_offset + 7) & ~7ULL;
    }
}

static void put64(unsigned char *data, unsigned offset, uint64_t value) {
    memcpy(data + offset, &value, sizeof value);
}
/* Win32 last error lives in TEB->LastErrorValue, where lifted Wine code reads it inline. */
#define last_error (*(uint32_t *)(void *)(teb + 0x68))

static bool fits(uint64_t addr, uint64_t size, uint64_t start, uint64_t length) {
    return addr >= start && size <= length && addr - start <= length - size;
}

static _Thread_local uint64_t guest_pc, guest_fault_pc;
static _Thread_local bool delivering_fault;

/*
 * Image-section fast path. Loads and stores into the primary image's own
 * sections (.data/.rdata globals, jump tables) are the hottest non-stack,
 * non-heap guest accesses. While every host page of a section is readable
 * (writable), a load (store) that fits the section cannot fault and needs no
 * armed signal state. Bit i of image_read_fast / image_write_fast says
 * section i qualifies; guest_virtual_protect recomputes the bits from the
 * per-page guest protection in image_prot, so a temporary VirtualProtect
 * (MinGW's pseudo-relocator) only diverts the section to the faultable slow
 * path until its pages are restored. Anything the fast path declines
 * (straddling, unmapped, protected) takes the slow path unchanged.
 */
static _Atomic uint64_t image_read_fast, image_write_fast;
/* image_page_section[rva >> 12] is 1 + the section owning that 4 KiB page, or 0. */
static uint8_t *image_page_section;
static uint64_t image_page_limit;
/* image_prot[rva >> 12] is the POSIX protection of that 4 KiB guest page. */
static uint8_t *image_prot;
static uint64_t image_prot_pages;

/*
 * Guest images are mapped at their own guest addresses, so a guest pointer
 * into an image is also the host pointer. The range must be free in the host
 * process; VM_FLAGS_FIXED fails instead of replacing an existing mapping.
 */
static unsigned char *guest_map_fixed(uint64_t base, uint64_t size) {
    vm_size_t page = (vm_size_t)sysconf(_SC_PAGESIZE);
    vm_address_t address = (vm_address_t)base;
    vm_size_t length = ((vm_size_t)size + page - 1) & ~(page - 1);
    if (!base || (base & (page - 1)) || !length ||
        vm_allocate(mach_task_self(), &address, length, VM_FLAGS_FIXED) != KERN_SUCCESS)
        return NULL;
    return (unsigned char *)address;
}

static void guest_unmap_fixed_range(uint64_t base, uint64_t size);

/*
 * Replace an already claimed guest range with a private copy-on-write mapping
 * of a page-aligned image held in the executable's data. Returns false (leaving
 * the range as it was) when there is no such image or the kernel refuses.
 */
static bool guest_map_image_copy(uint64_t base, const unsigned char *source, uint64_t size) {
    mach_vm_size_t page = (mach_vm_size_t)sysconf(_SC_PAGESIZE);
    if (!source || ((uintptr_t)source & (page - 1)) || (base & (page - 1)))
        return false;
    mach_vm_address_t target = base;
    vm_prot_t current, maximum;
    kern_return_t result = mach_vm_remap(mach_task_self(), &target, (size + page - 1) & ~(page - 1), 0,
                                         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
                                         (mach_vm_address_t)(uintptr_t)source, TRUE, &current, &maximum,
                                         VM_INHERIT_COPY);
    if (result != KERN_SUCCESS)
        return false;
    if ((current & (VM_PROT_READ | VM_PROT_WRITE)) != (VM_PROT_READ | VM_PROT_WRITE) &&
        mprotect((void *)(uintptr_t)base, (size_t)((size + page - 1) & ~(page - 1)), PROT_READ | PROT_WRITE)) {
        /* Unusable: put plain zero-filled memory back for the copying path. */
        guest_unmap_fixed_range(base, size);
        return false;
    }
    return true;
}

static void guest_unmap_fixed(uint64_t base, uint64_t size) {
    vm_size_t page = (vm_size_t)sysconf(_SC_PAGESIZE);
    vm_deallocate(mach_task_self(), (vm_address_t)base, ((vm_size_t)size + page - 1) & ~(page - 1));
}

static void guest_unmap_fixed_range(uint64_t base, uint64_t size) {
    guest_unmap_fixed(base, size);
    guest_map_fixed(base, size);
}

/* Recompute section i's fast-path bits from its guest page protections. */
static void image_update_fast(uint64_t i, bool writable_section) {
    if (i >= 64)
        return;
    int all = PROT_READ | PROT_WRITE;
    uint64_t first = guest_sections[i].address >> 12;
    uint64_t end = (guest_sections[i].address + guest_sections[i].size + 0xfff) >> 12;
    for (uint64_t page = first; page < end && page < image_prot_pages; ++page)
        all &= image_prot[page];
    uint64_t bit = UINT64_C(1) << i;
    if (all & PROT_READ)
        atomic_fetch_or(&image_read_fast, bit);
    else
        atomic_fetch_and(&image_read_fast, ~bit);
    if ((all & PROT_WRITE) && writable_section)
        atomic_fetch_or(&image_write_fast, bit);
    else
        atomic_fetch_and(&image_write_fast, ~bit);
}

static inline __attribute__((always_inline)) unsigned char *image_fast_span(uint64_t addr, uint32_t width, bool write) {
    /* Lifted RIP-relative operands arrive as bare RVAs; guest pointers as VAs.
       Like read_span, accept both. A bare RVA is below 4 GiB, where no host
       (identity-mapped) address can be. */
    uint64_t rva = addr;
    if (guest_image_base && addr >= guest_image_base) {
        rva = addr - guest_image_base;
        if (rva >= guest_image_span)
            return NULL;
    } else if (addr >= UINT64_C(0x100000000) || !addr) {
        /* Address 0 is a null dereference: read_span raises the access violation. */
        return NULL;
    }
    uint64_t page = rva >> 12;
    if (page >= image_page_limit)
        return NULL;
    uint32_t i = image_page_section[page];
    if (!i--)
        return NULL;
    uint64_t mask = atomic_load_explicit(write ? &image_write_fast : &image_read_fast, memory_order_relaxed);
    if ((mask >> i & 1) && fits(rva, width, guest_sections[i].address, guest_sections[i].size))
        return image[i] + (rva - guest_sections[i].address);
    return NULL;
}
static void guest_access_violation(uint64_t, bool);

/* Set once any lifted code marks a fault PC. Modules lifted without fault
   delivery never do, so their hot heap accesses skip the thread-local checks. */
static _Atomic bool guest_fault_pcs_used;

void guest_mark_fault_pc(uint64_t address) {
    if (!atomic_load_explicit(&guest_fault_pcs_used, memory_order_relaxed))
        atomic_store_explicit(&guest_fault_pcs_used, true, memory_order_relaxed);
    guest_fault_pc = address;
}
static uint64_t watched_rva = UINT64_MAX;

uint64_t guest_load(uint64_t addr, uint32_t width);
void guest_set_pc(uint64_t address) {
    /* ARM64_RECOMPILER_PC_LOG=<file> records every traced guest PC (debugging aid). */
    static FILE *pc_log;
    static int pc_log_state;
    if (!pc_log_state) {
        const char *path = getenv("ARM64_RECOMPILER_PC_LOG");
        pc_log = path ? fopen(path, "w") : NULL;
        pc_log_state = 1;
    }
    if (pc_log)
        fprintf(pc_log, "%llx\n", (unsigned long long)address);
    guest_pc = address;
    if (address == watched_rva) {
        fprintf(stderr, "Reached guest RVA %#llx\n", (unsigned long long)address);
        watched_rva = UINT64_MAX;
    }
}

void guest_trap(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(125);
}

static void detach_guest_modules(void);

/* ExitProcess: DLLs receive DLL_PROCESS_DETACH (Wine's CRT flushes stdio there). */
void guest_exit(uint32_t status) {
    detach_guest_modules();
    exit((int)status);
}

void guest_require_register(uint8_t available, uint8_t required) {
    (void)available;
    (void)required;
}

void guest_check_xcr(uint32_t index, uint64_t rva) {
    if (index != 0) {
        fprintf(stderr, "RVA %#llx: unsupported XGETBV index %u\n",
                (unsigned long long)rva, index);
        exit(125);
    }
}

/*
 * Darwin hardware fault delivery. A host copy that implements a guest memory
 * access runs with guest_memory_access armed and records which host span
 * stands for which guest address. If the copy raises SIGSEGV or SIGBUS (a
 * PROT_NONE or read-only VirtualAlloc page, a read-only mapped view, a freed
 * heap block), the handler runs on the alternate stack, translates the
 * host fault address back to the guest address, and returns into
 * guest_fault_trampoline. The trampoline runs on the faulting thread's normal
 * stack, outside signal context, and dispatches EXCEPTION_ACCESS_VIOLATION to
 * the guest's vectored and table-driven handlers.
 */
static _Thread_local volatile sig_atomic_t guest_memory_access, guest_signal_ready;
static _Thread_local volatile uintptr_t guest_signal_address;
static _Thread_local volatile sig_atomic_t guest_signal_write;
static _Thread_local volatile uintptr_t guest_access_host;
static _Thread_local volatile uint64_t guest_access_guest, guest_access_size;
static _Thread_local volatile sig_atomic_t guest_access_write;

static void guest_fault_trampoline(void) {
    guest_memory_access = 0;
    guest_access_violation(guest_signal_address, guest_signal_write != 0);
    guest_trap("guest fault trampoline returned");
}

static void handle_guest_memory_signal(int sig, siginfo_t *info, void *context) {
    if (!guest_memory_access || !guest_signal_ready || info->si_code <= 0) {
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    ucontext_t *uc = context;
    uintptr_t host = (uintptr_t)info->si_addr;
    if (host >= guest_access_host && host - guest_access_host < guest_access_size) {
        guest_signal_address = guest_access_guest + (host - guest_access_host);
        guest_signal_write = guest_access_write;
    } else {
        guest_signal_address = host;
        guest_signal_write = (uc->uc_mcontext->__es.__esr >> 6) & 1;
    }
    guest_memory_access = 0;
    __darwin_arm_thread_state64_set_pc_fptr(uc->uc_mcontext->__ss, guest_fault_trampoline);
}

/* Fault delivery is on unless ARM64_RECOMPILER_FAULT_SIGNALS=0. */
static bool guest_fault_signals_enabled(void) {
    const char *setting = getenv("ARM64_RECOMPILER_FAULT_SIGNALS");
    return !setting || strcmp(setting, "0") != 0;
}

static void init_guest_signal_handler(void) {
    static _Thread_local _Alignas(16) unsigned char alternate_stack[65536];
    stack_t stack = {.ss_sp = alternate_stack, .ss_size = sizeof alternate_stack};
    if (sigaltstack(&stack, NULL))
        guest_trap("cannot install alternate guest signal stack");
    struct sigaction action = {.sa_sigaction = handle_guest_memory_signal,
                               .sa_flags = SA_SIGINFO | SA_ONSTACK};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) || sigaction(SIGBUS, &action, NULL))
        guest_trap("cannot install guest memory signal handlers");
    guest_signal_ready = 1;
}

/* Keep the signal armed only for the host copy implementing a guest access. */
static __attribute__((noinline)) void guest_faultable_copy(void *destination,
                                                          const void *source, size_t size,
                                                          uint64_t guest_address, bool writing) {
    guest_access_host = (uintptr_t)(writing ? destination : source);
    guest_access_guest = guest_address;
    guest_access_size = size;
    guest_access_write = writing;
    guest_memory_access = 1;
    atomic_signal_fence(memory_order_seq_cst);
    memcpy(destination, source, size);
    atomic_signal_fence(memory_order_seq_cst);
    guest_memory_access = 0;
}

/*
 * ARM64_RECOMPILER_TRACE_TIME=1: print elapsed and process CPU time at startup
 * phases and around each module load, to see where launch time goes.
 */
static void trace_time(const char *what, const char *detail) {
    static int enabled = -1;
    static struct timespec origin;
    if (enabled < 0) {
        enabled = getenv("ARM64_RECOMPILER_TRACE_TIME") != NULL;
        clock_gettime(CLOCK_MONOTONIC, &origin);
    }
    if (!enabled)
        return;
    struct timespec now;
    struct rusage usage;
    clock_gettime(CLOCK_MONOTONIC, &now);
    getrusage(RUSAGE_SELF, &usage);
    fprintf(stderr, "[time] %8.1f ms  user %7.1f sys %7.1f  %s%s%s\n",
            (now.tv_sec - origin.tv_sec) * 1e3 + (now.tv_nsec - origin.tv_nsec) / 1e6,
            usage.ru_utime.tv_sec * 1e3 + usage.ru_utime.tv_usec / 1e3,
            usage.ru_stime.tv_sec * 1e3 + usage.ru_stime.tv_usec / 1e3, what, detail ? " " : "", detail ? detail : "");
}

/*
 * ARM64_RECOMPILER_PROFILE_NAMES=1: count calls that reach the by-name system
 * dispatcher and print the most frequent at exit. That path compares strings,
 * so a name that is hot here wants a direct route.
 */
static struct { char name[64]; uint64_t count; } named_dispatch_counts[512];
static void report_named_dispatch(void) {
    for (int round = 0; round < 25; ++round) {
        size_t best = 0;
        for (size_t i = 1; i < 512; ++i)
            if (named_dispatch_counts[i].count > named_dispatch_counts[best].count)
                best = i;
        if (!named_dispatch_counts[best].count)
            break;
        fprintf(stderr, "[names] %10llu %s\n", (unsigned long long)named_dispatch_counts[best].count,
                named_dispatch_counts[best].name);
        named_dispatch_counts[best].count = 0;
    }
}
static void count_named_dispatch(const char *name) {
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ARM64_RECOMPILER_PROFILE_NAMES") != NULL;
        if (enabled)
            atexit(report_named_dispatch);
    }
    if (!enabled)
        return;
    for (size_t i = 0; i < 512; ++i) {
        if (!named_dispatch_counts[i].name[0])
            snprintf(named_dispatch_counts[i].name, sizeof named_dispatch_counts[i].name, "%s", name);
        if (!strcmp(named_dispatch_counts[i].name, name)) {
            ++named_dispatch_counts[i].count;
            return;
        }
    }
}

/* ARM64_RECOMPILER_WINE_DEBUG: print the debug messages of lifted Wine DLLs. */
static bool wine_debug_enabled(void) {
    static int enabled = -1;
    if (enabled < 0)
        enabled = getenv("ARM64_RECOMPILER_WINE_DEBUG") != NULL;
    return enabled;
}

static void fault(void) {
    fprintf(stderr, "RVA %#llx: unsupported guest memory access\n", (unsigned long long)guest_pc);
    exit(125);
}

/* True for a live block from the host allocator, which backs every guest heap. */
static bool guest_heap_block(uint64_t address) {
    return address >= GUEST_HOST_FLOOR && malloc_size((void *)(uintptr_t)address) != 0;
}

/*
 * The process heap is 0x7fff2001; HeapCreate hands out further handles in the
 * same range. All of them allocate from the host allocator.
 */
enum { GUEST_HEAP_HANDLE = 0x7fff2001, GUEST_HEAP_HANDLE_END = 0x7fff2200 };
static _Atomic uint64_t guest_heap_next = GUEST_HEAP_HANDLE + 1;

static bool guest_heap_handle(uint64_t handle) {
    return handle >= GUEST_HEAP_HANDLE && handle < GUEST_HEAP_HANDLE_END;
}

/* HEAP_NO_SERIALIZE, HEAP_GENERATE_EXCEPTIONS, HEAP_ZERO_MEMORY. */
#define GUEST_HEAP_FLAGS 0xdu

uint64_t guest_heap_alloc(uint64_t handle, uint32_t flags, uint64_t size) {
    if (!guest_heap_handle(handle) || (flags & ~GUEST_HEAP_FLAGS))
        guest_trap("unsupported HeapAlloc handle or flags");
    if (!size)
        size = 1;
    void *data = (flags & 8u) ? calloc(size, 1) : malloc(size);
    if (!data)
        return 0;
    return (uint64_t)(uintptr_t)data;
}

uint64_t guest_heap_free(uint64_t handle, uint32_t flags, uint64_t address) {
    (void)handle; (void)flags;
    if (guest_heap_block(address)) {
        free((void *)(uintptr_t)address);
        return 1;
    }
    return 0;
}

uint64_t guest_heap_realloc(uint64_t handle, uint32_t flags, uint64_t address, uint64_t size) {
    if (!address)
        return guest_heap_alloc(handle, flags, size);
    if (!guest_heap_block(address))
        return 0;
    void *old_ptr = (void *)(uintptr_t)address;
    void *new_ptr = realloc(old_ptr, size ? size : 1);
    if (!new_ptr)
        return 0;
    return (uint64_t)(uintptr_t)new_ptr;
}

struct translated_module {
    struct guest_module *module;
    struct translated_module *next;
};
static _Atomic(struct translated_module *) translated_modules;
static pthread_mutex_t module_translation_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;

static unsigned char *mapped_module_span(const struct guest_module *module,
                                          uint64_t address, uint64_t size, bool writable) {
    if (!module->references || !fits(address, size, module->base, module->size))
        return NULL;
    for (size_t j = 0; j < module->section_count; ++j) {
        const struct section *section = &module->sections[j];
        if ((!writable || section->writable) && fits(address, size, section->address, section->size))
            return module->memory[j] + (address - section->address);
    }
    return NULL;
}

static unsigned char *module_span(uint64_t address, uint64_t size, bool writable) {
    for (size_t i = 0; i < guest_module_count; ++i) {
        unsigned char *span = mapped_module_span(&guest_modules[i], address, size, writable);
        if (span)
            return span;
    }
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next) {
        unsigned char *span = mapped_module_span(item->module, address, size, writable);
        if (span)
            return span;
    }
    return NULL;
}

/* Out of line so the thread-local fault state is only read on this rare path. */
static __attribute__((noinline, cold)) void read_span_null(void) {
    if (guest_fault_pc && current_cpu && !delivering_fault)
        guest_access_violation(0, false);
}

static const unsigned char *read_span(uint64_t addr, uint64_t size) {
    addr = guest_low_alias(addr);
    uint64_t original = addr;
    if (__builtin_expect(!addr, 0))
        read_span_null();
    if (guest_direct(addr))
        return (const unsigned char *)(uintptr_t)addr;
    if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < guest_image_span)
        addr -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i)
        if (fits(addr, size, guest_sections[i].address, guest_sections[i].size))
            return image[i] + (addr - guest_sections[i].address);
    if (guest_fault_pc && current_cpu && !delivering_fault)
        guest_access_violation(original, false);
    fprintf(stderr, "read address %#llx size %llu\n", (unsigned long long)addr, (unsigned long long)size);
    fault();
    return NULL;
}

uint64_t guest_load_slow(uint64_t addr, uint32_t width) {
    uint64_t value = 0;
    if (!width || width > sizeof value)
        fault();
    const void *source = read_span(addr, width);
    if (atomic_load_explicit(&guest_fault_pcs_used, memory_order_relaxed) && guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
        guest_faultable_copy(&value, source, width, addr, false);
    else
        memcpy(&value, source, width);
    return value;
}

__attribute__((always_inline)) uint64_t guest_load(uint64_t addr, uint32_t width) {
    if (fits(addr, width, STACK_BASE, STACK_SIZE)) {
        uint64_t val = 0;
        memcpy(&val, (const void *)(uintptr_t)addr, width);
        return val;
    }
    const unsigned char *section = image_fast_span(addr, width, false);
    if (section) {
        uint64_t val = 0;
        memcpy(&val, section, width);
        return val;
    }
    if (guest_direct(addr)) {
        uint64_t val = 0;
        const void *source = (const void *)(uintptr_t)addr;
        if (atomic_load_explicit(&guest_fault_pcs_used, memory_order_relaxed) && guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
            guest_faultable_copy(&val, source, width, addr, false);
        else
            memcpy(&val, source, width);
        return val;
    }
    return guest_load_slow(addr, width);
}

enum {
    SYNC_MODULE = 0x7fff0001, FIBER_MODULE = 0x7fff0002, KERNEL_MODULE = 0x7fff0003,
    INIT_CRITICAL = 0x7fff1001, FLS_ALLOC, FLS_GET, FLS_SET, FLS_FREE, FILE_APIS_ANSI, DEFAULT_DLL_DIRS,
    VIRTUAL_PROTECT, GET_HANDLE_INFO,
    GET_TICK_COUNT_64, GET_TICK_COUNT, QUERY_PERF_COUNTER, GET_SYSTEM_FILETIME,
    GET_CURRENT_PROCESS_ID, GET_CURRENT_THREAD_ID, IS_PROCESSOR_FEATURE_PRESENT,
    SET_UNHANDLED_EXCEPTION_FILTER, UNHANDLED_EXCEPTION_FILTER, TERMINATE_PROCESS,
    RTL_CAPTURE_CONTEXT, RTL_LOOKUP_FUNCTION_ENTRY, RTL_VIRTUAL_UNWIND, IS_DEBUGGER_PRESENT,
    QUERY_PERF_FREQ, TLS_ALLOC = 0x7fff1031
};
static unsigned sync_references, fiber_references, kernel_references;

enum { BCRYPT_MODULE = 0x7fff0004, ADVAPI_MODULE, WINSOCK_MODULE,
       SERVICE_TARGET = 0x7fff4200 };
static unsigned service_references[3];
static const struct { uint64_t module; const char *name; } service_exports[] = {
    {BCRYPT_MODULE, "BCryptGenRandom"},
    {ADVAPI_MODULE, "RegOpenKeyExW"}, {ADVAPI_MODULE, "RegQueryValueExW"},
    {ADVAPI_MODULE, "RegCloseKey"},
    {WINSOCK_MODULE, "WSAStartup"}, {WINSOCK_MODULE, "WSACleanup"},
    {WINSOCK_MODULE, "WSAGetLastError"}, {WINSOCK_MODULE, "WSASetLastError"},
    {WINSOCK_MODULE, "socket"}, {WINSOCK_MODULE, "closesocket"},
    {WINSOCK_MODULE, "bind"}, {WINSOCK_MODULE, "connect"}, {WINSOCK_MODULE, "listen"},
    {WINSOCK_MODULE, "accept"}, {WINSOCK_MODULE, "getsockname"},
    {WINSOCK_MODULE, "shutdown"}, {WINSOCK_MODULE, "send"}, {WINSOCK_MODULE, "recv"},
};

static bool is_lifted_system_dll(const char *resolved);

static uint64_t service_module(const char *name) {
    static const char *const names[] = {"bcrypt", "advapi32", "ws2_32"};
    static const char *const files[] = {"bcrypt.dll", "advapi32.dll", "ws2_32.dll"};
    for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
        size_t length = strlen(names[i]);
        if (!strncasecmp(name, names[i], length) &&
            (!name[length] || !strcasecmp(name + length, ".dll")))
            /* The program's own lifted copy of the DLL replaces the runtime's shims. */
            return is_lifted_system_dll(files[i]) ? 0 : BCRYPT_MODULE + i;
    }
    return 0;
}

static void module_string(char *text, size_t capacity, uint64_t address, unsigned width) {
    for (size_t i = 0; i < capacity; ++i) {
        uint64_t c = guest_load(address + width * i, width);
        if (!c) {
            text[i] = 0;
            return;
        }
        if (c < 32 || c >= 127)
            guest_trap("unsupported non-ASCII module or procedure name");
        text[i] = (char)c;
    }
    guest_trap("unterminated module or procedure name");
}

/*
 * A module named by a full path ("C:\\windows\\system32\\comctl32.dll", as Wine's
 * user32 names comctl32, or a DLL beside the program) is the module of that
 * file name: lifted modules have no directory of their own.
 */
static const char *system_module_name(const char *name) {
    if (!name[0] || (name[1] != ':' && name[0] != '\\'))
        return name;
    const char *slash = strrchr(name, '\\'), *forward = strrchr(name, '/');
    if (forward && (!slash || forward > slash))
        slash = forward;
    return slash && slash[1] ? slash + 1 : name;
}

static bool is_lifted_system_dll(const char *resolved);

/* A loaded (referenced) application module by file name, or NULL. */
static struct guest_module *loaded_module_named(const char *name) {
    char buffer[160];
    const char *dot = strrchr(name, '.');
    if (!dot || (strcasecmp(dot, ".dll") && strcasecmp(dot, ".drv"))) {
        snprintf(buffer, sizeof buffer, "%s.dll", name);
        name = buffer;
    }
    for (size_t i = 0; i < guest_module_count; ++i)
        if (guest_modules[i].references && !strcasecmp(guest_modules[i].name, name))
            return &guest_modules[i];
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next)
        if (item->module->references && !strcasecmp(item->module->name, name))
            return item->module;
    return NULL;
}

static bool is_kernel_module_name(const char *name) {
    static const char *const liftable[][2] = {
        {"ntdll", "ntdll.dll"}, {"kernelbase", "kernelbase.dll"}, {"kernel32", "kernel32.dll"}};
    for (unsigned i = 0; i < sizeof liftable / sizeof *liftable; ++i) {
        size_t n = strlen(liftable[i][0]);
        if (!strncasecmp(name, liftable[i][0], n) && (!name[n] || !strcasecmp(name + n, ".dll")) &&
            is_lifted_system_dll(liftable[i][1]))
            return false;
    }
    const char *modules[] = {"kernel32", "kernelbase", "ntdll"};
    for (size_t i = 0; i < sizeof modules / sizeof *modules; ++i) {
        size_t n = strlen(modules[i]);
        if (strncasecmp(name, modules[i], n) == 0 &&
            (!name[n] || strcasecmp(name + n, ".dll") == 0))
            return true;
    }
    static const char *const api_set_prefixes[] = {
        "api-ms-win-core-fibers-",
        "api-ms-win-core-synch-",
        "api-ms-win-core-localization-",
        "api-ms-win-core-datetime-",
        "api-ms-win-core-processthreads-",
        "api-ms-win-core-sysinfo-",
    };
    for (size_t i = 0; i < sizeof api_set_prefixes / sizeof *api_set_prefixes; ++i) {
        if (strncasecmp(name, api_set_prefixes[i], strlen(api_set_prefixes[i])) == 0)
            return true;
    }
    return false;
}

uint64_t guest_module_handle(uint64_t address, uint32_t wide) {
    if (!address)
        return guest_image_base;
    char text[520];
    module_string(text, sizeof text, address, wide ? 2 : 1);
    const char *name = system_module_name(text);
    /* The program itself, named by its path. */
    if (name != text && host_peb) {
        uint64_t parameters = guest_load((uint64_t)(uintptr_t)host_peb + 0x20, 8);
        uint64_t bytes = guest_load(parameters + 0x60, 2), image = guest_load(parameters + 0x68, 8);
        size_t length = strlen(name);
        bool same = bytes / 2 >= length;
        for (size_t i = 0; same && i < length; ++i)
            same = tolower((int)guest_load(image + bytes - 2 * (length - i), 2)) == tolower((unsigned char)name[i]);
        if (same && (bytes / 2 == length || guest_load(image + bytes - 2 * length - 2, 2) == '\\'))
            return guest_image_base;
    }
    uint64_t service = service_module(name);
    if (service && service_references[service - BCRYPT_MODULE])
        return service;
    if (is_kernel_module_name(name))
        return KERNEL_MODULE;
    struct guest_module *module = loaded_module_named(name);
    if (module)
        return module->base;
    last_error = 126;
    return 0;
}

void guest_store(uint64_t addr, uint64_t value, uint32_t width);
uint64_t guest_module_handle_ex(uint32_t flags, uint64_t address, uint64_t output) {
    if (flags || !output) {
        last_error = 87;
        return 0;
    }
    uint64_t handle = guest_module_handle(address, 1);
    if (handle == KERNEL_MODULE)
        ++kernel_references;
    guest_store(output, handle, 8);
    return handle != 0;
}

static struct guest_module *find_guest_module(uint64_t handle) {
    for (size_t i = 0; i < guest_module_count; ++i)
        if (guest_modules[i].base == handle && guest_modules[i].references)
            return &guest_modules[i];
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next)
        if (item->module->base == handle && item->module->references)
            return item->module;
    return NULL;
}

/* Bumped when a module's code goes away; see guest_lookup_dispatch. */
static _Atomic uint64_t dispatch_generation = 1;

static void unmap_guest_module(struct guest_module *module) {
    atomic_fetch_add(&dispatch_generation, 1);
    if (module->memory) {
        guest_unmap_fixed(module->base, module->size);
        /* A linked-in module keeps its address range for the next load. */
        if (module >= guest_modules && module < guest_modules + guest_module_count)
            guest_map_fixed(module->base, module->size);
    }
    free(module->memory);
    module->memory = NULL;
    module->references = 0;
}

static uint64_t wine_host_unix_call(uint64_t handle, uint32_t code, uint64_t args);

static void init_guest_cpu(uint64_t *cpu) {
    // The low byte of each width slot describes the initialized register.
    enum { GPR_COUNT = 16, CPU_WIDTH_OFFSET = GPR_COUNT + 32 + 5 };
    for (size_t i = 0; i < GPR_COUNT; ++i)
        cpu[CPU_WIDTH_OFFSET + i] = 64;
    for (size_t i = 6; i < 16; ++i)
        cpu[CPU_WIDTH_OFFSET + GPR_COUNT + i * 2] = 128;
}

static uint32_t call_module_entry_reserved(struct guest_module *module, uint64_t reason,
                                           uint64_t reserved) {
    uint64_t cpu[128] = {0};
    uint64_t *caller = current_cpu;
    if (!caller)
        guest_trap("DLL initialization requires a guest CPU");
    cpu[1] = module->base;
    cpu[2] = reason;
    cpu[3] = reserved;
    init_guest_cpu(cpu);
    cpu[7] = (caller[7] & ~UINT64_C(15)) - 40;
    guest_store(cpu[7], 0, 8);
    current_cpu = cpu;
    module->entry(cpu, 0);
    current_cpu = caller;
    return (uint32_t)cpu[0];
}

static uint32_t call_module_entry(struct guest_module *module, uint64_t reason) {
    return call_module_entry_reserved(module, reason, 0);
}

/* Attached modules in initialization order (dependencies first). */
static struct guest_module *attached_modules[256];
static size_t attached_module_count;

static void forget_attached_module(struct guest_module *module) {
    for (size_t i = attached_module_count; i > 0; --i)
        if (attached_modules[i - 1] == module) {
            memmove(&attached_modules[i - 1], &attached_modules[i],
                    (attached_module_count - i) * sizeof *attached_modules);
            --attached_module_count;
            return;
        }
}

static uint64_t load_application_module(const char *name);
static char *subsys_append_mapping_ranges(char *ranges);
static void release_application_module(struct guest_module *module);

/*
 * API-set schema: contract DLL names map to their implementing DLL.
 * api-ms-win-crt-* is ucrtbase.dll; core/security contracts are system code.
 */
static const char *resolve_api_set(const char *name, char *buffer, size_t size) {
    if (!strncasecmp(name, "api-ms-win-crt-", 15))
        return "ucrtbase.dll";
    static const char *const system_prefixes[] = {
        "api-ms-win-core-", "api-ms-win-security-", "api-ms-win-eventing-",
        "api-ms-win-appmodel-", "ext-ms-win-",
    };
    for (size_t i = 0; i < sizeof system_prefixes / sizeof *system_prefixes; ++i)
        if (!strncasecmp(name, system_prefixes[i], strlen(system_prefixes[i])))
            return "kernelbase.dll";
    const char *dot = strrchr(name, '.');
    if (!dot || (strcasecmp(dot, ".dll") && strcasecmp(dot, ".drv"))) {
        snprintf(buffer, size, "%s.dll", name);
        return buffer;
    }
    return name;
}

/*
 * System DLLs that become lifted guest modules when the program supplies them
 * (LIFTABLE_SYSTEM_DLLS in build_console_modules.py): a precompiled module of
 * that name, or with on-demand translation, the file beside the program.
 */
static bool is_lifted_system_dll(const char *resolved) {
    /* Keep in sync with LIFTABLE_SYSTEM_DLLS in build_console_modules.py. */
    static const char *const liftable[] = {"ntdll.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
                                           "win32u.dll", "kernel32.dll", "advapi32.dll", "sechost.dll",
                                           "shell32.dll", "shlwapi.dll", "ole32.dll",
                                           "ws2_32.dll", "oleaut32.dll", "userenv.dll"};
    enum { LIFTABLE = sizeof liftable / sizeof *liftable };
    static _Atomic int cache[LIFTABLE]; /* 0: unknown, 1: shim, 2: lifted */
    size_t index = 0;
    while (index < LIFTABLE && strcasecmp(resolved, liftable[index]))
        ++index;
    if (index == LIFTABLE)
        return false;
    _Atomic int *cached = &cache[index];
    int state = atomic_load(cached);
    if (!state) {
        state = 1;
        for (size_t i = 0; i < guest_module_count; ++i)
            if (!strcasecmp(guest_modules[i].name, resolved))
                state = 2;
        struct stat info;
        if (state == 1 && getenv("ARM64_RECOMPILER_PYTHON") && !stat(resolved, &info) && S_ISREG(info.st_mode))
            state = 2;
        atomic_store(cached, state);
    }
    return state == 2;
}

/* DLLs the runtime implements with named shims (keep in sync with build_console_modules.py). */
static bool is_system_dll_name(const char *name) {
    static const char *const system[] = {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "advapi32.dll", "bcrypt.dll",
        "ws2_32.dll", "user32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
        "userenv.dll", "secur32.dll", "crypt32.dll", "shlwapi.dll", "dbghelp.dll",
    };
    char buffer[160];
    const char *resolved = resolve_api_set(name, buffer, sizeof buffer);
    /* Only the DLL's own name selects the lifted copy; API-set contracts stay on the runtime. */
    if ((resolved == name || resolved == buffer) && is_lifted_system_dll(resolved))
        return false;
    for (size_t i = 0; i < sizeof system / sizeof *system; ++i)
        if (!strcasecmp(resolved, system[i]))
            return true;
    return false;
}

/*
 * Named system functions as call targets. A forwarded export such as
 * "kernel32.GetCurrentThreadId" resolves to a token; guest_indirect_call
 * dispatches it through the same named shims as a direct import.
 */
enum { SYSTEM_THUNK_BASE = 0x7fff8000, SYSTEM_THUNK_LIMIT = 0x4000 };
static char *system_thunk_names[SYSTEM_THUNK_LIMIT];
static size_t system_thunk_count;
static pthread_mutex_t system_thunk_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t system_thunk(const char *name) {
    pthread_mutex_lock(&system_thunk_lock);
    size_t i = 0;
    while (i < system_thunk_count && strcmp(system_thunk_names[i], name))
        ++i;
    if (i == system_thunk_count) {
        char *copy = system_thunk_count < SYSTEM_THUNK_LIMIT ? strdup(name) : NULL;
        if (!copy) {
            pthread_mutex_unlock(&system_thunk_lock);
            return 0;
        }
        system_thunk_names[system_thunk_count++] = copy;
    }
    pthread_mutex_unlock(&system_thunk_lock);
    return SYSTEM_THUNK_BASE + i;
}

static const char *system_thunk_name(uint64_t target) {
    if (target < SYSTEM_THUNK_BASE || target - SYSTEM_THUNK_BASE >= SYSTEM_THUNK_LIMIT)
        return NULL;
    pthread_mutex_lock(&system_thunk_lock);
    const char *name = target - SYSTEM_THUNK_BASE < system_thunk_count
                           ? system_thunk_names[target - SYSTEM_THUNK_BASE] : NULL;
    pthread_mutex_unlock(&system_thunk_lock);
    return name;
}

static uint64_t module_export_at(const struct guest_module *module, const char *name,
                                 uint64_t ordinal, unsigned depth);

/* Resolve "DLL.Name" or "DLL.#ordinal". The caller holds the loader lock. */
static uint64_t resolve_forwarder(const char *forwarder, unsigned depth) {
    const char *dot = strrchr(forwarder, '.');
    if (depth > 8 || !dot || dot == forwarder || dot - forwarder >= 128 || !dot[1])
        return 0;
    char dll[128], buffer[160];
    snprintf(dll, sizeof dll, "%.*s", (int)(dot - forwarder), forwarder);
    const char *target = resolve_api_set(dll, buffer, sizeof buffer);
    const char *symbol = dot + 1;
    uint64_t ordinal = 0;
    if (symbol[0] == '#') {
        ordinal = strtoull(symbol + 1, NULL, 10);
        symbol = NULL;
    }
    if (is_system_dll_name(target))
        return symbol ? system_thunk(symbol) : 0;
    uint64_t handle = load_application_module(target);
    struct guest_module *module = handle ? find_guest_module(handle) : NULL;
    return module ? module_export_at(module, symbol, ordinal, depth) : 0;
}

static uint64_t module_export_at(const struct guest_module *module, const char *name,
                                 uint64_t ordinal, unsigned depth) {
    for (size_t i = 0; i < module->export_count; ++i) {
        const struct guest_module_export *export = &module->exports[i];
        if (name ? export->name && !strcmp(name, export->name) : ordinal == export->ordinal)
            return export->forwarder ? resolve_forwarder(export->forwarder, depth + 1) : export->address;
    }
    return 0;
}

/* Look up an export by name, or by ordinal when name is NULL, following forwarders. */
static uint64_t module_export(const struct guest_module *module, const char *name, uint64_t ordinal) {
    return module_export_at(module, name, ordinal, 0);
}

static void release_module_dependencies(struct guest_module *module) {
    for (size_t i = module->import_count; i > 0; --i) {
        struct guest_module *dependency = find_guest_module(module->dependencies[i - 1]);
        if (dependency)
            release_application_module(dependency);
    }
    free(module->dependencies);
    module->dependencies = NULL;
}

static void release_application_module(struct guest_module *module) {
    if (module->references > 1) {
        --module->references;
        return;
    }
    forget_attached_module(module);
    call_module_entry(module, 0);
    unmap_guest_module(module);
    release_module_dependencies(module);
}

static uint64_t nls_file(const char *name, uint64_t *size);
static void (*guest_lookup_dispatch(uint64_t target))(void *, uint64_t);

/* Call a lifted guest function with up to four arguments on a fresh frame below the caller's. */
static uint64_t call_guest_function(uint64_t target, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    void (*fn)(void *, uint64_t) = guest_lookup_dispatch(target);
    uint64_t *caller = current_cpu;
    if (!fn || !caller)
        return 0;
    uint64_t cpu[128] = {0};
    init_guest_cpu(cpu);
    cpu[1] = a;
    cpu[2] = b;
    cpu[3] = c;
    cpu[4] = d;
    cpu[7] = (caller[7] & ~UINT64_C(15)) - 40;
    guest_store(cpu[7], 0, 8);
    current_cpu = cpu;
    fn(cpu, 0);
    current_cpu = caller;
    return cpu[0];
}

/*
 * Wine's loader initializes ntdll's NLS state (ANSI/OEM code pages and case
 * tables) during process startup, which the runtime loader replaces. Do the
 * same through ntdll's own exports once the lifted ntdll.dll is loaded.
 */
static void init_lifted_ntdll(struct guest_module *module) {
    if (wine_hosted) {
        /* Lifted DLLs reach their unix libraries by calling through this ntdll variable. */
        uint64_t slot = module_export(module, "__wine_unix_call_dispatcher", 0);
        if (slot)
            guest_store(slot, system_thunk("__wine_unix_call_dispatcher"), 8);
    }
    uint64_t size, ansi = nls_file("c_1252.nls", &size), oem = nls_file("c_437.nls", &size);
    uint64_t casemap = nls_file("l_intl.nls", &size);
    uint64_t init = module_export(module, "RtlInitNlsTables", 0);
    uint64_t reset = module_export(module, "RtlResetRtlTranslations", 0);
    if (!ansi || !oem || !casemap || !init || !reset)
        return;
    /* NLSTABLEINFO: two CPTABLEINFO (0x40 each) plus upper/lower case table pointers. */
    uint64_t info = guest_heap_alloc(GUEST_HEAP_HANDLE, 8, 0x100);
    if (!info)
        return;
    call_guest_function(init, ansi, oem, casemap, info);
    call_guest_function(reset, info, 0, 0, 0);
}

static uint64_t load_guest_module(struct guest_module *module, const char *path) {
    /* Already loaded: take a reference. This is by far the common call. */
    if (module->references) {
        ++module->references;
        return module->base;
    }
    trace_time("load begin", module->name);
    /* The DLL beside the program must be the one that was lifted. */
    FILE *file = fopen(path, "rb");
    if (!file) {
        last_error = 126;
        return 0;
    }
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    size_t total = 0, count;
    while ((count = fread(buffer, 1, sizeof buffer, file)) > 0) {
        CC_SHA256_Update(&hash, buffer, (CC_LONG)count);
        total += count;
    }
    CC_SHA256_Final(digest, &hash);
    bool matches = total == module->file_size && !ferror(file) &&
                   !memcmp(digest, module->file_hash, sizeof digest);
    fclose(file);
    if (!matches) {
        last_error = 193;
        return 0;
    }
    module->memory = calloc(module->section_count, sizeof *module->memory);
    if (!module->memory) {
        last_error = 8;
        return 0;
    }
    bool placed = true;
    for (size_t i = 0; i < module->section_count; ++i)
        placed = placed && fits(module->sections[i].address, module->sections[i].size,
                                module->base, module->size);
    /* Linked-in modules were reserved at startup (reserve_guest_modules). */
    bool reserved = module >= guest_modules && module < guest_modules + guest_module_count;
    unsigned char *mapping = !placed ? NULL
        : reserved ? (unsigned char *)(uintptr_t)module->base
        : guest_map_fixed(module->base, module->size);
    if (!mapping) {
        fprintf(stderr, "cannot map %s at guest address %#llx\n", module->name,
                (unsigned long long)module->base);
        free(module->memory);
        module->memory = NULL;
        last_error = 8;
        return 0;
    }
    /* Map the image copy-on-write from the executable when it carries one; pages
       the program never writes stay shared with the file instead of being copied. */
    bool shared = guest_map_image_copy(module->base, module->image, module->size);
    for (size_t i = 0; i < module->section_count; ++i) {
        const struct section *section = &module->sections[i];
        module->memory[i] = mapping + (section->address - module->base);
        if (!shared && section->initial_size)
            memcpy(module->memory[i], section->initial, section->initial_size);
    }
    module->references = 1;
    module->loading = true;
    if (module->import_count) {
        module->dependencies = calloc(module->import_count, sizeof *module->dependencies);
        if (!module->dependencies) {
            last_error = 8;
            goto fail;
        }
        for (size_t i = 0; i < module->import_count; ++i) {
            const struct guest_module_import *import = &module->imports[i];
            uint64_t target;
            if (is_system_dll_name(import->dll)) {
                /* Runtime-implemented DLL: the slot holds a named token. */
                target = import->name ? system_thunk(import->name) : 0;
            } else {
                uint64_t handle = load_application_module(import->dll);
                if (!handle)
                    goto fail;
                module->dependencies[i] = handle;
                target = module_export(find_guest_module(handle), import->name, import->ordinal);
            }
            unsigned char *slot = mapped_module_span(module, import->slot, sizeof target, false);
            if (!target || !slot) {
                if (getenv("ARM64_RECOMPILER_TRACE_IMPORTS"))
                    fprintf(stderr, "[load] %s: unresolved import %s!%s (#%llu)\n", module->name, import->dll,
                            import->name ? import->name : "", (unsigned long long)import->ordinal);
                last_error = 127;
                goto fail;
            }
            memcpy(slot, &target, sizeof target);
        }
    }
    if (!strcasecmp(module->name, "ntdll.dll") && is_lifted_system_dll("ntdll.dll"))
        init_lifted_ntdll(module);
    trace_time("imports bound, calling DllMain", module->name);
    if (!call_module_entry(module, 1)) {
        last_error = 1114;
        goto fail;
    }
    if (attached_module_count < sizeof attached_modules / sizeof *attached_modules)
        attached_modules[attached_module_count++] = module;
    module->loading = false;
    trace_time("load done", module->name);
    return module->base;

fail: {
    uint32_t error = last_error;
    if (getenv("ARM64_RECOMPILER_TRACE_IMPORTS"))
        fprintf(stderr, "[load] %s failed, error %u\n", module->name, error);
    module->loading = false;
    unmap_guest_module(module);
    if (module->dependencies)
        release_module_dependencies(module);
    last_error = error;
    return 0;
}
}

extern char **environ;

static struct guest_module *translate_guest_module(const char *name, const char *python) {
    const char *helper = getenv("ARM64_RECOMPILER_PLUGIN_HELPER");
    const char *directory = getenv("ARM64_RECOMPILER_PLUGIN_DIR");
    if (!helper || !directory || name[0] == '-' || strpbrk(name, "/\\:")) {
        last_error = 126;
        return NULL;
    }
    struct stat source;
    if (stat(name, &source) || !S_ISREG(source.st_mode)) {
        last_error = 126;
        return NULL;
    }

    char *output = NULL;
    if (asprintf(&output, "%s/plugin.XXXXXXXX", directory) < 0) {
        last_error = 8;
        return NULL;
    }
    int fd = mkstemp(output);
    if (fd < 0) {
        free(output);
        last_error = 8;
        return NULL;
    }
    close(fd);
    // Only the translation helper receives the current guest address ranges.
    char *ranges = NULL;
    int result = asprintf(&ranges, "ARM64_RECOMPILER_GUEST_RANGES=%llu:%llu",
                          (unsigned long long)guest_image_base,
                          (unsigned long long)(guest_image_base + 0x20000000));
    for (struct translated_module *item = atomic_load(&translated_modules); result >= 0 && item; item = item->next) {
        char *next = NULL;
        result = asprintf(&next, "%s,%llu:%llu", ranges,
                          (unsigned long long)item->module->base,
                          (unsigned long long)(item->module->base + item->module->size));
        free(ranges);
        ranges = next;
    }
    for (size_t i = 0; result >= 0 && i < guest_module_count; ++i) {
        char *next = NULL;
        result = asprintf(&next, "%s,%llu:%llu", ranges,
                          (unsigned long long)guest_modules[i].base,
                          (unsigned long long)(guest_modules[i].base + guest_modules[i].size));
        free(ranges);
        ranges = next;
    }
    /* Live VirtualAlloc regions and mapped views: a DLL must not land on them. */
    if (result >= 0) {
        ranges = subsys_append_mapping_ranges(ranges);
        if (!ranges)
            result = -1;
    }
    size_t env_count = 0;
    while (environ[env_count])
        ++env_count;
    char **env = result >= 0 ? calloc(env_count + 2, sizeof *env) : NULL;
    if (!env) {
        free(ranges);
        unlink(output);
        free(output);
        last_error = 8;
        return NULL;
    }
    size_t index = 0;
    const char key[] = "ARM64_RECOMPILER_GUEST_RANGES=";
    for (size_t i = 0; i < env_count; ++i)
        if (strncmp(environ[i], key, sizeof key - 1) != 0)
            env[index++] = environ[i];
    env[index] = ranges;
    char *const argv[] = {(char *)python, (char *)helper, (char *)name, output, NULL};
    pid_t pid;
    result = posix_spawn(&pid, python, NULL, NULL, argv, env);
    free(env);
    free(ranges);
    int status;
    if (!result) {
        do {
            result = waitpid(pid, &status, 0);
        } while (result < 0 && errno == EINTR);
    }
    void *library = NULL;
    if (result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        library = dlopen(output, RTLD_NOW | RTLD_LOCAL);
    unlink(output);
    free(output);
    if (!library) {
        last_error = 193;
        return NULL;
    }

    struct guest_module *module = dlsym(library, "translated_guest_module");
    if (!module || strcasecmp(module->name, name)) {
        dlclose(library);
        last_error = 193;
        return NULL;
    }
    struct translated_module *head = atomic_load(&translated_modules);
    for (struct translated_module *item = head; item; item = item->next) {
        const struct guest_module *other = item->module;
        if (module->base < other->base + other->size && other->base < module->base + module->size) {
            dlclose(library);
            last_error = 193;
            return NULL;
        }
    }
    struct translated_module *item = malloc(sizeof *item);
    if (!item) {
        dlclose(library);
        last_error = 8;
        return NULL;
    }
    *item = (struct translated_module){module, head};
    // Keep the translated image resident so later LoadLibrary calls can reuse it.
    atomic_store(&translated_modules, item);
    return module;
}

// The caller holds the loader lock through dependency resolution and attach.
static uint64_t load_application_module(const char *name) {
    struct guest_module *module = NULL;
    for (size_t i = 0; i < guest_module_count; ++i) {
        if (!strcasecmp(guest_modules[i].name, name)) {
            module = &guest_modules[i];
            break;
        }
    }
    const char *python = getenv("ARM64_RECOMPILER_PYTHON");
    if (!module && python) {
        for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next) {
            if (!strcasecmp(item->module->name, name)) {
                module = item->module;
                break;
            }
        }
        if (!module)
            module = translate_guest_module(name, python);
        if (!module)
            return 0;
    }
    if (!module) {
        last_error = 126;
        return 0;
    }
    /* A cycle (user32 <-> gdi32): the module is mapped and its exports resolve;
       it finishes initializing when the outer load returns, as on Windows. */
    if (module->loading && module->memory) {
        ++module->references;
        return module->base;
    }
    return load_guest_module(module, module->name);
}

/*
 * Process exit: DLL_PROCESS_DETACH with lpReserved non-NULL, in reverse
 * initialization order. Runs once, even if a DllMain calls ExitProcess.
 */
static void detach_guest_modules(void) {
    static bool detaching;
    if (detaching || !current_cpu)
        return;
    detaching = true;
    pthread_mutex_lock(&module_translation_lock);
    while (attached_module_count) {
        struct guest_module *module = attached_modules[--attached_module_count];
        call_module_entry_reserved(module, 0, 1);
    }
    pthread_mutex_unlock(&module_translation_lock);
}

/* IAT slots (RVAs) the lifter routes through bound values; sorted. */
__attribute__((weak)) const uint64_t guest_bound_import_slots[1] = {0};
__attribute__((weak)) const uint64_t guest_bound_import_count = 0;

static bool is_bound_import_slot(uint64_t rva) {
    size_t low = 0, high = guest_bound_import_count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (guest_bound_import_slots[mid] == rva)
            return true;
        if (guest_bound_import_slots[mid] < rva)
            low = mid + 1;
        else
            high = mid;
    }
    return false;
}

static void image_string(char *out, size_t size, uint64_t rva) {
    size_t i = 0;
    for (; i + 1 < size; ++i) {
        char c = (char)guest_load(rva + i, 1);
        if (!c)
            break;
        out[i] = c;
    }
    out[i] = 0;
}

/* The IAT may sit in a read-only section; the loader writes it directly. */
static void image_write64(uint64_t rva, uint64_t value) {
    for (uint64_t i = 0; i < guest_section_count; ++i)
        if (fits(rva, 8, guest_sections[i].address, guest_sections[i].size)) {
            memcpy(image[i] + (rva - guest_sections[i].address), &value, 8);
            return;
        }
    guest_trap("import address table outside the image");
}

/*
 * Bind the primary image's static imports from lifted guest DLLs, as the
 * Windows loader does before the entry point: walk the import directory, map
 * API-set contracts to their DLL, load each DLL (its dependencies load and
 * receive DLL_PROCESS_ATTACH first, so attach runs bottom-up), and resolve each
 * thunk by name or by ordinal (bit 63), following forwarders. Imports the
 * lifter left on named shims are skipped.
 */
void guest_bind_imports(void) {
    if (!guest_bound_import_count)
        return;
    uint64_t header = guest_load(0x3c, 4);
    uint64_t directory = guest_load(header + 0x18 + 0x70 + 8, 4);
    pthread_mutex_lock(&module_translation_lock);
    for (uint64_t descriptor = directory; directory; descriptor += 20) {
        uint64_t lookup = guest_load(descriptor, 4), name = guest_load(descriptor + 12, 4);
        uint64_t first = guest_load(descriptor + 16, 4);
        if (!name && !first)
            break;
        char dll[129], buffer[160];
        image_string(dll, sizeof dll, name);
        const char *target = resolve_api_set(dll, buffer, sizeof buffer);
        struct guest_module *module = NULL;
        for (uint64_t i = 0;; ++i) {
            uint64_t slot = first + i * 8;
            uint64_t entry = guest_load((lookup ? lookup : first) + i * 8, 8);
            if (!entry)
                break;
            if (!is_bound_import_slot(slot))
                continue;
            if (!module) {
                uint64_t handle = load_application_module(target);
                module = handle ? find_guest_module(handle) : NULL;
                if (!module) {
                    fprintf(stderr, "The program can't start because %s (%s) is missing or failed to initialize.\n",
                            dll, target);
                    exit((int)0xc0000135 & 0xff); /* STATUS_DLL_NOT_FOUND */
                }
            }
            char symbol[256];
            uint64_t ordinal = 0;
            if (entry >> 63)
                ordinal = entry & 0xffff;
            else
                image_string(symbol, sizeof symbol, (entry & 0x7fffffff) + 2);
            uint64_t address = module_export(module, ordinal ? NULL : symbol, ordinal);
            if (!address) {
                if (ordinal)
                    snprintf(symbol, sizeof symbol, "#%llu", (unsigned long long)ordinal);
                fprintf(stderr, "The procedure entry point %s could not be located in %s.\n", symbol, target);
                exit((int)0xc0000139 & 0xff); /* STATUS_ENTRYPOINT_NOT_FOUND */
            }
            image_write64(slot, address);
            if (getenv("ARM64_RECOMPILER_TRACE_IMPORTS")) {
                if (ordinal)
                    snprintf(symbol, sizeof symbol, "#%llu", (unsigned long long)ordinal);
                fprintf(stderr, "[bind] %s!%s -> %s %#llx\n", dll, symbol, target, (unsigned long long)address);
            }
        }
    }
    pthread_mutex_unlock(&module_translation_lock);
}

static uint64_t load_named_module(const char *module, uint64_t reserved, uint32_t flags) {
    if (!reserved && (flags == 0 || flags == 0x800)) {
        uint64_t service = service_module(module);
        if (service) {
            ++service_references[service - BCRYPT_MODULE];
            return service;
        }
        if (is_kernel_module_name(module)) {
            ++kernel_references;
            return KERNEL_MODULE;
        }
        if (strcasecmp(module, "api-ms-win-appmodel-runtime-l1-1-1") == 0 ||
            strcasecmp(module, "ext-ms-win-kernel32-package-current-l1-1-0") == 0 ||

            strcasecmp(module, "api-ms-win-appmodel-runtime-l1-1-2") == 0 ||
            strcasecmp(module, "api-ms-win-appmodel-runtime-l1-1-2.dll") == 0) {
            last_error = 126;
            return 0;
        }
    }
    if (!reserved && !flags) {
        const char *name = module;
        if (name[0] == '.' && (name[1] == '/' || name[1] == '\\'))
            name += 2;
        pthread_mutex_lock(&module_translation_lock);
        uint64_t handle = load_application_module(name);
        pthread_mutex_unlock(&module_translation_lock);
        if (handle || guest_module_count || getenv("ARM64_RECOMPILER_PYTHON"))
            return handle;
    }
    fprintf(stderr, "RVA %#llx: unsupported DLL load for %s, flags %#x\n",
            (unsigned long long)guest_pc, module, flags);
    exit(125);
}

uint64_t guest_load_library(uint64_t address, uint64_t reserved, uint32_t flags) {
    char module[520];
    module_string(module, sizeof module, address, 2);
    return load_named_module(system_module_name(module), reserved, flags);
}

uint64_t guest_load_library_a(uint64_t address) {
    char module[520];
    module_string(module, sizeof module, address, 1);
    return load_named_module(system_module_name(module), 0, 0);
}

uint64_t guest_free_library(uint64_t handle) {
    pthread_mutex_lock(&module_translation_lock);
    struct guest_module *module = find_guest_module(handle);
    if (module)
        release_application_module(module);
    pthread_mutex_unlock(&module_translation_lock);
    if (module)
        return 1;
    if (handle >= BCRYPT_MODULE && handle <= WINSOCK_MODULE) {
        unsigned *refs = &service_references[handle - BCRYPT_MODULE];
        if (*refs) {
            --*refs;
            return 1;
        }
        last_error = 6;
        return 0;
    }
    unsigned *references = handle == SYNC_MODULE ? &sync_references :
                           handle == FIBER_MODULE ? &fiber_references :
                           handle == KERNEL_MODULE ? &kernel_references : NULL;
    if (!references || !*references) {
        last_error = 6;
        return 0;
    }
    --*references;
    return 1;
}

uint64_t guest_get_proc(uint64_t handle, uint64_t address) {
    char symbol[129];
    if (address <= UINT16_MAX)
        snprintf(symbol, sizeof symbol, "#%llu", (unsigned long long)address);
    else
        module_string(symbol, sizeof symbol, address, 1);
    pthread_mutex_lock(&module_translation_lock);
    struct guest_module *module = find_guest_module(handle);
    uint64_t target = module ? module_export(module, address <= UINT16_MAX ? NULL : symbol, address) : 0;
    pthread_mutex_unlock(&module_translation_lock);
    if (module) {
        if (target)
            return target;
        last_error = 127;
        return 0;
    }
    if (handle >= BCRYPT_MODULE && handle <= WINSOCK_MODULE &&
        service_references[handle - BCRYPT_MODULE]) {
        for (size_t i = 0; i < sizeof service_exports / sizeof *service_exports; ++i)
            if (service_exports[i].module == handle && !strcmp(service_exports[i].name, symbol))
                return SERVICE_TARGET + i;
        last_error = 127;
        return 0;
    }
    if ((handle != SYNC_MODULE || !sync_references) &&
        (handle != FIBER_MODULE || !fiber_references) &&
        handle != KERNEL_MODULE) {
        last_error = 6;
        return 0;
    }
    if ((handle == SYNC_MODULE || handle == KERNEL_MODULE) &&
        (strcmp(symbol, "InitializeCriticalSectionEx") == 0 ||
         strcmp(symbol, "InitializeCriticalSectionAndSpinCount") == 0 ||
         strcmp(symbol, "InitializeCriticalSection") == 0))
        return INIT_CRITICAL;
    if (handle == KERNEL_MODULE && strcmp(symbol, "VirtualProtect") == 0)
        return VIRTUAL_PROTECT;
    if (handle == KERNEL_MODULE && strcmp(symbol, "GetHandleInformation") == 0)
        return GET_HANDLE_INFO;
    if (handle == KERNEL_MODULE) {
        if (strcmp(symbol, "GetTickCount64") == 0) return GET_TICK_COUNT_64;
        if (strcmp(symbol, "GetTickCount") == 0) return GET_TICK_COUNT;
        if (strcmp(symbol, "QueryPerformanceCounter") == 0) return QUERY_PERF_COUNTER;
        if (strcmp(symbol, "QueryPerformanceFrequency") == 0) return QUERY_PERF_FREQ;
        if (strcmp(symbol, "GetSystemTimeAsFileTime") == 0 ||
            strcmp(symbol, "GetSystemTimePreciseAsFileTime") == 0) return GET_SYSTEM_FILETIME;
        if (strcmp(symbol, "GetCurrentProcessId") == 0) return GET_CURRENT_PROCESS_ID;
        if (strcmp(symbol, "GetCurrentThreadId") == 0) return GET_CURRENT_THREAD_ID;
        if (strcmp(symbol, "IsProcessorFeaturePresent") == 0) return IS_PROCESSOR_FEATURE_PRESENT;
        if (strcmp(symbol, "SetUnhandledExceptionFilter") == 0) return SET_UNHANDLED_EXCEPTION_FILTER;
        if (strcmp(symbol, "UnhandledExceptionFilter") == 0) return UNHANDLED_EXCEPTION_FILTER;
        if (strcmp(symbol, "TerminateProcess") == 0) return TERMINATE_PROCESS;
        if (strcmp(symbol, "RtlCaptureContext") == 0) return RTL_CAPTURE_CONTEXT;
        if (strcmp(symbol, "RtlLookupFunctionEntry") == 0) return RTL_LOOKUP_FUNCTION_ENTRY;
        if (strcmp(symbol, "RtlVirtualUnwind") == 0) return RTL_VIRTUAL_UNWIND;
        if (strcmp(symbol, "IsDebuggerPresent") == 0) return IS_DEBUGGER_PRESENT;
        if (strcmp(symbol, "TlsAlloc") == 0) return TLS_ALLOC;
        if (strcmp(symbol, "TlsGetValue") == 0) return FLS_GET;
        if (strcmp(symbol, "TlsSetValue") == 0) return FLS_SET;
        if (strcmp(symbol, "TlsFree") == 0) return FLS_FREE;
        if (strcmp(symbol, "InitializeSListHead") == 0) return 0x7fff3002;
    }
    if (handle == KERNEL_MODULE && (strcmp(symbol, "AddVectoredExceptionHandler") == 0 || strcmp(symbol, "RemoveVectoredExceptionHandler") == 0))
        return 0x7fff3001;
    if (handle == KERNEL_MODULE && strcmp(symbol, "IsDBCSLeadByteEx") == 0)
        return 0x7fff3003;
    if (handle == KERNEL_MODULE && strcmp(symbol, "AreFileApisANSI") == 0)
        return FILE_APIS_ANSI;
    if (handle == KERNEL_MODULE && strcmp(symbol, "SetDefaultDllDirectories") == 0)
        return DEFAULT_DLL_DIRS;
    if (handle == KERNEL_MODULE && strcmp(symbol, "SetThreadDescription") == 0)
        return 0;
    if (handle == FIBER_MODULE || handle == KERNEL_MODULE) {
        if (strcmp(symbol, "FlsGetValue2") == 0)
            return FLS_GET;
        const char *names[] = {"FlsAlloc", "FlsGetValue", "FlsSetValue", "FlsFree"};
        for (unsigned i = 0; i < sizeof names / sizeof *names; ++i)
            if (strcmp(symbol, names[i]) == 0)
                return FLS_ALLOC + i;
    }
    last_error = 127;
    return 0;
}

void guest_stack_smash_trap(uint64_t return_va) {
    fprintf(stderr, "[DEBUG] __stack_chk_fail called! return_va = %#llx\n", (unsigned long long)return_va);
}

void *guest_pointer(uint64_t addr, uint32_t width) {
    if (!width || width > sizeof(uint64_t))
        fault();
    addr = guest_low_alias(addr);
    if (guest_direct(addr))
        return (void *)(uintptr_t)addr;
    if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < guest_image_span)
        addr -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *section = &guest_sections[i];
        if (fits(addr, width, section->address, section->size))
            return image[i] + (addr - section->address);
    }
    fprintf(stderr, "address %#llx size %u\n", (unsigned long long)addr, width);
    fault();
    return NULL;
}

void guest_store_slow(uint64_t addr, uint64_t value, uint32_t width) {
    addr = guest_low_alias(addr);
    uint64_t original = addr;
    if (!width || width > sizeof value)
        fault();
    if (guest_direct(addr)) {
        void *destination = (void *)(uintptr_t)addr;
        if (atomic_load_explicit(&guest_fault_pcs_used, memory_order_relaxed) && guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
            guest_faultable_copy(destination, &value, width, addr, true);
        else
            memcpy(destination, &value, width);
        return;
    }
    /* The primary image (as a VA or a bare RVA): honor the section protection. */
    if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < guest_image_span)
        addr -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *section = &guest_sections[i];
        bool writable = section_protection ? ((section_protection[i] & 0xcc) != 0) : section->writable;
        if (writable && fits(addr, width, section->address, section->size)) {
            memcpy(image[i] + (addr - section->address), &value, width);
            return;
        }
    }
    if (guest_fault_pc && current_cpu && !delivering_fault)
        guest_access_violation(original, true);
    fprintf(stderr, "write address %#llx size %u value %#llx\n", (unsigned long long)addr, width, (unsigned long long)value);
    Dl_info dlinf;
    if (dladdr(__builtin_return_address(0), &dlinf) && dlinf.dli_sname) {
        fprintf(stderr, "Called from native symbol: %s (+%td)\n", dlinf.dli_sname, (char*)__builtin_return_address(0) - (char*)dlinf.dli_saddr);
    }
    if (current_cpu) {
        uint64_t *regs = (uint64_t *)current_cpu;
        fprintf(stderr, "guest RAX=%#llx RCX=%#llx RDX=%#llx RBX=%#llx RSP=%#llx RBP=%#llx RSI=%#llx RDI=%#llx\n",
            regs[0], regs[1], regs[2], regs[8], regs[7], regs[9], regs[10], regs[11]);
        fprintf(stderr, "guest stack dump:\n");
        for (int i = 0; i < 64; ++i) {
            uint64_t val = guest_load(regs[7] + i * 8, 8);
            if (val >= guest_image_base && val < guest_image_base + 0x500000) {
                fprintf(stderr, "  [rsp + %d]: %#llx (RVA %#llx)\n", i * 8, (unsigned long long)val, (unsigned long long)(val - guest_image_base));
            } else if (val >= 0x140000000ULL && val < 0x140500000ULL) {
                fprintf(stderr, "  [rsp + %d]: %#llx (RVA %#llx)\n", i * 8, (unsigned long long)val, (unsigned long long)(val - 0x140000000ULL));
            } else {
                fprintf(stderr, "  [rsp + %d]: %#llx\n", i * 8, (unsigned long long)val);
            }
        }
    }
    fault();
}

__attribute__((always_inline)) void guest_store(uint64_t addr, uint64_t value, uint32_t width) {
    if (fits(addr, width, STACK_BASE, STACK_SIZE)) {
        memcpy((void *)(uintptr_t)addr, &value, width);
        return;
    }
    unsigned char *section = image_fast_span(addr, width, true);
    if (section) {
        memcpy(section, &value, width);
        return;
    }
    guest_store_slow(addr, value, width);
}

uint64_t guest_acrt_iob_func(uint32_t index) {
    if (index >= IOBUF_COUNT)
        return 0;
    return IOBUF_BASE + index * IOBUF_ENTRY_SIZE;
}

uint64_t guest_errno(void) {
    return ERRNO_BASE;
}

uint64_t guest_fwrite(uint64_t buffer, uint64_t size, uint64_t count, uint64_t stream) {
    if (!size || !count)
        return 0;
    uint64_t total = size * count;
    FILE *dest = (stream == guest_acrt_iob_func(2)) ? stderr : stdout;
    const unsigned char *span = read_span(buffer, total);
    size_t written = fwrite(span, 1, total, dest);
    return written / size;
}

uint64_t guest_fputs(uint64_t str, uint64_t stream) {
    FILE *dest = (stream == guest_acrt_iob_func(2)) ? stderr : stdout;
    uint64_t len = 0;
    while (guest_load(str + len, 1) != 0) {
        if (len > 1024 * 1024)
            fault();
        ++len;
    }
    const unsigned char *span = read_span(str, len);
    if (fwrite(span, 1, len, dest) != len)
        return UINT64_MAX;
    return 0;
}

uint64_t guest_fflush(uint64_t stream) {
    if (!stream) {
        fflush(stdout);
        fflush(stderr);
        return 0;
    }
    FILE *dest = (stream == guest_acrt_iob_func(2)) ? stderr : stdout;
    fflush(dest);
    return 0;
}

uint64_t guest_fputc(uint32_t ch, uint64_t stream) {
    FILE *dest = (stream == guest_acrt_iob_func(2)) ? stderr : stdout;
    int c = fputc((int)(unsigned char)ch, dest);
    return c == EOF ? UINT64_MAX : (uint64_t)(unsigned char)c;
}

uint64_t guest_putchar(uint32_t ch) {
    int c = putchar((int)(unsigned char)ch);
    return c == EOF ? UINT64_MAX : (uint64_t)(unsigned char)c;
}

uint64_t guest_puts(uint64_t str) {
    uint64_t len = 0;
    while (guest_load(str + len, 1) != 0) {
        if (len > 1024 * 1024)
            fault();
        ++len;
    }
    const unsigned char *span = read_span(str, len);
    if (fwrite(span, 1, len, stdout) != len || putchar('\n') == EOF)
        return UINT64_MAX;
    return 0;
}

uint64_t guest_setvbuf(uint64_t stream, uint64_t buffer, uint32_t mode, uint64_t size) {
    (void)stream;
    (void)buffer;
    (void)mode;
    (void)size;
    return 0;
}

static pthread_mutex_t vectored_lock = PTHREAD_MUTEX_INITIALIZER;
static struct vectored_handler { uint64_t handle, address; } vectored[64];
static size_t vectored_count;
static uint64_t next_vectored_handle = 1;

uint64_t guest_add_vectored_exception_handler(uint32_t first, uint64_t handler) {
    if (!handler)
        return 0;
    pthread_mutex_lock(&vectored_lock);
    uint64_t handle = 0;
    if (vectored_count < sizeof vectored / sizeof *vectored) {
        size_t index = first ? 0 : vectored_count;
        memmove(vectored + index + 1, vectored + index,
                (vectored_count - index) * sizeof *vectored);
        handle = next_vectored_handle++;
        vectored[index] = (struct vectored_handler){handle, handler};
        ++vectored_count;
    }
    pthread_mutex_unlock(&vectored_lock);
    return handle;
}

uint64_t guest_remove_vectored_exception_handler(uint64_t handle) {
    pthread_mutex_lock(&vectored_lock);
    size_t index = 0;
    while (index < vectored_count && vectored[index].handle != handle)
        ++index;
    bool found = index < vectored_count;
    if (found) {
        --vectored_count;
        memmove(vectored + index, vectored + index + 1,
                (vectored_count - index) * sizeof *vectored);
    }
    pthread_mutex_unlock(&vectored_lock);
    return found;
}

uint64_t guest_message_box_a(uint64_t hwnd, uint64_t text_ptr, uint64_t caption_ptr, uint32_t type) {
    (void)hwnd;
    (void)type;
    char text[512] = "(null)", caption[128] = "Alert";
    if (text_ptr) {
        uint64_t len = 0;
        while (len < sizeof(text) - 1 && guest_load(text_ptr + len, 1) != 0) {
            text[len] = (char)guest_load(text_ptr + len, 1);
            len++;
        }
        text[len] = '\0';
    }
    if (caption_ptr) {
        uint64_t len = 0;
        while (len < sizeof(caption) - 1 && guest_load(caption_ptr + len, 1) != 0) {
            caption[len] = (char)guest_load(caption_ptr + len, 1);
            len++;
        }
        caption[len] = '\0';
    }
    printf("[NATIVE GUI ALERT] %s: %s\n", caption, text);
    if (!getenv("HEADLESS_GUI")) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "osascript -e 'display alert \"%s\" message \"%s\"' >/dev/null 2>&1 &", caption, text);
        system(cmd);
    }
    return 1;
}

uint64_t guest_message_box_w(uint64_t hwnd, uint64_t text_ptr, uint64_t caption_ptr, uint32_t type) {
    (void)hwnd;
    (void)type;
    char text[512] = "(null)", caption[128] = "Alert";
    if (text_ptr) {
        uint64_t idx = 0;
        while (idx < sizeof(text) - 1) {
            uint16_t ch = (uint16_t)guest_load(text_ptr + idx * 2, 2);
            if (!ch) break;
            text[idx] = (ch < 128) ? (char)ch : '?';
            idx++;
        }
        text[idx] = '\0';
    }
    if (caption_ptr) {
        uint64_t idx = 0;
        while (idx < sizeof(caption) - 1) {
            uint16_t ch = (uint16_t)guest_load(caption_ptr + idx * 2, 2);
            if (!ch) break;
            caption[idx] = (ch < 128) ? (char)ch : '?';
            idx++;
        }
        caption[idx] = '\0';
    }
    printf("[NATIVE GUI ALERT] %s: %s\n", caption, text);
    if (!getenv("HEADLESS_GUI")) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "osascript -e 'display alert \"%s\" message \"%s\"' >/dev/null 2>&1 &", caption, text);
        system(cmd);
    }
    return 1;
}

uint64_t guest_p_argc(void) { return ARGC_BASE; }
uint64_t guest_p_argv(void) { return ARGV_BASE; }
uint64_t guest_p_wargv(void) { return WARGV_BASE; }
uint64_t guest_p_fmode(void) { return FMODE_BASE; }
uint64_t guest_p_commode(void) { return COMMODE_BASE; }
uint64_t guest_p_wenviron(void) { return WENVIRON_BASE; }
uint64_t guest_p_environ(void) { return ENVIRON_BASE; }
uint64_t guest_crt_atexit(uint64_t fn) { (void)fn; return 0; }
uint64_t guest_register_onexit(uint64_t table, uint64_t fn) { (void)table; (void)fn; return 0; }
uint64_t guest_init_onexit(uint64_t table) { (void)table; return 0; }
uint64_t guest_exec_onexit(uint64_t table) { (void)table; return 0; }
static void (*guest_lookup_dispatch(uint64_t target))(void *, uint64_t);

uint64_t guest_initterm(uint64_t start, uint64_t end) {
    if (!current_cpu) return 0;
    for (uint64_t p = start; p < end; p += 8) {
        uint64_t fn = guest_load(p, 8);
        if (fn) {
            uint64_t *regs = (uint64_t *)current_cpu;
            regs[7] -= 8;
            guest_store(regs[7], 0, 8);
            void (*target_fn)(void *, uint64_t) = guest_lookup_dispatch(fn);
            if (target_fn) {
                target_fn(current_cpu, 0);
            } else {
                regs[7] += 8;
            }
        }
    }
    return 0;
}

uint64_t guest_initterm_e(uint64_t start, uint64_t end) {
    if (!current_cpu) return 0;
    for (uint64_t p = start; p < end; p += 8) {
        uint64_t fn = guest_load(p, 8);
        if (fn) {
            uint64_t *regs = (uint64_t *)current_cpu;
            regs[7] -= 8;
            guest_store(regs[7], 0, 8);
            void (*target_fn)(void *, uint64_t) = guest_lookup_dispatch(fn);
            if (target_fn) {
                target_fn(current_cpu, 0);
                if (regs[0] != 0) return regs[0];
            } else {
                regs[7] += 8;
            }
        }
    }
    return 0;
}
uint64_t guest_configure_argv(uint32_t mode) { (void)mode; return 0; }
uint64_t guest_init_env(void) { return 0; }
uint64_t guest_get_initial_env(void) { return 0; }
uint64_t guest_set_app_type(uint32_t type) { (void)type; return 0; }
uint64_t guest_seh_filter_exe(uint32_t code, uint64_t info) { (void)info; return (uint64_t)code; }
uint64_t guest_set_invalid_param(uint64_t handler) { (void)handler; return 0; }
uint64_t guest_cexit(void) { return 0; }
uint64_t guest_set_thread_stack_guarantee(uint64_t size_ptr) { (void)size_ptr; return 1; }

static int guest_new_mode = 0;
uint64_t guest_set_new_mode(uint32_t mode) {
    int prev = guest_new_mode;
    guest_new_mode = (int)mode;
    return (uint64_t)prev;
}

unsigned char *guest_writable_span(uint64_t addr, uint64_t size) {
    addr = guest_low_alias(addr);
    if (guest_direct(addr))
        return (unsigned char *)(uintptr_t)addr;
    if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < guest_image_span)
        addr -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *sec = &guest_sections[i];
        bool writable = section_protection ? ((section_protection[i] & 0xcc) != 0) : sec->writable;
        if (writable && fits(addr, size, sec->address, sec->size))
            return image[i] + (addr - sec->address);
    }
    return NULL;
}

uint64_t guest_wcslen(uint64_t str) {
    if (!str) return 0;
    uint64_t len = 0;
    while (guest_load(str + len * 2, 2) != 0)
        len++;
    return len;
}

uint64_t guest_wcsnlen(uint64_t str, uint64_t maxlen) {
    if (!str) return 0;
    uint64_t len = 0;
    while (len < maxlen && guest_load(str + len * 2, 2) != 0)
        len++;
    return len;
}

uint64_t guest_strlen(uint64_t str) {
    if (!str) return 0;
    uint64_t len = 0;
    while (guest_load(str + len, 1) != 0)
        len++;
    return len;
}

uint64_t guest_strnlen(uint64_t str, uint64_t maxlen) {
    if (!str) return 0;
    uint64_t len = 0;
    while (len < maxlen && guest_load(str + len, 1) != 0)
        len++;
    return len;
}

uint64_t guest_memset(uint64_t dest, uint32_t c, uint64_t count) {
    if (!count) return dest;
    unsigned char *span = guest_writable_span(dest, count);
    if (span) {
        memset(span, (int)c, (size_t)count);
    } else {
        for (uint64_t i = 0; i < count; ++i)
            guest_store(dest + i, (uint8_t)c, 1);
    }
    return dest;
}

uint64_t guest_memcpy(uint64_t dest, uint64_t src, uint64_t count) {
    if (!count || dest == src) return dest;
    unsigned char *d = guest_writable_span(dest, count);
    const unsigned char *s = read_span(src, count);
    if (d && s) {
        memmove(d, s, (size_t)count);
    } else {
        if (dest < src) {
            for (uint64_t i = 0; i < count; ++i)
                guest_store(dest + i, guest_load(src + i, 1), 1);
        } else {
            for (uint64_t i = count; i > 0; --i)
                guest_store(dest + i - 1, guest_load(src + i - 1, 1), 1);
        }
    }
    return dest;
}

uint64_t guest_strcmp(uint64_t s1, uint64_t s2) {
    if (s1 == s2) return 0;
    uint64_t i = 0;
    for (;; ++i) {
        uint8_t c1 = (uint8_t)guest_load(s1 + i, 1);
        uint8_t c2 = (uint8_t)guest_load(s2 + i, 1);
        if (c1 != c2)
            return (uint64_t)(int)(c1 - c2);
        if (!c1)
            return 0;
    }
}

uint64_t guest_strncmp(uint64_t s1, uint64_t s2, uint64_t n) {
    if (!n || s1 == s2) return 0;
    for (uint64_t i = 0; i < n; ++i) {
        uint8_t c1 = (uint8_t)guest_load(s1 + i, 1);
        uint8_t c2 = (uint8_t)guest_load(s2 + i, 1);
        if (c1 != c2)
            return (uint64_t)(int)(c1 - c2);
        if (!c1)
            return 0;
    }
    return 0;
}

uint64_t guest_memcmp(uint64_t s1, uint64_t s2, uint64_t count, uint64_t dummy) {
    (void)dummy;
    if (!count || s1 == s2) return 0;
    const unsigned char *p1 = read_span(s1, count);
    const unsigned char *p2 = read_span(s2, count);
    if (p1 && p2) {
        return (uint64_t)memcmp(p1, p2, (size_t)count);
    }
    for (uint64_t i = 0; i < count; ++i) {
        uint8_t c1 = (uint8_t)guest_load(s1 + i, 1);
        uint8_t c2 = (uint8_t)guest_load(s2 + i, 1);
        if (c1 != c2)
            return (uint64_t)(int)(c1 - c2);
    }
    return 0;
}

uint64_t guest_memchr(uint64_t s, uint32_t c, uint64_t count, uint64_t dummy) {
    (void)dummy;
    if (!s || !count) return 0;
    for (uint64_t i = 0; i < count; ++i) {
        if ((uint8_t)guest_load(s + i, 1) == (uint8_t)c)
            return s + i;
    }
    return 0;
}

uint64_t guest_strchr(uint64_t s, uint32_t c, uint64_t d1, uint64_t d2) {
    (void)d1; (void)d2;
    if (!s) return 0;
    for (uint64_t i = 0;; ++i) {
        uint8_t b = (uint8_t)guest_load(s + i, 1);
        if (b == (uint8_t)c) return s + i;
        if (!b) return 0;
    }
}

uint64_t guest_strrchr(uint64_t s, uint32_t c, uint64_t d1, uint64_t d2) {
    (void)d1; (void)d2;
    if (!s) return 0;
    uint64_t match = 0;
    for (uint64_t i = 0;; ++i) {
        uint8_t b = (uint8_t)guest_load(s + i, 1);
        if (b == (uint8_t)c) match = s + i;
        if (!b) break;
    }
    return match;
}

uint64_t guest_strstr(uint64_t haystack, uint64_t needle, uint64_t d1, uint64_t d2) {
    (void)d1; (void)d2;
    if (!haystack || !needle) return 0;
    uint8_t first = (uint8_t)guest_load(needle, 1);
    if (!first) return haystack;
    for (uint64_t i = 0;; ++i) {
        uint8_t h = (uint8_t)guest_load(haystack + i, 1);
        if (!h) return 0;
        if (h == first) {
            uint64_t j = 1;
            for (;; ++j) {
                uint8_t n = (uint8_t)guest_load(needle + j, 1);
                if (!n) return haystack + i;
                if ((uint8_t)guest_load(haystack + i + j, 1) != n) break;
            }
        }
    }
}

uint64_t guest_strcpy(uint64_t dest, uint64_t src) {
    uint64_t i = 0;
    for (;; ++i) {
        uint8_t c = (uint8_t)guest_load(src + i, 1);
        guest_store(dest + i, c, 1);
        if (!c) break;
    }
    return dest;
}

uint64_t guest_strdup(uint64_t str) {
    if (!str) return 0;
    uint64_t len = guest_strlen(str);
    uint64_t mem = guest_heap_alloc(0x7fff2001, 0, len + 1);
    if (mem)
        guest_strcpy(mem, str);
    return mem;
}

uint64_t guest_isalnum(uint32_t c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
uint64_t guest_isalpha(uint32_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
uint64_t guest_isspace(uint32_t c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }

uint64_t guest_process_prng(uint64_t buffer, uint64_t size) {
    if (!size) return 1;
    unsigned char *span = guest_writable_span(buffer, size);
    if (span) {
        arc4random_buf(span, (size_t)size);
    } else {
        unsigned char tmp[64];
        uint64_t remaining = size, cur = buffer;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof tmp ? sizeof tmp : (size_t)remaining;
            arc4random_buf(tmp, chunk);
            for (size_t i = 0; i < chunk; ++i)
                guest_store(cur + i, tmp[i], 1);
            cur += chunk;
            remaining -= chunk;
        }
    }
    return 1;
}

uint64_t guest_compare_words(uint64_t first, uint64_t second, uint32_t width) {
    uint64_t result = 0;
    uint64_t difference = first ^ second;
    uint64_t mask = (UINT64_C(1) << width) - 1;
    for (unsigned i = 0; i < 64; i += width)
        if (((difference >> i) & mask) == 0)
            result |= mask << i;
    return result;
}

uint32_t guest_vector_mask(uint64_t low, uint64_t high) {
    uint32_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        result |= ((low >> (8 * i + 7)) & 1) << i;
        result |= ((high >> (8 * i + 7)) & 1) << (8 + i);
    }
    return result;
}

uint32_t guest_movmskps(uint64_t low, uint64_t high) {
    return (uint32_t)(((low >> 31) & 1) | (((low >> 63) & 1) << 1) |
                      (((high >> 31) & 1) << 2) | (((high >> 63) & 1) << 3));
}

uint64_t guest_packuswb(uint64_t low, uint64_t high) {
    uint64_t packed = 0;
    for (unsigned i = 0; i < 8; ++i) {
        int16_t word = (int16_t)((i < 4 ? low : high) >> ((i % 4) * 16));
        unsigned byte = word < 0 ? 0 : word > 255 ? 255 : (unsigned)word;
        packed |= (uint64_t)byte << (i * 8);
    }
    return packed;
}

/* packsswb: eight signed words to signed-saturated bytes. */
uint64_t guest_packsswb(uint64_t low, uint64_t high) {
    uint64_t packed = 0;
    for (unsigned i = 0; i < 8; ++i) {
        int16_t word = (int16_t)((i < 4 ? low : high) >> ((i % 4) * 16));
        int byte = word < -128 ? -128 : word > 127 ? 127 : word;
        packed |= (uint64_t)(uint8_t)byte << (i * 8);
    }
    return packed;
}

/* packssdw: four signed doublewords to signed-saturated words. */
uint64_t guest_packssdw(uint64_t low, uint64_t high) {
    uint64_t packed = 0;
    for (unsigned i = 0; i < 4; ++i) {
        int32_t value = (int32_t)((i < 2 ? low : high) >> ((i % 2) * 32));
        int word = value < -32768 ? -32768 : value > 32767 ? 32767 : value;
        packed |= (uint64_t)(uint16_t)word << (i * 16);
    }
    return packed;
}

uint64_t guest_shuffle(uint64_t low, uint64_t high, uint64_t other,
                       uint32_t operation, uint32_t control, uint32_t lane) {
    uint64_t result = 0;
    if (operation == 0) {
        for (unsigned i = 0; i < 4; ++i) {
            unsigned input = 8 * (lane * 4 + i);
            uint64_t pair = ((other >> input) & 255) | (((low >> input) & 255) << 8);
            result |= pair << (16 * i);
        }
    } else if (operation == 1) {
        if (lane)
            return high;
        for (unsigned i = 0; i < 4; ++i)
            result |= ((low >> (16 * ((control >> (2 * i)) & 3))) & 65535) << (16 * i);
    } else {
        for (unsigned i = 0; i < 2; ++i) {
            unsigned index = (control >> (2 * (2 * lane + i))) & 3;
            uint64_t word = ((index < 2 ? low : high) >> (32 * (index % 2))) & UINT32_MAX;
            result |= word << (32 * i);
        }
    }
    return result;
}

/* pshufb: eight result bytes selected from the 16-byte table by one half of the mask. */
uint64_t guest_pshufb(uint64_t low, uint64_t high, uint64_t mask) {
    unsigned char table[16], control[8], result[8];
    memcpy(table, &low, 8);
    memcpy(table + 8, &high, 8);
    memcpy(control, &mask, 8);
    for (int i = 0; i < 8; ++i)
        result[i] = control[i] & 0x80 ? 0 : table[control[i] & 15];
    uint64_t value;
    memcpy(&value, result, 8);
    return value;
}

uint64_t guest_vector_shift(uint64_t val, uint64_t count, uint32_t kind) {
    if (kind == 0) { // psllw
        if (count >= 16) return 0;
        uint16_t w[4];
        memcpy(w, &val, 8);
        for (int i = 0; i < 4; i++) w[i] <<= count;
        uint64_t res;
        memcpy(&res, w, 8);
        return res;
    } else if (kind == 1) { // psrlw
        if (count >= 16) return 0;
        uint16_t w[4];
        memcpy(w, &val, 8);
        for (int i = 0; i < 4; i++) w[i] >>= count;
        uint64_t res;
        memcpy(&res, w, 8);
        return res;
    } else if (kind == 2) { // pslld
        if (count >= 32) return 0;
        uint32_t d[2];
        memcpy(d, &val, 8);
        d[0] <<= count;
        d[1] <<= count;
        uint64_t res;
        memcpy(&res, d, 8);
        return res;
    } else if (kind == 3) { // psrld
        if (count >= 32) return 0;
        uint32_t d[2];
        memcpy(d, &val, 8);
        d[0] >>= count;
        d[1] >>= count;
        uint64_t res;
        memcpy(&res, d, 8);
        return res;
    } else if (kind == 4) { // psllq
        if (count >= 64) return 0;
        return val << count;
    } else if (kind == 5) { // psrlq
        if (count >= 64) return 0;
        return val >> count;
    } else if (kind == 6) { // psraw: counts past the width fill with the sign
        int16_t w[4];
        memcpy(w, &val, 8);
        for (int i = 0; i < 4; i++) w[i] = (int16_t)(w[i] >> (count > 15 ? 15 : count));
        uint64_t res;
        memcpy(&res, w, 8);
        return res;
    } else if (kind == 7) { // psrad
        int32_t d[2];
        memcpy(d, &val, 8);
        d[0] >>= count > 31 ? 31 : count;
        d[1] >>= count > 31 ? 31 : count;
        uint64_t res;
        memcpy(&res, d, 8);
        return res;
    }
    return 0;
}

void guest_div32(uint64_t dividend, uint64_t divisor, uint64_t *quotient, uint64_t *remainder) {
    if (!divisor || (dividend >> 32) >= divisor)
        guest_trap("guest unsigned division fault");
    *quotient = dividend / divisor;
    *remainder = dividend % divisor;
}

void guest_div(uint64_t high, uint64_t low, uint64_t denominator,
               uint64_t *quotient, uint64_t *remainder) {
    if (!denominator || high >= denominator)
        guest_trap("guest unsigned division fault");
    __uint128_t dividend = ((__uint128_t)high << 64) | low;
    *quotient = dividend / denominator;
    *remainder = dividend % denominator;
}

void guest_idiv32(int64_t dividend, int32_t divisor, uint64_t *quotient, uint64_t *remainder) {
    if (!divisor) guest_trap("guest signed division by zero");
    int64_t q = dividend / divisor;
    int64_t r = dividend % divisor;
    if (q < INT32_MIN || q > INT32_MAX) guest_trap("guest signed division overflow");
    *quotient = (uint32_t)(int32_t)q;
    *remainder = (uint32_t)(int32_t)r;
}

void guest_idiv(int64_t high, uint64_t low, int64_t denominator,
                uint64_t *quotient, uint64_t *remainder) {
    if (!denominator) guest_trap("guest signed division by zero");
    __int128 dividend = ((__int128)high << 64) | low;
    __int128 q = dividend / denominator;
    __int128 r = dividend % denominator;
    if (q < INT64_MIN || q > INT64_MAX) guest_trap("guest signed division overflow");
    *quotient = (uint64_t)(int64_t)q;
    *remainder = (uint64_t)(int64_t)r;
}

/* ========================================================================= */
/* x87 FPU Stack Emulation & Vector Helpers                                  */
/* ========================================================================= */
static _Thread_local double guest_st[8];
static _Thread_local int guest_st_top = 0;
static _Thread_local uint16_t guest_fpu_sw = 0;

static double load_f80(const uint8_t *b) {
    uint64_t mant = *(const uint64_t *)b;
    uint16_t exp_sign = *(const uint16_t *)(b + 8);
    int sign = (exp_sign >> 15) & 1;
    int exp = exp_sign & 0x7fff;
    if (exp == 0 && mant == 0) return sign ? -0.0 : 0.0;
    if (exp == 0x7fff) {
        if ((mant & 0x7fffffffffffffffull) == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    double frac = (double)mant / 18446744073709551616.0;
    double val = ldexp(frac, exp - 16383 + 1);
    return sign ? -val : val;
}

static void store_f80(uint8_t *b, double val) {
    if (isnan(val)) {
        memset(b, 0, 10);
        *(uint64_t *)b = 0xc000000000000000ull;
        *(uint16_t *)(b + 8) = 0x7fff;
        return;
    }
    if (isinf(val)) {
        memset(b, 0, 10);
        *(uint64_t *)b = 0x8000000000000000ull;
        *(uint16_t *)(b + 8) = (val < 0 ? 0xffff : 0x7fff);
        return;
    }
    if (val == 0.0) {
        memset(b, 0, 10);
        if (signbit(val)) *(uint16_t *)(b + 8) = 0x8000;
        return;
    }
    int sign = signbit(val) ? 1 : 0;
    if (sign) val = -val;
    int exp;
    double norm = frexp(val, &exp);
    uint64_t mant = (uint64_t)(norm * 18446744073709551616.0);
    int x86_exp = exp + 16383 - 1;
    if (x86_exp < 0) x86_exp = 0;
    if (x86_exp > 0x7fff) x86_exp = 0x7fff;
    *(uint64_t *)b = mant;
    *(uint16_t *)(b + 8) = (sign << 15) | (x86_exp & 0x7fff);
}

void guest_fld_f80(uint64_t addr) {
    uint8_t buf[10];
    for (int i = 0; i < 10; ++i) buf[i] = (uint8_t)guest_load(addr + i, 1);
    guest_st_top = (guest_st_top - 1) & 7;
    guest_st[guest_st_top] = load_f80(buf);
}

void guest_fstp_f80(uint64_t addr) {
    uint8_t buf[10];
    store_f80(buf, guest_st[guest_st_top]);
    for (int i = 0; i < 10; ++i) guest_store(addr + i, buf[i], 1);
    guest_st_top = (guest_st_top + 1) & 7;
}

void guest_fld_f64(uint64_t addr) {
    union { double d; uint64_t u; } val;
    val.u = guest_load(addr, 8);
    guest_st_top = (guest_st_top - 1) & 7;
    guest_st[guest_st_top] = val.d;
}

void guest_fstp_f64(uint64_t addr) {
    union { double d; uint64_t u; } val;
    val.d = guest_st[guest_st_top];
    guest_store(addr, val.u, 8);
    guest_st_top = (guest_st_top + 1) & 7;
}

void guest_fld_f32(uint64_t addr) {
    union { float f; uint32_t u; } val;
    val.u = (uint32_t)guest_load(addr, 4);
    guest_st_top = (guest_st_top - 1) & 7;
    guest_st[guest_st_top] = (double)val.f;
}

void guest_fstp_f32(uint64_t addr) {
    union { float f; uint32_t u; } val;
    val.f = (float)guest_st[guest_st_top];
    guest_store(addr, val.u, 4);
    guest_st_top = (guest_st_top + 1) & 7;
}

void guest_fild(int64_t val) {
    guest_st_top = (guest_st_top - 1) & 7;
    guest_st[guest_st_top] = (double)val;
}

void guest_fldz(void) {
    guest_st_top = (guest_st_top - 1) & 7;
    guest_st[guest_st_top] = 0.0;
}

void guest_fld_st(uint32_t idx) {
    double val = guest_st[(guest_st_top + idx) & 7];
    guest_st_top = (guest_st_top - 1) & 7;
    guest_st[guest_st_top] = val;
}

void guest_fstp_st(uint32_t idx) {
    guest_st[(guest_st_top + idx) & 7] = guest_st[guest_st_top];
    guest_st_top = (guest_st_top + 1) & 7;
}

void guest_fxch(uint32_t idx) {
    int i0 = guest_st_top;
    int i1 = (guest_st_top + idx) & 7;
    double tmp = guest_st[i0];
    guest_st[i0] = guest_st[i1];
    guest_st[i1] = tmp;
}

void guest_faddp(uint32_t idx) {
    guest_st[(guest_st_top + idx) & 7] += guest_st[guest_st_top];
    guest_st_top = (guest_st_top + 1) & 7;
}

uint32_t guest_fcompi(uint32_t idx, uint32_t pop) {
    double a = guest_st[guest_st_top];
    double b = guest_st[(guest_st_top + idx) & 7];
    if (pop) guest_st_top = (guest_st_top + 1) & 7;
    if (isnan(a) || isnan(b)) return 0x3; // ZF=1, CF=1
    if (a < b) return 0x2; // ZF=0, CF=1
    if (a > b) return 0x0; // ZF=0, CF=0
    return 0x1; // ZF=1, CF=0
}

void guest_fscale(void) {
    guest_st[guest_st_top] = ldexp(guest_st[guest_st_top], (int)trunc(guest_st[(guest_st_top + 1) & 7]));
}

void guest_fprem(void) {
    guest_st[guest_st_top] = fmod(guest_st[guest_st_top], guest_st[(guest_st_top + 1) & 7]);
}

void guest_fninit(void) {
    guest_st_top = 0;
    guest_fpu_sw = 0;
}

uint16_t guest_fnstsw(void) {
    return guest_fpu_sw | (uint16_t)((guest_st_top & 7) << 11);
}

uint64_t guest_shufps(uint64_t d0, uint64_t d1, uint64_t s0, uint64_t s1, uint32_t imm, uint32_t lane) {
    uint32_t d_lanes[4] = { (uint32_t)d0, (uint32_t)(d0 >> 32), (uint32_t)d1, (uint32_t)(d1 >> 32) };
    uint32_t s_lanes[4] = { (uint32_t)s0, (uint32_t)(s0 >> 32), (uint32_t)s1, (uint32_t)(s1 >> 32) };
    uint32_t out[4];
    out[0] = d_lanes[imm & 3];
    out[1] = d_lanes[(imm >> 2) & 3];
    out[2] = s_lanes[(imm >> 4) & 3];
    out[3] = s_lanes[(imm >> 6) & 3];
    if (lane == 0) return (uint64_t)out[0] | ((uint64_t)out[1] << 32);
    return (uint64_t)out[2] | ((uint64_t)out[3] << 32);
}

uint64_t guest_punpcklwd(uint64_t d0, uint64_t s0, uint32_t lane) {
    uint16_t d[4] = { (uint16_t)d0, (uint16_t)(d0 >> 16), (uint16_t)(d0 >> 32), (uint16_t)(d0 >> 48) };
    uint16_t s[4] = { (uint16_t)s0, (uint16_t)(s0 >> 16), (uint16_t)(s0 >> 32), (uint16_t)(s0 >> 48) };
    if (lane == 0) {
        return (uint64_t)d[0] | ((uint64_t)s[0] << 16) | ((uint64_t)d[1] << 32) | ((uint64_t)s[1] << 48);
    } else {
        return (uint64_t)d[2] | ((uint64_t)s[2] << 16) | ((uint64_t)d[3] << 32) | ((uint64_t)s[3] << 48);
    }
}

/* movs/rep movs with DF clear: element-wise forward copy, so overlapping moves behave like x86. */
void guest_move_string(uint64_t destination, uint64_t source, uint64_t count, uint32_t width) {
    for (uint64_t i = 0; i < count; ++i)
        guest_store(destination + i * width, guest_load(source + i * width, width), width);
}

uint64_t guest_fill(uint64_t destination, uint64_t count, uint64_t value, uint32_t width) {
    if (count > 16 * 1024 * 1024 / width)
        guest_trap("guest fill exceeds runtime limit");
    for (uint64_t i = 0; i < count; ++i) {
        guest_store(destination, value, width);
        destination += width;
    }
    return destination;
}

void guest_startup_info(uint64_t destination) {
    for (unsigned offset = 0; offset < 104; offset += 8)
        guest_store(destination + offset, 0, 8);
    guest_store(destination, 104, 4);
}

/*
 * Guest address ranges that host mappings handed to the guest (VirtualAlloc,
 * MapViewOfFile) must never overlap, because the runtime resolves addresses
 * in them as image memory: the primary image window and every guest DLL
 * image [base, base + SizeOfImage), linked-in or translated on demand.
 * Linked-in modules are reserved even before they load, since their bases are
 * fixed at build time. Returns the end of the first overlapping range, or 0.
 */
static uint64_t guest_reserved_overlap(uint64_t address, uint64_t size) {
    uint64_t end = address + (size ? size : 1);
    if (end < address)
        return UINT64_MAX;
    if (guest_image_base && address < guest_image_base + 0x20000000 && end > guest_image_base)
        return guest_image_base + 0x20000000;
    for (size_t i = 0; i < guest_module_count; ++i) {
        const struct guest_module *module = &guest_modules[i];
        if (address < module->base + module->size && end > module->base)
            return module->base + module->size;
    }
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next)
        if (address < item->module->base + item->module->size && end > item->module->base)
            return item->module->base + item->module->size;
    return 0;
}

#include "console_subsystems.h"

uint64_t guest_close_handle(uint64_t handle) {
    return guest_close_handle_unified(handle);
}

uint64_t guest_nt_read_file(uint64_t handle, uint64_t event, uint64_t apc,
                            uint64_t context, uint64_t args) {
    (void)context;
    uint64_t io_status = guest_load(args, 8);
    uint64_t buffer = guest_load(args + 8, 8);
    uint32_t requested = (uint32_t)guest_load(args + 16, 4);
    uint64_t offset = guest_load(args + 24, 8);
    struct HandleEntry *entry = get_handle(handle);
    uint32_t status = 0;
    ssize_t count = 0;
    if (!entry || entry->kind != HANDLE_KIND_FILE || entry->fd < 0)
        status = 0xc0000008;
    else if (!io_status || event || apc)
        status = 0xc000000d;
    else if (requested) {
        unsigned char *host = guest_writable_span(buffer, requested);
        int64_t position = offset ? (int64_t)guest_load(offset, 8) : -2;
        if (!host || position < -2 || position == -1)
            status = 0xc000000d;
        else {
            do {
                count = position == -2 ? read(entry->fd, host, requested) :
                                         pread(entry->fd, host, requested, position);
            } while (count < 0 && errno == EINTR);
            if (count <= 0)
                status = count == 0 ? 0xc0000011 : 0xc0000185;
        }
    }
    if (io_status) {
        guest_store(io_status, status, 8);
        guest_store(io_status + 8, count > 0 ? (uint64_t)count : 0, 8);
    }
    return status;
}

uint64_t guest_nt_write_file(uint64_t handle, uint64_t event, uint64_t apc,
                             uint64_t context, uint64_t args) {
    (void)context;
    uint64_t io_status = guest_load(args, 8);
    uint64_t buffer = guest_load(args + 8, 8);
    uint32_t requested = (uint32_t)guest_load(args + 16, 4);
    uint64_t offset = guest_load(args + 24, 8);
    int fd = -1;
    if (handle == 1 || handle == 2) {
        fd = (int)handle;
    } else if (handle == 3) {
        fd = 0;
    } else if (handle == 0x10 || handle == 0x14 || handle == 0x18) {
        fd = (handle == 0x18 || handle == 0x14) ? 2 : 1;
    } else {
        struct HandleEntry *entry = get_handle(handle);
        if (entry && entry->kind == HANDLE_KIND_FILE && entry->fd >= 0)
            fd = entry->fd;
    }
    uint32_t status = 0;
    ssize_t count = 0;
    if (fd < 0) {
        status = 0xc0000008; // STATUS_INVALID_HANDLE
    } else if (!io_status || event || apc) {
        status = 0xc000000d; // STATUS_INVALID_PARAMETER
    } else if (requested) {
        const unsigned char *host = read_span(buffer, requested);
        int64_t position = offset ? (int64_t)guest_load(offset, 8) : -2;
        if (!host || position < -2 || position == -1) {
            status = 0xc000000d;
        } else {
            do {
                count = position == -2 ? write(fd, host, requested) :
                                         pwrite(fd, host, requested, position);
            } while (count < 0 && errno == EINTR);
            if (count < 0)
                status = 0xc0000001; // STATUS_UNSUCCESSFUL
        }
    }
    if (io_status) {
        guest_store(io_status, status, 8);
        guest_store(io_status + 8, count > 0 ? (uint64_t)count : 0, 8);
    }
    return status;
}

#include "generated_shims.h"

static uint64_t guest_localeconv(void);
static uint64_t guest_setlocale(uint64_t category, uint64_t locale_ptr);

/* Set when a named call fell through to guest_unimplemented_stub. */
static _Thread_local const char *unimplemented_call;

uint64_t guest_unimplemented_stub(const char *func_name, const char *dll_name) {
    if (func_name) {
        if (strcmp(func_name, "setlocale") == 0) return guest_setlocale(0, 0);
        if (strcmp(func_name, "localeconv") == 0) return guest_localeconv();
        if (strcmp(func_name, "PathIsRelativeA") == 0) return 1;
        if (strcmp(func_name, "_lock_file") == 0 || strcmp(func_name, "_unlock_file") == 0) return 0;
        if (strcmp(func_name, "_beginthreadex") == 0) return 0x7fff6001;
        if (strcmp(func_name, "_endthreadex") == 0) return 0;
        if (strcmp(func_name, "GetTimeZoneInformation") == 0) return 0;
        if (strcmp(func_name, "GetProcessAffinityMask") == 0) return 1;
        if (strcmp(func_name, "SetProcessAffinityMask") == 0) return 1;
        if (strcmp(func_name, "ResumeThread") == 0) return 1;
        if (strcmp(func_name, "SuspendThread") == 0) return 0;
        if (strcmp(func_name, "TryEnterCriticalSection") == 0) return 1;
    }
    unimplemented_call = func_name;
    static const char *logged_functions[1024];
    static size_t logged_count = 0;
    static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&log_lock);
    bool already_logged = false;
    for (size_t i = 0; i < logged_count; ++i) {
        if (strcmp(logged_functions[i], func_name) == 0) {
            already_logged = true;
            break;
        }
    }
    if (!already_logged && logged_count < sizeof(logged_functions) / sizeof(*logged_functions)) {
        logged_functions[logged_count++] = strdup(func_name);
        fprintf(stderr, "[WARN] Unimplemented Win32 API: %s!%s (returning 0)\n",
                dll_name ? dll_name : "unknown.dll", func_name);
    }
    pthread_mutex_unlock(&log_lock);
    return 0;
}

static int format_guest_string(char *out, size_t out_size, uint64_t fmt_addr, uint64_t va_addr) {
    if (!out || !out_size || !fmt_addr) return 0;
    size_t out_idx = 0;
    uint64_t arg_idx = 0;
    size_t fmt_len = 0;
    while (guest_load(fmt_addr + fmt_len, 1) != 0 && fmt_len < 65536) fmt_len++;
    char *fmt = malloc(fmt_len + 1);
    if (!fmt) return 0;
    for (size_t i = 0; i <= fmt_len; ++i) fmt[i] = (char)guest_load(fmt_addr + i, 1);

    for (size_t i = 0; i < fmt_len && out_idx + 1 < out_size; ) {
        if (fmt[i] != '%') {
            out[out_idx++] = fmt[i++];
            continue;
        }
        if (i + 1 < fmt_len && fmt[i+1] == '%') {
            out[out_idx++] = '%';
            i += 2;
            continue;
        }
        size_t spec_start = i;
        i++; // skip '%'
        while (i < fmt_len && (fmt[i] == '-' || fmt[i] == '+' || fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) i++;
        if (i < fmt_len && fmt[i] == '*') {
            i++;
            arg_idx++;
        } else {
            while (i < fmt_len && isdigit((unsigned char)fmt[i])) i++;
        }
        if (i < fmt_len && fmt[i] == '.') {
            i++;
            if (i < fmt_len && fmt[i] == '*') {
                i++;
                arg_idx++;
            } else {
                while (i < fmt_len && isdigit((unsigned char)fmt[i])) i++;
            }
        }
        while (i < fmt_len && (fmt[i] == 'h' || fmt[i] == 'l' || fmt[i] == 'j' || fmt[i] == 'z' || fmt[i] == 't' || fmt[i] == 'L' || fmt[i] == 'I')) i++;
        if (i >= fmt_len) break;
        char type = fmt[i++];
        char spec[64];
        size_t spec_len = i - spec_start;
        if (spec_len >= sizeof(spec)) spec_len = sizeof(spec) - 1;
        memcpy(spec, fmt + spec_start, spec_len);
        spec[spec_len] = '\0';

        uint64_t raw_arg = va_addr ? guest_load(va_addr + (arg_idx++) * 8, 8) : 0;
        if (type == 's') {
            char buf[1024];
            if (!raw_arg) {
                snprintf(buf, sizeof(buf), "(null)");
            } else {
                size_t s_len = 0;
                while (guest_load(raw_arg + s_len, 1) != 0 && s_len < sizeof(buf) - 1) {
                    buf[s_len] = (char)guest_load(raw_arg + s_len, 1);
                    s_len++;
                }
                buf[s_len] = '\0';
            }
            char tmp[2048];
            snprintf(tmp, sizeof(tmp), spec, buf);
            size_t t_len = strlen(tmp);
            if (out_idx + t_len >= out_size) t_len = out_size - out_idx - 1;
            memcpy(out + out_idx, tmp, t_len);
            out_idx += t_len;
        } else if (type == 'f' || type == 'g' || type == 'e' || type == 'a' ||
                   type == 'F' || type == 'G' || type == 'E' || type == 'A') {
            double d;
            memcpy(&d, &raw_arg, sizeof(double));
            int written = snprintf(out + out_idx, out_size - out_idx, spec, d);
            if (written > 0) out_idx += written;
        } else if (type == 'p') {
            int written = snprintf(out + out_idx, out_size - out_idx, spec, (void*)raw_arg);
            if (written > 0) out_idx += written;
        } else if (type == 'c') {
            char ch = (char)raw_arg;
            out[out_idx++] = ch;
        } else {
            char llspec[64];
            if (!strstr(spec, "ll") && !strstr(spec, "l") && !strstr(spec, "I64") && !strstr(spec, "z")) {
                size_t l = strlen(spec);
                spec[l-1] = '\0';
                snprintf(llspec, sizeof(llspec), "%sll%c", spec, type);
            } else {
                strncpy(llspec, spec, sizeof(llspec) - 1);
                llspec[sizeof(llspec)-1] = '\0';
            }
            if (type == 'd' || type == 'i') {
                if (strstr(spec, "ll") || strstr(spec, "l") || strstr(spec, "I64") || strstr(spec, "z")) {
                    int written = snprintf(out + out_idx, out_size - out_idx, llspec, (long long)raw_arg);
                    if (written > 0) out_idx += written;
                } else {
                    int written = snprintf(out + out_idx, out_size - out_idx, llspec, (long long)(int32_t)raw_arg);
                    if (written > 0) out_idx += written;
                }
            } else {
                if (strstr(spec, "ll") || strstr(spec, "l") || strstr(spec, "I64") || strstr(spec, "z")) {
                    int written = snprintf(out + out_idx, out_size - out_idx, llspec, (unsigned long long)raw_arg);
                    if (written > 0) out_idx += written;
                } else {
                    int written = snprintf(out + out_idx, out_size - out_idx, llspec, (unsigned long long)(uint32_t)raw_arg);
                    if (written > 0) out_idx += written;
                }
            }
        }
    }
    out[out_idx] = '\0';
    free(fmt);
    return (int)out_idx;
}

static int subsys_stdio_common_vfprintf(uint64_t options, uint64_t stream, uint64_t fmt_addr, uint64_t locale, uint64_t va_addr) {
    (void)options; (void)locale;
    char buffer[65536];
    int len = format_guest_string(buffer, sizeof(buffer), fmt_addr, va_addr);
    FILE *dest = (stream == guest_acrt_iob_func(2)) ? stderr : stdout;
    fwrite(buffer, 1, len, dest);
    return len;
}

static int subsys_stdio_common_vsprintf(uint64_t options, uint64_t dest_buf, uint64_t buf_count, uint64_t fmt_addr, uint64_t va_addr) {
    (void)options;
    char local_buf[65536];
    int len = format_guest_string(local_buf, sizeof(local_buf), fmt_addr, va_addr);
    if (buf_count > 0 && dest_buf) {
        size_t to_copy = (size_t)len;
        if (to_copy >= buf_count) to_copy = buf_count - 1;
        for (size_t i = 0; i < to_copy; ++i) guest_store(dest_buf + i, (unsigned char)local_buf[i], 1);
        guest_store(dest_buf + to_copy, 0, 1);
    }
    return len;
}

static uint64_t guest_path_is_relative_a(uint64_t path) {
    if (!path) return 1;
    char c0 = (char)guest_load(path, 1);
    char c1 = (char)guest_load(path + 1, 1);
    if (c0 == '/' || c0 == '\\') return 0;
    if (isalpha((unsigned char)c0) && c1 == ':') return 0;
    return 1;
}

static uint64_t guest_fullpath(uint64_t absPath, uint64_t relPath, uint64_t maxLen) {
    (void)maxLen;
    char rel[1024];
    size_t i = 0;
    while (i < sizeof(rel) - 1) {
        char c = (char)guest_load(relPath + i, 1);
        if (!c) break;
        if (c == '\\') c = '/';
        rel[i++] = c;
    }
    rel[i] = '\0';
    char resolved[1024];
    if (!realpath(rel, resolved)) {
        strncpy(resolved, rel, sizeof(resolved) - 1);
        resolved[sizeof(resolved) - 1] = '\0';
    }
    size_t res_len = strlen(resolved);
    if (!absPath) {
        absPath = guest_heap_alloc(0x7fff2001, 0, res_len + 1);
    }
    for (size_t j = 0; j <= res_len; ++j) {
        guest_store(absPath + j, (unsigned char)resolved[j], 1);
    }
    return absPath;
}

static uint64_t subsys_crt_read(int fd, uint64_t buf, size_t count) {
    if (!count) return 0;
    char *tmp = malloc(count);
    if (!tmp) return UINT64_MAX;
    ssize_t n = read(fd, tmp, count);
    if (n > 0) {
        for (ssize_t i = 0; i < n; ++i)
            guest_store(buf + i, (unsigned char)tmp[i], 1);
    }
    free(tmp);
    return n >= 0 ? (uint64_t)n : UINT64_MAX;
}

static uint64_t subsys_crt_write(int fd, uint64_t buf, size_t count) {
    if (!count) return 0;
    char *tmp = malloc(count);
    if (!tmp) return UINT64_MAX;
    for (size_t i = 0; i < count; ++i)
        tmp[i] = (char)guest_load(buf + i, 1);
    ssize_t n = write(fd, tmp, count);
    free(tmp);
    return n >= 0 ? (uint64_t)n : UINT64_MAX;
}

static uint64_t subsys_crt_open(uint64_t path_addr, int oflag, int pmode) {
    if (!path_addr) return UINT64_MAX;
    char path[1024];
    size_t i = 0;
    while (i < sizeof(path) - 1) {
        char c = (char)guest_load(path_addr + i, 1);
        if (!c) break;
        if (c == '\\') c = '/';
        path[i++] = c;
    }
    path[i] = '\0';
    if (strcmp(path, "-") == 0) return 0;
    int posix_flags = 0;
    int acc = oflag & 3;
    if (acc == 0) posix_flags |= O_RDONLY;
    else if (acc == 1) posix_flags |= O_WRONLY;
    else if (acc == 2) posix_flags |= O_RDWR;
    if (oflag & 0x0008) posix_flags |= O_APPEND;
    if (oflag & 0x0100) posix_flags |= O_CREAT;
    if (oflag & 0x0200) posix_flags |= O_TRUNC;
    if (oflag & 0x0400) posix_flags |= O_EXCL;
    int fd = open(path, posix_flags, pmode ? pmode : 0644);
    if (fd < 0) {
        set_win32_errno(errno);
        return UINT64_MAX;
    }
    return (uint64_t)fd;
}

static FILE *stream_to_file(uint64_t stream) {
    if (!stream) return stdin;
    if (stream == guest_acrt_iob_func(2)) return stderr;
    if (stream == guest_acrt_iob_func(1)) return stdout;
    if (stream == guest_acrt_iob_func(0)) return stdin;
    return (FILE *)(uintptr_t)stream;
}

static uint64_t subsys_crt_fread(uint64_t buf, uint64_t size, uint64_t count, uint64_t stream) {
    size_t total = (size_t)(size * count);
    if (!total) return 0;
    FILE *f = stream_to_file(stream);
    if (!f) return 0;
    char *tmp = malloc(total);
    if (!tmp) return 0;
    size_t n = fread(tmp, (size_t)size, (size_t)count, f);
    size_t bytes = n * (size_t)size;
    for (size_t i = 0; i < bytes; ++i)
        guest_store(buf + i, (unsigned char)tmp[i], 1);
    free(tmp);
    return n;
}

static uint64_t subsys_crt_getc(uint64_t stream) {
    FILE *f = stream_to_file(stream);
    if (!f) return UINT64_MAX;
    int c = getc(f);
    return c == EOF ? UINT64_MAX : (uint64_t)(unsigned char)c;
}

static uint64_t subsys_crt_fgets(uint64_t buf, uint32_t num, uint64_t stream) {
    if (num <= 1) return buf;
    FILE *f = stream_to_file(stream);
    if (!f) return 0;
    char *tmp = malloc(num);
    if (!tmp) return 0;
    char *res = fgets(tmp, (int)num, f);
    if (res) {
        size_t len = strlen(res);
        for (size_t i = 0; i <= len; ++i)
            guest_store(buf + i, (unsigned char)res[i], 1);
        free(tmp);
        return buf;
    }
    free(tmp);
    return 0;
}

static uint64_t subsys_crt_wfopen(uint64_t name_addr, uint64_t mode_addr) {
    if (!name_addr || !mode_addr) return 0;
    char path[1024];
    size_t i = 0;
    while (i < sizeof(path) - 1) {
        uint16_t c = (uint16_t)guest_load(name_addr + i * 2, 2);
        if (!c) break;
        if (c == '\\') c = '/';
        path[i++] = (char)c;
    }
    path[i] = '\0';
    char mode[16];
    size_t j = 0;
    while (j < sizeof(mode) - 1) {
        uint16_t c = (uint16_t)guest_load(mode_addr + j * 2, 2);
        if (!c) break;
        mode[j++] = (char)c;
    }
    mode[j] = '\0';
    FILE *f = fopen(path, mode);
    return (uint64_t)(uintptr_t)f;
}

static uint64_t guest_feof(uint64_t stream) {
    FILE *f = stream_to_file(stream);
    return f ? (uint64_t)feof(f) : 1;
}

static uint64_t guest_ferror(uint64_t stream) {
    FILE *f = stream_to_file(stream);
    return f ? (uint64_t)ferror(f) : 0;
}

static uint64_t guest_strerror(int err) {
    const char *msg = strerror(err ? err : ENOENT);
    size_t len = strlen(msg);
    uint64_t mem = guest_heap_alloc(0x7fff2001, 0, len + 1);
    if (mem) {
        for (size_t i = 0; i <= len; ++i)
            guest_store(mem + i, (unsigned char)msg[i], 1);
    }
    return mem;
}

uint64_t guest_getenv(uint64_t name_addr) {
    if (!name_addr) return 0;
    char name_buf[256];
    size_t i = 0;
    while (i < sizeof(name_buf) - 1) {
        char c = (char)guest_load(name_addr + i, 1);
        if (!c) break;
        name_buf[i++] = c;
    }
    name_buf[i] = '\0';
    const char *val = getenv(name_buf);
    if (!val) return 0;
    size_t len = strlen(val);
    uint64_t mem = guest_heap_alloc(0x7fff2001, 0, len + 1);
    if (mem) {
        for (size_t j = 0; j <= len; ++j)
            guest_store(mem + j, (unsigned char)val[j], 1);
    }
    return mem;
}

static uint64_t guest_fclose(uint64_t stream) {
    (void)stream;
    return 0;
}

static uint64_t guest_stat64(uint64_t path_ptr, uint64_t buf) {
    char path[1024];
    size_t i = 0;
    while (i < sizeof(path) - 1) {
        char c = (char)guest_load(path_ptr + i, 1);
        if (!c) break;
        if (c == '\\') c = '/';
        path[i++] = c;
    }
    path[i] = '\0';
    struct stat st;
    if (stat(path, &st) != 0) {
        last_error = 2; // ERROR_FILE_NOT_FOUND
        return UINT64_MAX;
    }
    guest_store(buf + 0, (uint32_t)st.st_dev, 4);
    guest_store(buf + 4, (uint16_t)st.st_ino, 2);
    guest_store(buf + 6, (uint16_t)st.st_mode, 2);
    guest_store(buf + 8, (uint16_t)st.st_nlink, 2);
    guest_store(buf + 10, (uint16_t)st.st_uid, 2);
    guest_store(buf + 12, (uint16_t)st.st_gid, 2);
    guest_store(buf + 14, 0, 2);
    guest_store(buf + 16, (uint64_t)st.st_size, 8);
    guest_store(buf + 24, (uint64_t)st.st_atime, 8);
    guest_store(buf + 32, (uint64_t)st.st_mtime, 8);
    guest_store(buf + 40, (uint64_t)st.st_ctime, 8);
    return 0;
}

static uint64_t guest_fstat64(int fd, uint64_t buf) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        last_error = 6; // ERROR_INVALID_HANDLE
        return UINT64_MAX;
    }
    guest_store(buf + 0, (uint32_t)st.st_dev, 4);
    guest_store(buf + 4, (uint16_t)st.st_ino, 2);
    guest_store(buf + 6, (uint16_t)st.st_mode, 2);
    guest_store(buf + 8, (uint16_t)st.st_nlink, 2);
    guest_store(buf + 10, (uint16_t)st.st_uid, 2);
    guest_store(buf + 12, (uint16_t)st.st_gid, 2);
    guest_store(buf + 14, 0, 2);
    guest_store(buf + 16, (uint64_t)st.st_size, 8);
    guest_store(buf + 24, (uint64_t)st.st_atime, 8);
    guest_store(buf + 32, (uint64_t)st.st_mtime, 8);
    guest_store(buf + 40, (uint64_t)st.st_ctime, 8);
    return 0;
}

static uint64_t guest_get_cp_info(uint32_t cp, uint64_t info_ptr) {
    (void)cp;
    if (info_ptr) {
        guest_store(info_ptr + 0, 1, 4); // MaxCharSize
    }
    return 1;
}

static uint64_t guest_get_console_mode(uint64_t handle, uint64_t mode_ptr) {
    (void)handle;
    if (mode_ptr) {
        guest_store(mode_ptr, 7, 4); // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
    }
    return 1;
}

static uint64_t guest_write_console_w(uint64_t handle, uint64_t buf, uint32_t count, uint64_t written_ptr) {
    (void)handle;
    if (!count) {
        if (written_ptr) guest_store(written_ptr, 0, 4);
        return 1;
    }
    char *utf8 = malloc(count * 4 + 1);
    if (!utf8) return 0;
    size_t out_len = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint16_t c = (uint16_t)guest_load(buf + i * 2, 2);
        if (c < 128) {
            utf8[out_len++] = (char)c;
        } else if (c < 0x800) {
            utf8[out_len++] = 0xc0 | (c >> 6);
            utf8[out_len++] = 0x80 | (c & 0x3f);
        } else {
            utf8[out_len++] = 0xe0 | (c >> 12);
            utf8[out_len++] = 0x80 | ((c >> 6) & 3);
            utf8[out_len++] = 0x80 | (c & 0x3f);
        }
    }
    utf8[out_len] = '\0';
    fwrite(utf8, 1, out_len, stdout);
    fflush(stdout);
    if (written_ptr) guest_store(written_ptr, count, 4);
    free(utf8);
    return 1;
}

static uint64_t guest_localeconv(void) {
    static uint64_t guest_lconv = 0;
    if (!guest_lconv) {
        guest_lconv = guest_heap_alloc(0x7fff2001, 8, 128);
        uint64_t dot = guest_heap_alloc(0x7fff2001, 0, 2);
        guest_store(dot, '.', 1);
        guest_store(guest_lconv, dot, 8); // decimal_point
    }
    return guest_lconv;
}

static uint64_t guest_setlocale(uint64_t category, uint64_t locale_ptr) {
    (void)category; (void)locale_ptr;
    static uint64_t c_locale = 0;
    if (!c_locale) {
        c_locale = guest_heap_alloc(0x7fff2001, 0, 2);
        guest_store(c_locale, 'C', 1);
    }
    return c_locale;
}

uint64_t guest_system_directory(uint64_t buffer, uint32_t size, uint32_t wide);

uint64_t guest_malloc(uint64_t size) {
    return guest_heap_alloc(0x7fff2001, 0, size);
}

uint64_t guest_free(uint64_t ptr) {
    if (ptr) guest_heap_free(0x7fff2001, 0, ptr);
    return 0;
}

uint64_t guest_calloc(uint64_t num, uint64_t size) {
    return guest_heap_alloc(0x7fff2001, 8, num * size);
}

uint64_t guest_realloc(uint64_t ptr, uint64_t size) {
    return guest_heap_realloc(0x7fff2001, 0, ptr, size);
}

uint64_t guest__strdup(uint64_t str, uint64_t b, uint64_t c, uint64_t d) {
    (void)b; (void)c; (void)d;
    return guest_strdup(str);
}

struct guest_thread {
    atomic_uint references;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool finished;
    uint32_t exit_code, id;
    void (*entry)(void *, uint64_t);
    uint64_t argument;
    unsigned char *stack_memory;
    size_t stack_size;
};

static void retain_guest_thread(void *opaque) {
    struct guest_thread *thread = opaque;
    atomic_fetch_add(&thread->references, 1);
}

static void release_guest_thread(void *opaque) {
    struct guest_thread *thread = opaque;
    if (atomic_fetch_sub(&thread->references, 1) == 1) {
        pthread_cond_destroy(&thread->condition);
        pthread_mutex_destroy(&thread->mutex);
        free(thread->stack_memory);
        free(thread);
    }
}

static struct guest_thread *acquire_thread_handle(uint64_t handle) {
    if (handle < 0x1000 || handle >= 0x1000 + MAX_HANDLES)
        return NULL;
    pthread_mutex_lock(&g_handle_lock);
    const struct HandleEntry *entry = &g_handles[handle - 0x1000];
    struct guest_thread *thread = entry->kind == HANDLE_KIND_THREAD ? entry->object : NULL;
    if (thread)
        retain_guest_thread(thread);
    pthread_mutex_unlock(&g_handle_lock);
    return thread;
}

static void init_guest_thread_data(void) {
    put64(teb, 0x08, STACK_BASE + STACK_SIZE);
    put64(teb, 0x10, STACK_BASE);
    if (!wine_hosted) { /* hosted: Wine filled in Self, ClientId and the PEB pointer */
        put64(teb, 0x30, TEB_BASE);
        put64(teb, 0x40, guest_identity(0));
        put64(teb, 0x48, guest_identity(1));
        put64(teb, 0x60, PEB_BASE);
    }
    put64(teb, 0x58, TLS_BASE);
    put64(tls_storage, 0, TLS_BASE + 0x200);
    if (guest_tls_end_raw > guest_tls_start_raw) {
        uint64_t size = guest_tls_end_raw - guest_tls_start_raw;
        if (size <= sizeof tls_storage - 0x200) {
            const unsigned char *src = read_span(guest_tls_start_raw, size);
            if (src)
                memcpy(tls_storage + 0x200, src, size);
        }
    }
}

static _Thread_local jmp_buf *guest_resume_boundary;
static _Thread_local uint64_t resume_cpu[128], resume_pc;
uint64_t guest_indirect_dispatch(void *, uint64_t, uint64_t, uint32_t);

static void capture_guest_context(uint64_t, uint64_t, uint64_t);

static uint64_t resume_guest(void) {
    for (;;) {
        uint64_t record = guest_heap_alloc(0x7fff2001, 8, 0x4e0);
        if (!record)
            guest_trap("cannot allocate continuation context");
        uint64_t context = record + 16;
        current_cpu = resume_cpu;
        capture_guest_context(context, resume_pc, resume_cpu[7]);
        uint64_t entry = guest_rtl_lookup_function_entry(resume_pc, record, 0);
        uint64_t return_pc = guest_load(resume_cpu[7], 8);
        if (entry) {
            guest_rtl_virtual_unwind(0, guest_load(record, 8), resume_pc,
                                     entry, context, 0, 0, 0);
            return_pc = guest_load(context + 0xf8, 8);
        }
        guest_heap_free(0x7fff2001, 0, record);
        uint64_t result = guest_indirect_dispatch(resume_cpu, resume_pc, return_pc, 1);
        if (!return_pc)
            return result;
        resume_pc = return_pc;
    }
}

static void *run_guest_thread(void *opaque) {
    struct guest_thread *thread = opaque;
    init_guest_thread_data();
    pthread_mutex_lock(&thread->mutex);
    thread->id = (uint32_t)guest_identity(1);
    pthread_cond_broadcast(&thread->condition);
    pthread_mutex_unlock(&thread->mutex);
    uint64_t cpu[128] = {0};
    init_guest_cpu(cpu);
    cpu[1] = thread->argument;
    uint64_t stack_base = (uint64_t)(uintptr_t)thread->stack_memory;
    uint64_t stack_top = stack_base + thread->stack_size;
    put64(teb, 0x08, stack_top);
    put64(teb, 0x10, stack_base);
    cpu[7] = stack_top - 40;
    current_cpu = cpu;
    guest_store(cpu[7], 0, 8);
    jmp_buf boundary;
    guest_resume_boundary = &boundary;
    uint32_t status;
    if (!setjmp(boundary)) {
        if (guest_fault_signals_enabled())
            init_guest_signal_handler();
        thread->entry(cpu, 0);
        status = (uint32_t)cpu[0];
    } else {
        status = (uint32_t)resume_guest();
    }
    pthread_mutex_lock(&thread->mutex);
    thread->exit_code = status;
    thread->finished = true;
    pthread_cond_broadcast(&thread->condition);
    pthread_mutex_unlock(&thread->mutex);
    release_guest_thread(thread);
    return NULL;
}

static uint64_t wait_guest_thread(uint64_t, uint32_t);

uint64_t guest_GetFinalPathNameByHandleW(uint64_t handle, uint64_t buf, uint32_t cch, uint32_t flags) {
    return subsys_GetFinalPathNameByHandleW(handle, buf, cch, flags);
}

uint64_t guest_WaitOnAddress(uint64_t address, uint64_t compare_address, uint64_t size, uint32_t ms) {
    return subsys_WaitOnAddress(address, compare_address, size, ms);
}

uint64_t guest_WakeByAddressSingle(uint64_t address) {
    subsys_WakeByAddressSingle(address);
    return 0;
}

uint64_t guest_WakeByAddressAll(uint64_t address) {
    subsys_WakeByAddressAll(address);
    return 0;
}

uint64_t guest_CreateWaitableTimerExW(uint64_t attrs, uint64_t name, uint32_t flags, uint32_t access) {
    return subsys_CreateWaitableTimerExW(attrs, name, flags, access);
}

uint64_t guest_CreateWaitableTimerW(uint64_t attrs, uint64_t name, uint32_t manual) {
    return subsys_CreateWaitableTimerW(attrs, name, manual);
}

uint64_t guest_SetWaitableTimer(uint64_t timer, uint64_t due_time, uint32_t period, uint64_t routine) {
    return subsys_SetWaitableTimer(timer, due_time, period, routine);
}

uint64_t guest_create_thread(uint64_t attributes, uint64_t size, uint64_t start,
                             uint64_t argument, uint32_t flags, uint64_t id_address) {
    (void)attributes;
    if (flags & ~0x10004u) {
        last_error = 87;
        return 0;
    }
    void (*entry)(void *, uint64_t) = guest_lookup_dispatch(start);
    if (!entry) {
        last_error = 87;
        return 0;
    }
    struct guest_thread *thread = calloc(1, sizeof *thread);
    if (!thread) {
        last_error = 8;
        return 0;
    }
    if (pthread_mutex_init(&thread->mutex, NULL)) {
        free(thread);
        last_error = 8;
        return 0;
    }
    if (pthread_cond_init(&thread->condition, NULL)) {
        pthread_mutex_destroy(&thread->mutex);
        free(thread);
        last_error = 8;
        return 0;
    }
    atomic_init(&thread->references, 1);
    if (size > SIZE_MAX - 4095) {
        release_guest_thread(thread);
        last_error = 8;
        return 0;
    }
    thread->stack_size = size > STACK_SIZE ? (size + 4095) & ~(size_t)4095 : STACK_SIZE;
    thread->stack_memory = calloc(1, thread->stack_size);
    if (!thread->stack_memory) {
        release_guest_thread(thread);
        last_error = 8;
        return 0;
    }
    thread->entry = entry;
    thread->argument = argument;
    uint64_t handle = alloc_handle(HANDLE_KIND_THREAD);
    if (!handle) {
        release_guest_thread(thread);
        last_error = 8;
        return 0;
    }
    struct HandleEntry *entry_handle = get_handle(handle);
    entry_handle->object = thread;
    entry_handle->release_object = release_guest_thread;
    entry_handle->wait_object = wait_guest_thread;
    retain_guest_thread(thread);
    pthread_t host;
    if (pthread_create(&host, NULL, run_guest_thread, thread)) {
        release_guest_thread(thread);
        guest_close_handle(handle);
        last_error = 8;
        return 0;
    }
    pthread_detach(host);
    if (id_address) {
        pthread_mutex_lock(&thread->mutex);
        while (!thread->id)
            pthread_cond_wait(&thread->condition, &thread->mutex);
        uint32_t id = thread->id;
        pthread_mutex_unlock(&thread->mutex);
        guest_store(id_address, id, 4);
    }
    return handle;
}

static uint64_t wait_guest_thread(uint64_t handle, uint32_t timeout) {
    struct guest_thread *thread = acquire_thread_handle(handle);
    if (!thread) {
        last_error = 6;
        return UINT32_MAX;
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout / 1000;
    deadline.tv_nsec += (timeout % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&thread->mutex);
    int result = 0;
    while (!thread->finished && !result)
        result = timeout == UINT32_MAX ?
            pthread_cond_wait(&thread->condition, &thread->mutex) :
            pthread_cond_timedwait(&thread->condition, &thread->mutex, &deadline);
    bool finished = thread->finished;
    pthread_mutex_unlock(&thread->mutex);
    release_guest_thread(thread);
    if (!finished && result && result != ETIMEDOUT) {
        last_error = 6;
        return UINT32_MAX;
    }
    return finished ? 0 : 0x102;
}

static uint64_t guest_get_exit_code_thread(uint64_t handle, uint64_t output) {
    if (!output) {
        last_error = 87;
        return 0;
    }
    struct guest_thread *thread = acquire_thread_handle(handle);
    if (!thread) {
        last_error = 6;
        return 0;
    }
    pthread_mutex_lock(&thread->mutex);
    uint32_t code = thread->finished ? thread->exit_code : 259;
    pthread_mutex_unlock(&thread->mutex);
    release_guest_thread(thread);
    guest_store(output, code, 4);
    return 1;
}

/* Read-only registry values supplied by the console Windows environment. */
static uint64_t open_registry_key(uint64_t root, uint64_t subkey, uint32_t access, uint64_t output) {
    char name[129] = "";
    if (!output)
        return 87;
    if (subkey)
        module_string(name, sizeof name, subkey, 2);
    if ((uint32_t)root != 0x80000002 || strcasecmp(name, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"))
        return 2;
    if (access & ~0x20319u)
        return 5;
    guest_store(output, 0x7fff4100, 8);
    return 0;
}

static uint64_t query_registry_value(uint64_t key, uint64_t name_address,
                                     uint64_t type, uint64_t output, uint64_t size_slot) {
    if (key != 0x7fff4100)
        return 6;
    if (!name_address || !size_slot)
        return 87;
    char name[129];
    module_string(name, sizeof name, name_address, 2);
    const char *value = NULL;
    if (!strcasecmp(name, "SystemRoot"))
        value = "C:\\Windows";
    else if (!strcasecmp(name, "CurrentVersion"))
        value = "10.0";
    if (!value)
        return 2;
    uint32_t capacity = output ? (uint32_t)guest_load(size_slot, 4) : 0;
    uint32_t bytes = (uint32_t)(strlen(value) + 1) * 2;
    guest_store(size_slot, bytes, 4);
    if (type)
        guest_store(type, 1, 4);
    if (!output)
        return 0;
    if (capacity < bytes)
        return 234;
    for (uint32_t i = 0; i < bytes / 2; ++i)
        guest_store(output + i * 2, (unsigned char)value[i], 2);
    return 0;
}

static _Thread_local unsigned winsock_error;
static atomic_uint winsock_startups;

static uint64_t winsock_startup(uint32_t version, uint64_t output) {
    if (!output)
        return 10014;
    if ((version & 0xffff) != 0x202)
        return 10092;
    unsigned char *data = guest_writable_span(output, 408);
    if (!data)
        return 10014;
    memset(data, 0, 408);
    guest_store(output, 0x02020202, 4);
    atomic_fetch_add(&winsock_startups, 1);
    return 0;
}

static uint64_t winsock_failure(int error) {
    switch (error) {
    case EINVAL: winsock_error = 10022; break;
    case EBADF: case ENOTSOCK: winsock_error = 10038; break;
    case EWOULDBLOCK: winsock_error = 10035; break;
    case EADDRINUSE: winsock_error = 10048; break;
    case EADDRNOTAVAIL: winsock_error = 10049; break;
    case ECONNREFUSED: winsock_error = 10061; break;
    case ECONNRESET: winsock_error = 10054; break;
    case EPIPE: winsock_error = 10058; break;
    case ETIMEDOUT: winsock_error = 10060; break;
    case EAFNOSUPPORT: winsock_error = 10047; break;
    case EPROTONOSUPPORT: winsock_error = 10043; break;
    case EMFILE: case ENFILE: winsock_error = 10024; break;
    default: winsock_error = 10050; break;
    }
    return UINT64_MAX;
}

static uint64_t winsock_track_socket(int fd) {
    if (fd < 0)
        return winsock_failure(errno);
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof enabled);
    uint64_t handle = alloc_handle(HANDLE_KIND_SOCKET);
    if (!handle) {
        close(fd);
        return winsock_failure(EMFILE);
    }
    get_handle(handle)->fd = fd;
    return handle;
}

static uint64_t winsock_call(const char *name, uint64_t first, uint64_t second,
                             uint64_t third, uint64_t fourth) {
    if (!strcmp(name, "WSAStartup"))
        return winsock_startup((uint32_t)first, second);
    if (!strcmp(name, "WSAGetLastError"))
        return winsock_error;
    if (!strcmp(name, "WSASetLastError")) {
        winsock_error = (uint32_t)first;
        return 0;
    }
    if (!atomic_load(&winsock_startups)) {
        winsock_error = 10093;
        return UINT64_MAX;
    }
    if (!strcmp(name, "WSACleanup")) {
        unsigned count = atomic_load(&winsock_startups);
        while (count && !atomic_compare_exchange_weak(&winsock_startups, &count, count - 1)) {}
        if (!count) {
            winsock_error = 10093;
            return UINT64_MAX;
        }
        return 0;
    }
    if (!strcmp(name, "socket")) {
        if (first != 2)
            return winsock_failure(EAFNOSUPPORT);
        if (second != SOCK_STREAM && second != SOCK_DGRAM)
            return winsock_failure(EPROTONOSUPPORT);
        return winsock_track_socket(socket(AF_INET, (int)second, (int)third));
    }
    struct HandleEntry *entry = get_handle(first);
    if (!entry || entry->kind != HANDLE_KIND_SOCKET)
        return winsock_failure(ENOTSOCK);
    int fd = entry->fd;
    if (!strcmp(name, "closesocket"))
        return guest_close_handle(first) ? 0 : winsock_failure(ENOTSOCK);
    if (!strcmp(name, "listen"))
        return listen(fd, (int)second) < 0 ? winsock_failure(errno) : 0;
    if (!strcmp(name, "shutdown"))
        return shutdown(fd, (int)second) < 0 ? winsock_failure(errno) : 0;
    if (!strcmp(name, "bind") || !strcmp(name, "connect")) {
        if (!second || third < 16)
            return winsock_failure(EINVAL);
        if (guest_load(second, 2) != 2)
            return winsock_failure(EAFNOSUPPORT);
        struct sockaddr_in address = {.sin_len = sizeof address, .sin_family = AF_INET};
        address.sin_port = (uint16_t)guest_load(second + 2, 2);
        address.sin_addr.s_addr = (uint32_t)guest_load(second + 4, 4);
        const struct sockaddr *addr = (const struct sockaddr *)&address;
        int result = name[0] == 'b' ? bind(fd, addr, sizeof address) : connect(fd, addr, sizeof address);
        return result < 0 ? winsock_failure(errno) : 0;
    }
    if (!strcmp(name, "getsockname") || !strcmp(name, "accept")) {
        bool accepting = name[0] == 'a';
        if (accepting && !second)
            return winsock_track_socket(accept(fd, NULL, NULL));
        if (!second || !third || guest_load(third, 4) < 16)
            return winsock_failure(EINVAL);
        struct sockaddr_in address = {0};
        socklen_t size = sizeof address;
        struct sockaddr *addr = (struct sockaddr *)&address;
        int result = accepting ? accept(fd, addr, &size) : getsockname(fd, addr, &size);
        if (result < 0)
            return winsock_failure(errno);
        guest_store(second, 2, 2);
        guest_store(second + 2, address.sin_port, 2);
        guest_store(second + 4, address.sin_addr.s_addr, 4);
        guest_store(second + 8, 0, 8);
        guest_store(third, 16, 4);
        return accepting ? winsock_track_socket(result) : 0;
    }
    if ((int32_t)third < 0 || fourth || (!second && third))
        return winsock_failure(EINVAL);
    bool sending = !strcmp(name, "send");
    const void *buffer = third ? (sending ? read_span(second, (uint32_t)third) :
                                    guest_writable_span(second, (uint32_t)third)) : NULL;
    if (!buffer && third) {
        winsock_error = 10014;
        return UINT64_MAX;
    }
    ssize_t result = sending ? send(fd, buffer, (uint32_t)third, 0) :
                               recv(fd, (void *)buffer, (uint32_t)third, 0);
    return result < 0 ? winsock_failure(errno) : (uint64_t)result;
}

static uint64_t call_service(size_t index, uint64_t first, uint64_t second,
                             uint64_t third, uint64_t fourth) {
    const char *name = service_exports[index].name;
    if (service_exports[index].module == WINSOCK_MODULE)
        return winsock_call(name, first, second, third, fourth);
    if (strcmp(name, "RegOpenKeyExW") == 0 && current_cpu) {
        uint64_t args = ((uint64_t *)current_cpu)[7] + 40;
        return third ? 87 : open_registry_key(first, second, (uint32_t)fourth, guest_load(args, 8));
    }
    if (strcmp(name, "RegQueryValueExW") == 0 && current_cpu) {
        uint64_t args = ((uint64_t *)current_cpu)[7] + 40;
        return third ? 87 : query_registry_value(first, second, fourth,
                                                  guest_load(args, 8), guest_load(args + 8, 8));
    }
    if (strcmp(name, "RegCloseKey") == 0)
        return first == 0x7fff4100 ? 0 : 6;
    if (strcmp(name, "BCryptGenRandom") == 0) {
        if (first || fourth != 2)
            return 0xc000000d;
        unsigned char *buffer = guest_writable_span(second, (uint32_t)third);
        if (!buffer && (uint32_t)third)
            return 0xc000000d;
        if ((uint32_t)third)
            arc4random_buf(buffer, (uint32_t)third);
        return 0;
    }
    return 87;
}

/*
 * kernel32 (or other system) functions the runtime does not implement fall
 * back to the lifted kernelbase.dll when the program ships one: the export
 * runs as lifted Wine code in the caller's own guest frame, so register and
 * stack arguments are exactly as the caller placed them.
 */
/*
 * Set by guest_indirect_call_inline (lifted inline import calls, where no
 * return address is pushed) and consumed at the top of guest_indirect_call.
 */
static _Thread_local bool inline_import_call;

static bool kernelbase_fallback(const char *name, bool inline_frame, uint64_t *result) {
    static _Thread_local unsigned depth;
    uint64_t *cpu = (uint64_t *)current_cpu;
    if (!cpu || depth > 8 || !is_lifted_system_dll("kernelbase.dll"))
        return false;
    pthread_mutex_lock(&module_translation_lock);
    struct guest_module *module = loaded_module_named("kernelbase.dll");
    if (!module) {
        uint64_t handle = load_application_module("kernelbase.dll");
        module = handle ? find_guest_module(handle) : NULL;
    }
    uint64_t target = module ? module_export(module, name, 0) : 0;
    pthread_mutex_unlock(&module_translation_lock);
    /* Forwarders back into runtime system code would loop. */
    if (!target || system_thunk_name(target))
        return false;
    void (*fn)(void *, uint64_t) = guest_lookup_dispatch(target);
    if (!fn)
        return false;
    static int trace = -1;
    if (trace < 0)
        trace = getenv("ARM64_RECOMPILER_TRACE_IMPORTS") != NULL;
    if (trace)
        fprintf(stderr, "[fallback] %s -> kernelbase.dll %#llx\n", name, (unsigned long long)target);
    uint64_t saved[128];
    memcpy(saved, cpu, sizeof saved);
    /* The callee expects [rsp] = return address, stack arguments at rsp+40. An
       inline caller has not pushed one, so push a slot below its frame. */
    if (inline_frame)
        cpu[7] -= 8;
    uint64_t rsp = cpu[7], return_address = guest_load(rsp, 8);
    guest_store(rsp, 0, 8); /* the callee returns to return_va 0 */
    ++depth;
    fn(cpu, 0);
    --depth;
    *result = cpu[0];
    if (trace)
        fprintf(stderr, "[fallback] %s = %#llx\n", name, (unsigned long long)*result);
    memcpy(cpu, saved, sizeof saved);
    guest_store(rsp, return_address, 8);
    current_cpu = cpu;
    return true;
}

uint64_t guest_indirect_call(uint64_t target, uint64_t first, uint64_t second,
                             uint64_t third, uint64_t fourth);

uint64_t guest_indirect_call_inline(uint64_t target, uint64_t first, uint64_t second,
                                    uint64_t third, uint64_t fourth) {
    inline_import_call = true;
    return guest_indirect_call(target, first, second, third, fourth);
}

uint64_t guest_indirect_call(uint64_t target, uint64_t first, uint64_t second,
                             uint64_t third, uint64_t fourth) {
    bool inline_frame = inline_import_call;
    inline_import_call = false;
    if (target >= SERVICE_TARGET && target - SERVICE_TARGET < sizeof service_exports / sizeof *service_exports)
        return call_service(target - SERVICE_TARGET, first, second, third, fourth);
    (void)fourth;
    if (target == 0x7fff1030)
        return 2; // The guest registry has no configured keys.
    if (target == 0x7fff3001 || target == 0x7fff3002 || target == 0x7fff3003)
        return 0;
    if (target == 0x7fff1020 || target == 0x7fff1021)
        return guest_system_directory(first, (uint32_t)second, target == 0x7fff1021);
    if (target == DEFAULT_DLL_DIRS) {
        if ((uint32_t)first == 0x800)
            return 1; // The modeled resolver only exposes built-in system modules.
        last_error = 87;
        return 0;
    }
    if (target == FILE_APIS_ANSI)
        return 1;
    if (target == TLS_ALLOC || (target >= FLS_ALLOC && target <= FLS_FREE)) {
        static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
        static struct { bool allocated; uint64_t callback, generation; } slots[128];
        static _Thread_local struct { uint64_t value, generation; } local[128];
        pthread_mutex_lock(&lock);
        if (target == FLS_ALLOC || target == TLS_ALLOC) {
            for (unsigned i = 0; i < sizeof slots / sizeof *slots; ++i)
                if (!slots[i].allocated) {
                    slots[i].allocated = true;
                    slots[i].callback = target == FLS_ALLOC ? first : 0;
                    ++slots[i].generation;
                    pthread_mutex_unlock(&lock);
                    return i;
                }
            pthread_mutex_unlock(&lock);
            last_error = 8;
            return UINT32_MAX;
        }
        uint32_t index = (uint32_t)first;
        if (index >= sizeof slots / sizeof *slots || !slots[index].allocated) {
            pthread_mutex_unlock(&lock);
            last_error = 87;
            return 0;
        }
        if (local[index].generation != slots[index].generation) {
            local[index].generation = slots[index].generation;
            local[index].value = 0;
        }
        if (target == FLS_GET) {
            pthread_mutex_unlock(&lock);
            last_error = 0;
            return local[index].value;
        }
        if (target == FLS_SET) {
            local[index].value = second;
            pthread_mutex_unlock(&lock);
            return 1;
        }
        if (slots[index].callback && local[index].value) {
            fprintf(stderr, "RVA %#llx: FlsFree needs guest callback %#llx\n",
                    (unsigned long long)guest_pc, (unsigned long long)slots[index].callback);
            exit(125);
        }
        slots[index].allocated = false;
        pthread_mutex_unlock(&lock);
        return 1;
    }
    if (target == INIT_CRITICAL) {
        if (third != 0 && third != 0x01000000)
            guest_trap("unsupported InitializeCriticalSectionEx flags");
        guest_init_critical(first, (uint32_t)second);
        return 1;
    }
    if (target == VIRTUAL_PROTECT) {
        return guest_virtual_protect(first, second, (uint32_t)third, fourth);
    }
    if (target == GET_HANDLE_INFO) {
        return guest_get_handle_info(first, second);
    }
    if (target == GET_TICK_COUNT_64) return guest_tick_count_64();
    if (target == GET_TICK_COUNT) return guest_tick_count();
    if (target == QUERY_PERF_COUNTER) return guest_performance_counter(first);
    if (target == QUERY_PERF_FREQ) return guest_performance_frequency(first);
    if (target == GET_SYSTEM_FILETIME) { guest_system_filetime(first); return 0; }
    if (target == GET_CURRENT_PROCESS_ID) return guest_identity(0);
    if (target == GET_CURRENT_THREAD_ID) return guest_identity(1);
    if (target == IS_PROCESSOR_FEATURE_PRESENT) return guest_is_processor_feature_present((uint32_t)first);
    if (target == SET_UNHANDLED_EXCEPTION_FILTER) return guest_exception_filter(first);
    if (target == UNHANDLED_EXCEPTION_FILTER) return guest_unhandled_exception_filter(first);
    if (target == TERMINATE_PROCESS) return guest_terminate_process(first, (uint32_t)second);
    if (target == RTL_CAPTURE_CONTEXT) { guest_rtl_capture_context(first); return 0; }
    if (target == RTL_LOOKUP_FUNCTION_ENTRY) return guest_rtl_lookup_function_entry(first, second, third);
    if (target == RTL_VIRTUAL_UNWIND) {
        if (!current_cpu)
            return 0;
        uint64_t args = ((uint64_t *)current_cpu)[7] + 40;
        return guest_rtl_virtual_unwind((uint32_t)first, second, third, fourth,
                                        guest_load(args, 8), guest_load(args + 8, 8),
                                        guest_load(args + 16, 8), guest_load(args + 24, 8));
    }
    if (target == IS_DEBUGGER_PRESENT || target == 0x7fff3002) return 0;
    if (target == 0x7fff3001) {
        return (uint64_t)guest_add_vectored_exception_handler((uint32_t)first, second);
    }
    const char *system_name = system_thunk_name(target);
    /* An import-by-name entry in the primary image (as a VA or a bare RVA) or in a module. */
    if (target < 0x20000000 || system_name || module_span(target, 2, false) ||
        (guest_image_base && target >= guest_image_base && target - guest_image_base < guest_image_span)) {
        char name[128] = {0};
        bool valid = true;
        if (system_name)
            snprintf(name, sizeof name, "%s", system_name);
        for (size_t i = 0; !system_name && i < sizeof(name) - 1; ++i) {
            uint8_t c = (uint8_t)guest_load(target + 2 + i, 1);
            if (!c) { name[i] = 0; break; }
            if (c < 32 || c >= 127) { valid = false; break; }
            name[i] = (char)c;
        }
        if (valid && name[0]) {
            count_named_dispatch(name);
            static int trace_imports = -1;
            if (trace_imports < 0)
                trace_imports = getenv("ARM64_RECOMPILER_TRACE_IMPORTS") != NULL;
            if (trace_imports)
                fprintf(stderr, "[import] %s(%#llx, %#llx, %#llx, %#llx)\n", name,
                        (unsigned long long)first, (unsigned long long)second,
                        (unsigned long long)third, (unsigned long long)fourth);
            uint64_t shim_res = 0;
            if (strcmp(name, "CreateFileW") == 0 || strcmp(name, "CreateFileA") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t stack = regs ? regs[7] + 40 : 0;
                uint32_t creation = stack ? (uint32_t)guest_load(stack, 4) : 3;
                uint32_t flags = stack ? (uint32_t)guest_load(stack + 8, 4) : 0;
                uint64_t template_file = stack ? guest_load(stack + 16, 8) : 0;
                return (name[10] == 'W' ? subsys_CreateFileW : subsys_CreateFileA)(
                    first, (uint32_t)second, (uint32_t)third, fourth, creation, flags, template_file);
            }
            if (wine_hosted && !strcmp(name, "__wine_unix_call_dispatcher"))
                return wine_host_unix_call(first, (uint32_t)second, third);
            if (guest_dispatch_generated_shim(name, &shim_res, first, second, third, fourth))
                return shim_res;
            if (strcmp(name, "GetModuleHandleA") == 0)
                return guest_module_handle(first, 0);
            if (strcmp(name, "GetModuleHandleW") == 0)
                return guest_module_handle(first, 1);
            if (strcmp(name, "LoadLibraryW") == 0)
                return guest_load_library(first, 0, 0);
            if (strcmp(name, "GetProcAddress") == 0)
                return guest_get_proc(first, second);
            if (strcmp(name, "GetProcessHeap") == 0) return 0x7fff2001;
            if (strcmp(name, "HeapCreate") == 0) {
                uint64_t handle = atomic_fetch_add(&guest_heap_next, 1);
                if (guest_heap_handle(handle))
                    return handle;
                last_error = 8;
                return 0;
            }
            if (strcmp(name, "HeapDestroy") == 0) return guest_heap_handle(first) && first != GUEST_HEAP_HANDLE;
            if (strcmp(name, "HeapSize") == 0) {
                if (!guest_heap_handle(first) || !guest_heap_block(third))
                    return (uint64_t)-1;
                return malloc_size((void *)(uintptr_t)third);
            }
            if (strcmp(name, "HeapValidate") == 0 || strcmp(name, "HeapLock") == 0 ||
                strcmp(name, "HeapUnlock") == 0 || strcmp(name, "HeapSetInformation") == 0)
                return guest_heap_handle(first) || strcmp(name, "HeapSetInformation") == 0;
            if (strcmp(name, "HeapCompact") == 0) return 0;
            if (strcmp(name, "HeapAlloc") == 0) return guest_heap_alloc(first, (uint32_t)second, third);
            if (strcmp(name, "HeapFree") == 0) return guest_heap_free(first, (uint32_t)second, third);
            if (strcmp(name, "HeapReAlloc") == 0) return guest_heap_realloc(first, (uint32_t)second, third, fourth);
            if (strcmp(name, "EnterCriticalSection") == 0 ||
                strcmp(name, "LeaveCriticalSection") == 0 ||
                strcmp(name, "DeleteCriticalSection") == 0) {
                unsigned operation = name[0] == 'D' ? 2 : name[0] == 'E';
                guest_critical_section(first, operation);
                return 0;
            }
            if (strcmp(name, "GetStdHandle") == 0)
                return guest_stdout((uint32_t)first);
            if (strcmp(name, "WriteFile") == 0)
                return guest_write(first, second, (uint32_t)third, fourth, 0);
            if (strcmp(name, "GetLastError") == 0)
                return guest_get_last_error();
            if (strcmp(name, "SetLastError") == 0) {
                guest_set_last_error((uint32_t)first);
                return 0;
            }
            if (strcmp(name, "ExitProcess") == 0)
                guest_exit((uint32_t)first);
            if (strcmp(name, "VirtualProtect") == 0)
                return guest_virtual_protect(first, second, (uint32_t)third, fourth);
            if (strcmp(name, "GetHandleInformation") == 0)
                return guest_get_handle_info(first, second);
            if (strcmp(name, "GetTickCount64") == 0) return guest_tick_count_64();
            if (strcmp(name, "GetTickCount") == 0) return guest_tick_count();
            if (strcmp(name, "QueryPerformanceFrequency") == 0) return guest_performance_frequency(first);
            if (strcmp(name, "GetCurrentProcessId") == 0) return guest_identity(0);
            if (strcmp(name, "GetCurrentThreadId") == 0) return guest_identity(1);
            if (strcmp(name, "GetCurrentProcess") == 0) return (uint64_t)-1;
            if (strcmp(name, "GetCurrentThread") == 0) return (uint64_t)-2;
            if (strcmp(name, "TlsAlloc") == 0) return guest_indirect_call(TLS_ALLOC, 0, 0, 0, 0);
            if (strcmp(name, "TlsGetValue") == 0) return guest_indirect_call(FLS_GET, first, second, third, fourth);
            if (strcmp(name, "TlsSetValue") == 0) return guest_indirect_call(FLS_SET, first, second, third, fourth);
            if (strcmp(name, "TlsFree") == 0) return guest_indirect_call(FLS_FREE, first, second, third, fourth);
            if (strcmp(name, "GetProcessAffinityMask") == 0) {
                if (second) guest_store(second, 1, 8);
                if (third) guest_store(third, 1, 8);
                return 1;
            }
            if (strcmp(name, "GetThreadPriority") == 0) return 0;
            if (strcmp(name, "SetThreadPriority") == 0) return 1;
            if (strcmp(name, "TryEnterCriticalSection") == 0) {
                return guest_try_critical_section(first);
            }
            if (strcmp(name, "RaiseException") == 0) {
                if (!current_cpu)
                    guest_trap("RaiseException requires a guest context");
                uint64_t rsp = ((uint64_t *)current_cpu)[7];
                guest_raise_exception((uint32_t)first, (uint32_t)second, (uint32_t)third,
                                      fourth, guest_load(rsp, 8), rsp + 8);
                return 0;
            }
            for (size_t i = 0; i < sizeof service_exports / sizeof *service_exports; ++i)
                if (!strcmp(name, service_exports[i].name))
                    return call_service(i, first, second, third, fourth);
            if (strcmp(name, "IsProcessorFeaturePresent") == 0) return guest_is_processor_feature_present((uint32_t)first);
            if (strcmp(name, "SetUnhandledExceptionFilter") == 0) return guest_exception_filter(first);
            if (strcmp(name, "UnhandledExceptionFilter") == 0) return guest_unhandled_exception_filter(first);
            if (strcmp(name, "TerminateProcess") == 0) return guest_terminate_process(first, (uint32_t)second);
            if (strcmp(name, "RtlCaptureContext") == 0) { guest_rtl_capture_context(first); return 0; }
            if (strcmp(name, "RtlPcToFileHeader") == 0) {
                uint64_t base = 0;
                for (uint64_t i = 0; i < guest_section_count; ++i) {
                    const struct section *section = &guest_sections[i];
                    if (fits(first, 1, guest_image_base + section->address, section->size) ||
                        fits(first, 1, section->address, section->size)) {
                        base = guest_image_base;
                        break;
                    }
                }
                if (second)
                    guest_store(second, base, 8);
                return base;
            }
            if (strcmp(name, "RtlLookupFunctionEntry") == 0) return guest_rtl_lookup_function_entry(first, second, third);
            if (strcmp(name, "RtlVirtualUnwind") == 0)
                return guest_indirect_call(RTL_VIRTUAL_UNWIND, first, second, third, fourth);
            if (strcmp(name, "IsDebuggerPresent") == 0) return 0;
            if (strcmp(name, "InitializeSListHead") == 0) return 0;
            if (strcmp(name, "QueryPerformanceCounter") == 0)
                return guest_performance_counter(first);
            if (strcmp(name, "GetSystemTimeAsFileTime") == 0 ||
                strcmp(name, "GetSystemTimePreciseAsFileTime") == 0) {
                guest_system_filetime(first);
                return 0;
            }
            if (strcmp(name, "InitializeCriticalSection") == 0 ||
                strcmp(name, "InitializeCriticalSectionAndSpinCount") == 0 ||
                strcmp(name, "InitializeCriticalSectionEx") == 0) {
                guest_init_critical(first, (uint32_t)second);
                return 1;
            }

            /* Core Subsystems: File I/O & Handles */
            if (strcmp(name, "CreateFileW") == 0) return subsys_CreateFileW(first, (uint32_t)second, (uint32_t)third, fourth, 3, 0, 0);
            if (strcmp(name, "CreateFileA") == 0) return subsys_CreateFileA(first, (uint32_t)second, (uint32_t)third, fourth, 3, 0, 0);
            if (strcmp(name, "ReadFile") == 0) return subsys_ReadFile(first, second, (uint32_t)third, fourth, 0);
            if (strcmp(name, "CloseHandle") == 0) return guest_close_handle(first);
            if (strcmp(name, "SetFilePointer") == 0) return subsys_SetFilePointer(first, (int32_t)second, third, (uint32_t)fourth);
            if (strcmp(name, "SetFilePointerEx") == 0) return subsys_SetFilePointerEx(first, (int64_t)second, third, (uint32_t)fourth);
            if (strcmp(name, "GetFileInformationByHandle") == 0) return subsys_GetFileInformationByHandle(first, second);
            if (strcmp(name, "GetFileSize") == 0) return subsys_GetFileSize(first, second);
            if (strcmp(name, "GetFileSizeEx") == 0) return subsys_GetFileSizeEx(first, second);
            if (strcmp(name, "FlushFileBuffers") == 0) return subsys_FlushFileBuffers(first);
            if (strcmp(name, "DuplicateHandle") == 0) return subsys_DuplicateHandle(first, second, third, fourth, 0, 0, 0);

            /* Core Subsystems: Filesystem & Traversal */
            if (strcmp(name, "GetFileAttributesW") == 0) return subsys_GetFileAttributesW(first);
            if (strcmp(name, "GetFileAttributesA") == 0) return subsys_GetFileAttributesA(first);
            if (strcmp(name, "DeleteFileW") == 0) return subsys_DeleteFileW(first);
            if (strcmp(name, "DeleteFileA") == 0) return subsys_DeleteFileA(first);
            if (strcmp(name, "CreateDirectoryW") == 0) return subsys_CreateDirectoryW(first, second);
            if (strcmp(name, "CreateDirectoryA") == 0) return subsys_CreateDirectoryA(first, second);
            if (strcmp(name, "RemoveDirectoryW") == 0) return subsys_RemoveDirectoryW(first);
            if (strcmp(name, "RemoveDirectoryA") == 0) return subsys_RemoveDirectoryA(first);
            if (strcmp(name, "GetFullPathNameW") == 0) return subsys_GetFullPathNameW(first, (uint32_t)second, third, fourth);
            if (strcmp(name, "GetCurrentDirectoryW") == 0) return subsys_GetCurrentDirectoryW((uint32_t)first, second);
            if (strcmp(name, "GetCurrentDirectoryA") == 0) return subsys_GetCurrentDirectoryA((uint32_t)first, second);
            if (strcmp(name, "SetCurrentDirectoryW") == 0) return subsys_SetCurrentDirectoryW(first);
            if (strcmp(name, "SetCurrentDirectoryA") == 0) return subsys_SetCurrentDirectoryA(first);
            if (strcmp(name, "GetTempPathW") == 0) return subsys_GetTempPathW((uint32_t)first, second);
            if (strcmp(name, "GetTempPathA") == 0) return subsys_GetTempPathA((uint32_t)first, second);
            if (strcmp(name, "FindFirstFileW") == 0) return subsys_FindFirstFileW(first, second);
            if (strcmp(name, "FindFirstFileExW") == 0) {
                if (second > 1 || fourth != 0) {
                    last_error = 87;
                    return UINT64_MAX;
                }
                return subsys_FindFirstFileW(first, third);
            }
            if (strcmp(name, "FindNextFileW") == 0) return subsys_FindNextFileW(first, second);
            if (strcmp(name, "FindClose") == 0) return subsys_FindClose(first);

            /* Core Subsystems: Virtual Memory */
            if (strcmp(name, "VirtualAlloc") == 0) return subsys_VirtualAlloc(first, second, (uint32_t)third, (uint32_t)fourth);
            if (strcmp(name, "VirtualFree") == 0) return subsys_VirtualFree(first, second, (uint32_t)third);
            if (strcmp(name, "VirtualAllocEx") == 0) return subsys_VirtualAlloc(second, third, (uint32_t)fourth, 0x04);
            if (strcmp(name, "VirtualFreeEx") == 0) return subsys_VirtualFree(second, third, (uint32_t)fourth);
            if (strcmp(name, "CreateFileMappingW") == 0 || strcmp(name, "CreateFileMappingA") == 0) return subsys_CreateFileMappingW(first, second, (uint32_t)third, 0, 0, fourth);
            if (strcmp(name, "MapViewOfFile") == 0) return subsys_MapViewOfFile(first, (uint32_t)second, 0, (uint32_t)third, fourth);
            if (strcmp(name, "MapViewOfFileEx") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t base_hint = (regs && regs[7]) ? guest_load(regs[7] + 32, 8) : 0;
                return subsys_MapViewOfFileEx(first, (uint32_t)second, 0, (uint32_t)third, fourth, base_hint);
            }
            if (strcmp(name, "UnmapViewOfFile") == 0) return subsys_UnmapViewOfFile(first);

            /* Core Subsystems: Synchronization */
            if (strcmp(name, "CreateEventW") == 0) return subsys_CreateEventW(first, (uint32_t)second, (uint32_t)third, fourth);
            if (strcmp(name, "CreateEventA") == 0) return subsys_CreateEventA(first, (uint32_t)second, (uint32_t)third, fourth);
            if (strcmp(name, "CreateSemaphoreA") == 0 || strcmp(name, "CreateSemaphoreW") == 0) {
                uint64_t h = alloc_handle(HANDLE_KIND_EVENT);
                struct HandleEntry *e = get_handle(h);
                if (e) {
                    e->manual_reset = false;
                    e->signaled = ((int32_t)second > 0);
                }
                return h;
            }
            if (strcmp(name, "ReleaseSemaphore") == 0) {
                if (third) guest_store(third, 0, 4);
                return subsys_SetEvent(first);
            }
            if (strcmp(name, "SetEvent") == 0) return subsys_SetEvent(first);
            if (strcmp(name, "ResetEvent") == 0) return subsys_ResetEvent(first);
            if (strcmp(name, "GetExitCodeThread") == 0) return guest_get_exit_code_thread(first, second);
            if (strcmp(name, "WaitForSingleObject") == 0) return subsys_WaitForSingleObject(first, (uint32_t)second);
            if (strcmp(name, "WaitForMultipleObjects") == 0) return subsys_WaitForMultipleObjects((uint32_t)first, second, (uint32_t)third, (uint32_t)fourth);
            if (strcmp(name, "InitializeSRWLock") == 0) return subsys_InitializeSRWLock(first);
            if (strcmp(name, "AcquireSRWLockExclusive") == 0) return subsys_AcquireSRWLockExclusive(first);
            if (strcmp(name, "ReleaseSRWLockExclusive") == 0) return subsys_ReleaseSRWLockExclusive(first);
            if (strcmp(name, "AcquireSRWLockShared") == 0) return subsys_AcquireSRWLockShared(first);
            if (strcmp(name, "ReleaseSRWLockShared") == 0) return subsys_ReleaseSRWLockShared(first);
            if (strcmp(name, "SleepConditionVariableSRW") == 0) return subsys_SleepConditionVariableSRW(first, second, (uint32_t)third, (uint32_t)fourth);
            if (strcmp(name, "WakeConditionVariable") == 0) return subsys_WakeConditionVariable(first);
            if (strcmp(name, "WakeAllConditionVariable") == 0) return subsys_WakeAllConditionVariable(first);
            if (strcmp(name, "InitOnceExecuteOnce") == 0) return subsys_InitOnceExecuteOnce(first, second, third, fourth);
            if (strcmp(name, "GetFinalPathNameByHandleW") == 0) return subsys_GetFinalPathNameByHandleW(first, second, (uint32_t)third, (uint32_t)fourth);
            if (strcmp(name, "WaitOnAddress") == 0) return subsys_WaitOnAddress(first, second, third, (uint32_t)fourth);
            if (strcmp(name, "WakeByAddressSingle") == 0) { subsys_WakeByAddressSingle(first); return 0; }
            if (strcmp(name, "WakeByAddressAll") == 0) { subsys_WakeByAddressAll(first); return 0; }
            if (strcmp(name, "CreateWaitableTimerExW") == 0) return subsys_CreateWaitableTimerExW(first, second, (uint32_t)third, (uint32_t)fourth);
            if (strcmp(name, "CreateWaitableTimerW") == 0) return subsys_CreateWaitableTimerW(first, second, (uint32_t)third);
            if (strcmp(name, "SetWaitableTimer") == 0) return subsys_SetWaitableTimer(first, second, (uint32_t)third, fourth);
            if (strcmp(name, "CreateThread") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint32_t flags = (regs && regs[7]) ? (uint32_t)guest_load(regs[7] + 40, 4) : 0;
                uint64_t id_ptr = (regs && regs[7]) ? guest_load(regs[7] + 48, 8) : 0;
                return guest_create_thread(first, second, third, fourth, flags, id_ptr);
            }

            /* CRT Globals & Startup */
            if (strcmp(name, "__p___argc") == 0) return guest_p_argc();
            if (strcmp(name, "__p___argv") == 0) return guest_p_argv();
            if (strcmp(name, "__p___wargv") == 0) return guest_p_wargv();
            if (strcmp(name, "__p__fmode") == 0) return guest_p_fmode();
            if (strcmp(name, "__p__commode") == 0) return guest_p_commode();
            if (strcmp(name, "__p__environ") == 0) return guest_p_environ();
            if (strcmp(name, "__p__wenviron") == 0) return guest_p_wenviron();
            if (strcmp(name, "_crt_atexit") == 0) return guest_crt_atexit(first);
            if (strcmp(name, "_set_invalid_parameter_handler") == 0) return guest_set_invalid_param(first);
            if (strcmp(name, "_set_app_type") == 0) return guest_set_app_type((uint32_t)first);
            if (strcmp(name, "_configure_wide_argv") == 0) return guest_configure_argv((uint32_t)first);
            if (strcmp(name, "_initialize_wide_environment") == 0) return guest_init_env();
            if (strcmp(name, "_get_initial_wide_environment") == 0) return guest_get_initial_env();
            if (strcmp(name, "_initterm") == 0) return guest_initterm(first, second);
            if (strcmp(name, "_initterm_e") == 0) return guest_initterm_e(first, second);
            if (strcmp(name, "_seh_filter_exe") == 0) return guest_seh_filter_exe((uint32_t)first, second);
            if (strcmp(name, "_cexit") == 0) return guest_cexit();
            if (strcmp(name, "_set_new_mode") == 0) return guest_set_new_mode((uint32_t)first);
            if (strcmp(name, "setvbuf") == 0) return guest_setvbuf(first, second, (uint32_t)third, fourth);
            if (strcmp(name, "exit") == 0 || strcmp(name, "_exit") == 0) guest_exit((uint32_t)first);
            if (strcmp(name, "abort") == 0) abort();
            if (strcmp(name, "_errno") == 0) return guest_errno();

            /* CRT Stdio & Formatters */
            if (strcmp(name, "__acrt_iob_func") == 0) return guest_acrt_iob_func((uint32_t)first);
            if (strcmp(name, "fputc") == 0) return guest_fputc((uint32_t)first, second);
            if (strcmp(name, "putchar") == 0) return guest_putchar((uint32_t)first);
            if (strcmp(name, "fputs") == 0) return guest_fputs(first, second);
            if (strcmp(name, "puts") == 0) return guest_puts(first);
            if (strcmp(name, "fwrite") == 0) return guest_fwrite(first, second, third, fourth);
            if (strcmp(name, "fflush") == 0) return guest_fflush(first);
            if (strcmp(name, "clearerr") == 0) return 0;
            if (strcmp(name, "feof") == 0) return guest_feof(first);
            if (strcmp(name, "ferror") == 0) return guest_ferror(first);
            if (strcmp(name, "_wfopen") == 0) return subsys_crt_wfopen(first, second);
            if (strcmp(name, "strerror") == 0) return guest_strerror((int)first);
            if (strcmp(name, "fclose") == 0) return guest_fclose(first);
            if (strcmp(name, "fread") == 0) return subsys_crt_fread(first, second, third, fourth);
            if (strcmp(name, "getc") == 0 || strcmp(name, "fgetc") == 0) return subsys_crt_getc(first);
            if (strcmp(name, "fgets") == 0) return subsys_crt_fgets(first, (uint32_t)second, third);
            if (strcmp(name, "getenv") == 0) return guest_getenv(first);
            if (strcmp(name, "_fileno") == 0) {
                if (first == guest_acrt_iob_func(0)) return 0;
                if (first == guest_acrt_iob_func(1)) return 1;
                if (first == guest_acrt_iob_func(2)) return 2;
                return 1;
            }
            if (strcmp(name, "_isatty") == 0) return isatty((int)first);
            if (strcmp(name, "_get_osfhandle") == 0) return first;
            if (strcmp(name, "_setmode") == 0) return 0;
            if (strcmp(name, "_close") == 0) return close((int)first);
            if (strcmp(name, "_lock_file") == 0 || strcmp(name, "_unlock_file") == 0) return 0;
            if (strcmp(name, "_read") == 0) return subsys_crt_read((int)first, second, (size_t)third);
            if (strcmp(name, "_write") == 0) return subsys_crt_write((int)first, second, (size_t)third);
            if (strcmp(name, "_open") == 0) return subsys_crt_open(first, (int)second, (int)third);
            if (strcmp(name, "IsDBCSLeadByteEx") == 0) return 0;
            if (strcmp(name, "__stdio_common_vfprintf") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t va_addr = (regs && regs[7]) ? guest_load(regs[7] + 40, 8) : 0;
                return subsys_stdio_common_vfprintf(first, second, third, fourth, va_addr);
            }
            if (strcmp(name, "__stdio_common_vsprintf") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t va_addr = (regs && regs[7]) ? guest_load(regs[7] + 48, 8) : 0;
                return subsys_stdio_common_vsprintf(first, second, third, fourth, va_addr);
            }

            /* Memory & String Allocation */
            if (strcmp(name, "malloc") == 0) return guest_heap_alloc(0x7fff2001, 0, first);
            if (strcmp(name, "free") == 0) { if (first) guest_heap_free(0x7fff2001, 0, first); return 0; }
            if (strcmp(name, "calloc") == 0) return guest_heap_alloc(0x7fff2001, 8, first * second);
            if (strcmp(name, "realloc") == 0) return guest_heap_realloc(0x7fff2001, 0, first, second);
            if (strcmp(name, "_strdup") == 0) return guest_strdup(first);
            if (strcmp(name, "___lc_codepage_func") == 0) return 65001;
            if (strcmp(name, "_configthreadlocale") == 0) return 0;
            if (strcmp(name, "localeconv") == 0) return guest_localeconv();
            if (strcmp(name, "setlocale") == 0) return guest_setlocale(first, second);
            if (strcmp(name, "wcslen") == 0) return guest_wcslen(first);
            if (strcmp(name, "wcsnlen") == 0) return guest_wcsnlen(first, second);
            if (strcmp(name, "strlen") == 0) return guest_strlen(first);
            if (strcmp(name, "strnlen") == 0) return guest_strnlen(first, second);
            if (strcmp(name, "memset") == 0) return guest_memset(first, (uint32_t)second, third);
            if (strcmp(name, "memcpy") == 0 || strcmp(name, "memmove") == 0) return guest_memcpy(first, second, third);
            if (strcmp(name, "memcmp") == 0) return guest_memcmp(first, second, third, fourth);
            if (strcmp(name, "memchr") == 0) return guest_memchr(first, (uint32_t)second, third, fourth);
            if (strcmp(name, "strstr") == 0) return guest_strstr(first, second, third, fourth);
            if (strcmp(name, "strcmp") == 0) return guest_strcmp(first, second);
            if (strcmp(name, "strncmp") == 0) return guest_strncmp(first, second, third);
            if (strcmp(name, "strcpy") == 0) return guest_strcpy(first, second);
            if (strcmp(name, "strchr") == 0) return guest_strchr(first, second, third, fourth);
            if (strcmp(name, "strrchr") == 0) return guest_strrchr(first, second, third, fourth);
            if (strcmp(name, "qsort") == 0) return guest_qsort(first, second, third, fourth);
            if (strcmp(name, "PathIsRelativeA") == 0) return guest_path_is_relative_a(first);
            if (strcmp(name, "_fullpath") == 0) return guest_fullpath(first, second, third);
            if (strcmp(name, "_stat64") == 0) return guest_stat64(first, second);
            if (strcmp(name, "_fstat64") == 0) return guest_fstat64((int)first, second);
            if (strcmp(name, "GetCPInfo") == 0) return guest_get_cp_info((uint32_t)first, second);
            if (strcmp(name, "GetConsoleCP") == 0 || strcmp(name, "GetConsoleOutputCP") == 0) return 65001;
            if (strcmp(name, "GetConsoleMode") == 0) return guest_get_console_mode(first, second);
            if (strcmp(name, "SetConsoleMode") == 0) return 1;
            if (strcmp(name, "GetConsoleScreenBufferInfo") == 0) return subsys_GetConsoleScreenBufferInfo(first, second);
            if (strcmp(name, "SetConsoleTextAttribute") == 0) return 1;
            if (strcmp(name, "WriteConsoleW") == 0) return guest_write_console_w(first, second, (uint32_t)third, fourth);
            if (strcmp(name, "GetEnvironmentVariableW") == 0) return subsys_GetEnvironmentVariableW(first, second, (uint32_t)third);
            if (strcmp(name, "GetComputerNameExW") == 0) return subsys_GetComputerNameExW((uint32_t)first, second, third);
            if (strcmp(name, "GetUserProfileDirectoryW") == 0) return subsys_GetUserProfileDirectoryW(first, second, third);
            if (strcmp(name, "GetTimeZoneInformation") == 0) return 0;
            if (strcmp(name, "_beginthreadex") == 0) return 0x7fff6001;
            if (strcmp(name, "_endthreadex") == 0) return 0;
            if (strcmp(name, "NtWriteFile") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t args = (regs && regs[7]) ? regs[7] + 32 : 0;
                return guest_nt_write_file(first, second, third, fourth, args);
            }
            if (strcmp(name, "NtReadFile") == 0) {
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t args = (regs && regs[7]) ? regs[7] + 32 : 0;
                return guest_nt_read_file(first, second, third, fourth, args);
            }

            /*
             * Wine's PE DLLs (such as its ucrtbase.dll) log through ntdll's
             * debug channels. Channels report as disabled and messages are
             * dropped unless ARM64_RECOMPILER_WINE_DEBUG is set.
             */
            if (strcmp(name, "MultiByteToWideChar") == 0 || strcmp(name, "WideCharToMultiByte") == 0) {
                /* Same conversion as the inline lowering; arguments 5 and 6 are on the stack. */
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t stack = regs ? regs[7] + 40 : 0;
                uint64_t dest = stack ? guest_load(stack, 8) : 0;
                uint64_t size = stack ? guest_load(stack + 8, 4) : 0;
                return guest_convert_text(name[0] == 'M', (uint32_t)first, (uint32_t)second,
                                          third, (int32_t)fourth, dest, size);
            }
            if (strcmp(name, "GetVersionExW") == 0 || strcmp(name, "GetVersionExA") == 0) {
                /* Windows 10 build 19045: dwMajor, dwMinor, dwBuild, dwPlatformId follow the size field. */
                if (!first)
                    return 0;
                guest_store(first + 4, 10, 4);
                guest_store(first + 8, 0, 4);
                guest_store(first + 12, 19045, 4);
                guest_store(first + 16, 2, 4);
                guest_store(first + 20, 0, 2);
                return 1;
            }
            if (strcmp(name, "GetEnvironmentStringsA") == 0) {
                static const char environment[] = "SystemRoot=C:\\Windows\0";
                uint64_t address = guest_heap_alloc(0x7fff2001, 0, sizeof environment);
                for (size_t i = 0; address && i < sizeof environment; ++i)
                    guest_store(address + i, (unsigned char)environment[i], 1);
                return address;
            }
            if (strcmp(name, "FreeEnvironmentStringsA") == 0)
                return guest_heap_free(0x7fff2001, 0, first);
            if (strcmp(name, "GetModuleFileNameA") == 0) {
                static const char module_name[] = "C:\\program.exe";
                uint32_t size = (uint32_t)third;
                if (first && first != guest_image_base) {
                    last_error = 6;
                    return 0;
                }
                if (!size) {
                    last_error = 122;
                    return 0;
                }
                size_t written = size < sizeof module_name ? size : sizeof module_name;
                for (size_t i = 0; i + 1 < written; ++i)
                    guest_store(second + i, (unsigned char)module_name[i], 1);
                guest_store(second + written - 1, 0, 1);
                if (written < sizeof module_name) {
                    last_error = 122;
                    return size;
                }
                return written - 1;
            }
            if (strcmp(name, "SetConsoleCtrlHandler") == 0)
                return 1;
            if (strcmp(name, "NtQuerySystemTime") == 0) {
                guest_system_filetime(first);
                return 0;
            }
            if (strcmp(name, "GetCommandLineW") == 0 || strcmp(name, "GetCommandLineA") == 0)
                return guest_command_line(name[14] == 'W');
            if (strcmp(name, "SetStdHandle") == 0)
                return 1;
            if (strcmp(name, "GetStartupInfoA") == 0) {
                guest_startup_info(first); /* same layout and zero fields as the W form */
                return 0;
            }
            if (strcmp(name, "IsBadStringPtrA") == 0 || strcmp(name, "IsBadStringPtrW") == 0)
                return first == 0;
            if (strcmp(name, "GetUserDefaultLocaleName") == 0) {
                static const char locale[] = "en-US";
                if ((uint32_t)second < sizeof locale) {
                    last_error = 122;
                    return 0;
                }
                for (size_t i = 0; i < sizeof locale; ++i)
                    guest_store(first + i * 2, (unsigned char)locale[i], 2);
                return sizeof locale;
            }
            if (strcmp(name, "LocaleNameToLCID") == 0)
                return 0x409; /* every locale name maps to en-US */
            if (strcmp(name, "LCMapStringW") == 0 || strcmp(name, "LCMapStringEx") == 0) {
                /* Case mapping (LCMAP_LOWERCASE/UPPERCASE) or a plain copy for ASCII text. */
                uint64_t *regs = (uint64_t *)current_cpu;
                uint64_t stack = regs ? regs[7] + 40 : 0;
                bool ex = name[11] == 'E';
                uint32_t flags = (uint32_t)second;
                uint64_t source = third;
                int32_t length = (int32_t)fourth;
                uint64_t dest = stack ? guest_load(stack, 8) : 0;
                int32_t size = stack ? (int32_t)guest_load(stack + 8, 4) : 0;
                (void)ex;
                if (!source || flags & ~0x0f000300u || length == 0 || length < -1) {
                    last_error = 87;
                    return 0;
                }
                if (length == -1) {
                    for (length = 0; guest_load(source + (uint64_t)length * 2, 2); ++length) {}
                    ++length;
                }
                if (!size)
                    return (uint64_t)length;
                if (size < length) {
                    last_error = 122;
                    return 0;
                }
                for (int32_t i = 0; i < length; ++i) {
                    unsigned c = (unsigned)guest_load(source + (uint64_t)i * 2, 2);
                    if (c < 128 && (flags & 0x100)) c = (unsigned)tolower((int)c);
                    if (c < 128 && (flags & 0x200)) c = (unsigned)toupper((int)c);
                    guest_store(dest + (uint64_t)i * 2, c, 2);
                }
                return (uint64_t)length;
            }
            if (strcmp(name, "GetStringTypeW") == 0) {
                /* CT_CTYPE1 only; non-ASCII characters report C1_DEFINED | C1_ALPHA. */
                if ((uint32_t)first != 1 || !second || !fourth) {
                    last_error = 87;
                    return 0;
                }
                int32_t count = (int32_t)third;
                if (count == -1)
                    for (count = 0; guest_load(second + (uint64_t)count * 2, 2); ++count) {}
                for (int32_t i = 0; i < count; ++i) {
                    unsigned c = (unsigned)guest_load(second + (uint64_t)i * 2, 2);
                    unsigned type = 0x200;
                    if (c < 128) {
                        if (isupper((int)c)) type |= 0x1 | 0x100;
                        if (islower((int)c)) type |= 0x2 | 0x100;
                        if (isdigit((int)c)) type |= 0x4;
                        if (isspace((int)c)) type |= 0x8;
                        if (ispunct((int)c)) type |= 0x10;
                        if (iscntrl((int)c)) type |= 0x20;
                        if (c == ' ' || c == '\t') type |= 0x40;
                        if (isxdigit((int)c)) type |= 0x80;
                        if (!c) type = 0x20 | 0x200;
                    } else {
                        type |= 0x100;
                    }
                    guest_store(fourth + (uint64_t)i * 2, type, 2);
                }
                return 1;
            }
            if (strcmp(name, "__wine_dbg_get_channel_flags") == 0) {
                /* Like ntdll, record the answer in the channel (its first byte), which
                   clears the "not yet initialized" bit: Wine's TRACE/WARN macros then test
                   the byte inline and disabled messages cost nothing more. */
                uint64_t flags = wine_debug_enabled() ? 0x0f : 0;
                if (first)
                    guest_store(first, flags, 1);
                return flags;
            }
            if (strcmp(name, "__wine_dbg_header") == 0) {
                /* (class, channel, function). TRACE/WARN reach this first for a channel
                   they have not asked about yet; record its flags as above so that a
                   disabled channel stops formatting arguments and calling here. */
                if (second)
                    guest_store(second, wine_debug_enabled() ? 0x0f : 0, 1);
                return wine_debug_enabled() ? 0 : (uint64_t)(int64_t)-1;
            }
            if (strcmp(name, "__wine_dbg_strdup") == 0)
                return first;
            if (strcmp(name, "__wine_dbg_output") == 0) {
                size_t length = 0;
                while (first && length < 4096 && guest_load(first + length, 1))
                    ++length;
                if (wine_debug_enabled())
                    for (size_t i = 0; i < length; ++i)
                        fputc((int)guest_load(first + i, 1), stderr);
                return length;
            }
            if (strcmp(name, "_vsnprintf") == 0) {
                int length = subsys_stdio_common_vsprintf(0, first, second, third, fourth);
                return (uint64_t)(int64_t)((uint64_t)length >= second ? -1 : length);
            }

            if (kernelbase_fallback(name, inline_frame, &shim_res))
                return shim_res;
            return guest_unimplemented_stub(name, "wine_api");
        }
    }
    if (target >= 0x7fff0000 && target < 0x80000000)
        return 0;
    fprintf(stderr, "RVA 0x%llx: unsupported indirect call target 0x%llx\n",
            (unsigned long long)guest_pc, (unsigned long long)target);
    exit(125);
}

/*
 * Lifted system DLLs (Wine's ntdll.dll): exports the runtime owns call here by
 * name. Rtl and Ldr entry points adapt NT conventions (NTSTATUS results,
 * counted strings, LARGE_INTEGER timeouts) to the runtime's Win32 shims;
 * everything else, including the Nt* syscalls, dispatches like a named import.
 */
enum {
    STATUS_SUCCESS_NT = 0, STATUS_TIMEOUT_NT = 0x102, STATUS_NO_MORE_ENTRIES_NT = 0x8000001a,
    STATUS_NOT_IMPLEMENTED_NT = 0xc0000002, STATUS_INVALID_PARAMETER_NT = 0xc000000d,
    STATUS_NO_MEMORY_NT = 0xc0000017, STATUS_PROCEDURE_NOT_FOUND_NT = 0xc000007a,
    STATUS_DLL_NOT_FOUND_NT = 0xc0000135, STATUS_ORDINAL_NOT_FOUND_NT = 0xc0000138,
};

static uint64_t call_system(const char *name, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return guest_indirect_call(system_thunk(name), a, b, c, d);
}

/* NUL-terminated guest heap copy of a UNICODE_STRING (width 2) or ANSI_STRING (width 1). */
static uint64_t counted_string_copy(uint64_t string, unsigned width) {
    if (!string)
        return 0;
    uint64_t length = guest_load(string, 2), buffer = guest_load(string + 8, 8);
    uint64_t copy = guest_heap_alloc(GUEST_HEAP_HANDLE, 8, length + width);
    for (uint64_t i = 0; copy && i < length; ++i)
        guest_store(copy + i, guest_load(buffer + i, 1), 1);
    return copy;
}

/* NT timeout (NULL: infinite; negative: relative 100 ns; positive: absolute FILETIME) to ms. */
static uint32_t nt_timeout_ms(uint64_t timeout) {
    if (!timeout)
        return UINT32_MAX;
    int64_t value = (int64_t)guest_load(timeout, 8);
    if (value > 0) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        int64_t current = ((int64_t)now.tv_sec + 11644473600LL) * 10000000 + now.tv_nsec / 100;
        value = current - value;
        if (value > 0)
            value = 0;
    }
    uint64_t ms = (uint64_t)(-value) / 10000;
    return ms >= UINT32_MAX ? UINT32_MAX - 1 : (uint32_t)ms;
}

/*
 * Wine NLS data files (locale.nls, c_*.nls, l_intl.nls, sortdefault.nls,
 * norm*.nls), loaded once into guest heap memory for kernelbase's locale code.
 * ARM64_RECOMPILER_NLS_DIR names Wine's share/wine/nls directory.
 */
static uint64_t nls_file(const char *name, uint64_t *size) {
    static struct { char name[32]; uint64_t address, size; } files[16];
    static size_t count;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < count; ++i)
        if (!strcmp(files[i].name, name)) {
            *size = files[i].size;
            pthread_mutex_unlock(&lock);
            return files[i].address;
        }
    const char *directory = getenv("ARM64_RECOMPILER_NLS_DIR");
    char path[1024];
    uint64_t address = 0;
    struct stat info;
    int fd = -1;
    if (directory && count < sizeof files / sizeof *files &&
        snprintf(path, sizeof path, "%s/%s", directory, name) < (int)sizeof path &&
        (fd = open(path, O_RDONLY)) >= 0 && !fstat(fd, &info) && info.st_size > 0 &&
        (address = guest_heap_alloc(GUEST_HEAP_HANDLE, 0, (uint64_t)info.st_size))) {
        unsigned char *host = (unsigned char *)(uintptr_t)address;
        ssize_t done = 0;
        while (done < info.st_size) {
            ssize_t n = read(fd, host + done, (size_t)(info.st_size - done));
            if (n <= 0)
                break;
            done += n;
        }
        if (done == info.st_size) {
            snprintf(files[count].name, sizeof files[count].name, "%s", name);
            files[count].address = address;
            files[count].size = *size = (uint64_t)info.st_size;
            ++count;
        } else {
            guest_heap_free(GUEST_HEAP_HANDLE, 0, address);
            address = 0;
        }
    }
    if (fd >= 0)
        close(fd);
    pthread_mutex_unlock(&lock);
    if (!address && getenv("ARM64_RECOMPILER_TRACE_IMPORTS"))
        fprintf(stderr, "[nls] cannot load %s (set ARM64_RECOMPILER_NLS_DIR)\n", name);
    return address;
}

static uint64_t nt_query_information_process(uint64_t process, uint32_t kind, uint64_t buffer,
                                             uint32_t length, uint64_t returned) {
    if (process != UINT64_MAX)
        return 0xc0000008; /* STATUS_INVALID_HANDLE: only the current process */
    uint32_t needed;
    switch (kind) {
    case 0: /* ProcessBasicInformation */
        needed = 48;
        if (length >= needed) {
            for (uint32_t i = 0; i < needed; i += 8)
                guest_store(buffer + i, 0, 8);
            guest_store(buffer + 8, PEB_BASE, 8);
            guest_store(buffer + 16, 1, 8);
            guest_store(buffer + 24, 8, 4);
            guest_store(buffer + 32, guest_identity(0), 8);
        }
        break;
    case 7:    /* ProcessDebugPort */
    case 0x1a: /* ProcessWow64Information */
        needed = 8;
        if (length >= needed)
            guest_store(buffer, 0, 8);
        break;
    case 0x1f: /* ProcessDebugFlags: no debugger */
        needed = 4;
        if (length >= needed)
            guest_store(buffer, 1, 4);
        break;
    case 0x24: /* ProcessCookie */
        needed = 4;
        if (length >= needed)
            guest_store(buffer, 0x5eed1234, 4);
        break;
    case 0x1e: /* ProcessDebugObjectHandle */
        return 0xc0000353; /* STATUS_PORT_NOT_SET */
    default:
        if (getenv("ARM64_RECOMPILER_TRACE_IMPORTS"))
            fprintf(stderr, "[override] NtQueryInformationProcess class %#x unsupported\n", kind);
        return 0xc0000003; /* STATUS_INVALID_INFO_CLASS */
    }
    if (returned)
        guest_store(returned, needed, 4);
    return length >= needed ? STATUS_SUCCESS_NT : 0xc0000004; /* STATUS_INFO_LENGTH_MISMATCH */
}

/*
 * Per-block heap user value and flags (RtlSetUserValueHeap / RtlGetUserInfoHeap),
 * which Wine's LocalAlloc/GlobalAlloc use to map blocks back to their handles.
 */
struct heap_user_info { uint64_t block, value; uint32_t flags; struct heap_user_info *next; };
static struct heap_user_info *heap_user_buckets[1024];
static pthread_mutex_t heap_user_lock = PTHREAD_MUTEX_INITIALIZER;

static struct heap_user_info *heap_user_entry(uint64_t block, bool create) {
    struct heap_user_info **bucket = &heap_user_buckets[(block >> 4) % 1024];
    for (struct heap_user_info *entry = *bucket; entry; entry = entry->next)
        if (entry->block == block)
            return entry;
    if (!create)
        return NULL;
    struct heap_user_info *entry = calloc(1, sizeof *entry);
    if (entry) {
        entry->block = block;
        entry->next = *bucket;
        *bucket = entry;
    }
    return entry;
}

static bool rtl_override(const char *name, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t *result) {
    uint64_t *regs = (uint64_t *)current_cpu;
    uint64_t stack = regs ? regs[7] + 40 : 0; /* fifth argument */
    if (!strncmp(name, "Rtl", 3)) {
        const char *rest = name + 3;
        static const char *const same[][2] = {
            {"AllocateHeap", "HeapAlloc"}, {"FreeHeap", "HeapFree"}, {"ReAllocateHeap", "HeapReAlloc"},
            {"SizeHeap", "HeapSize"}, {"LockHeap", "HeapLock"}, {"UnlockHeap", "HeapUnlock"},
            {"ValidateHeap", "HeapValidate"}, {"TryEnterCriticalSection", "TryEnterCriticalSection"},
            {"InitializeSRWLock", "InitializeSRWLock"}, {"AcquireSRWLockExclusive", "AcquireSRWLockExclusive"},
            {"ReleaseSRWLockExclusive", "ReleaseSRWLockExclusive"}, {"AcquireSRWLockShared", "AcquireSRWLockShared"},
            {"ReleaseSRWLockShared", "ReleaseSRWLockShared"},
            {"TryAcquireSRWLockExclusive", "TryAcquireSRWLockExclusive"},
            {"TryAcquireSRWLockShared", "TryAcquireSRWLockShared"},
            {"WakeConditionVariable", "WakeConditionVariable"},
            {"WakeAllConditionVariable", "WakeAllConditionVariable"},
            {"WakeAddressSingle", "WakeByAddressSingle"}, {"WakeAddressAll", "WakeByAddressAll"},
            {"GetLastWin32Error", "GetLastError"}, {"SetLastWin32Error", "SetLastError"},
            {"RestoreLastWin32Error", "SetLastError"}, {"CaptureContext", "RtlCaptureContext"},
            {"LookupFunctionEntry", "RtlLookupFunctionEntry"}, {"VirtualUnwind", "RtlVirtualUnwind"},
            {"PcToFileHeader", "RtlPcToFileHeader"}, {"QueryPerformanceCounter", "QueryPerformanceCounter"},
            {"QueryPerformanceFrequency", "QueryPerformanceFrequency"}, {"GetTickCount", "GetTickCount"},
        };
        /* Wine-internal heap flags (HEAP_SETTABLE_USER_*, ...) have no runtime-heap meaning. */
        if (!strcmp(rest, "AllocateHeap") || !strcmp(rest, "ReAllocateHeap"))
            b &= GUEST_HEAP_FLAGS;
        for (size_t i = 0; i < sizeof same / sizeof *same; ++i)
            if (!strcmp(rest, same[i][0])) {
                *result = call_system(same[i][1], a, b, c, d);
                return true;
            }
        if (!strcmp(rest, "InitializeConditionVariable")) {
            guest_store(a, 0, 8);
            *result = 0;
        } else if (!strcmp(rest, "CreateHeap")) {
            *result = call_system("HeapCreate", a, c, d, 0);
        } else if (!strcmp(rest, "DestroyHeap")) {
            *result = call_system("HeapDestroy", a, 0, 0, 0) ? 0 : a;
        } else if (!strcmp(rest, "GetProcessHeaps")) {
            if (a && b)
                guest_store(b, GUEST_HEAP_HANDLE, 8);
            *result = 1;
        } else if (!strcmp(rest, "SetUserValueHeap") || !strcmp(rest, "SetUserFlagsHeap")) {
            /* (heap, flags, block, value) / (heap, flags, block, clear, set) */
            pthread_mutex_lock(&heap_user_lock);
            struct heap_user_info *entry = heap_user_entry(c, true);
            if (entry && rest[7] == 'V')
                entry->value = d;
            else if (entry)
                entry->flags = (entry->flags & ~(uint32_t)d) | (stack ? (uint32_t)guest_load(stack, 4) : 0);
            pthread_mutex_unlock(&heap_user_lock);
            *result = entry != NULL;
        } else if (!strcmp(rest, "GetUserInfoHeap")) {
            /* (heap, flags, block, void **value, ULONG *flags) */
            pthread_mutex_lock(&heap_user_lock);
            struct heap_user_info *entry = heap_user_entry(c, false);
            uint64_t value = entry ? entry->value : 0;
            uint32_t flags = entry ? entry->flags : 0;
            pthread_mutex_unlock(&heap_user_lock);
            if (d)
                guest_store(d, value, 8);
            uint64_t flags_out = stack ? guest_load(stack, 8) : 0;
            if (flags_out)
                guest_store(flags_out, flags, 4);
            *result = 1;
        } else if (!strcmp(rest, "CompactHeap")) {
            *result = 0;
        } else if (!strcmp(rest, "SetHeapInformation")) {
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "WalkHeap")) {
            *result = STATUS_NO_MORE_ENTRIES_NT;
        } else if (!strcmp(rest, "EnterCriticalSection") || !strcmp(rest, "LeaveCriticalSection") ||
                   !strcmp(rest, "DeleteCriticalSection")) {
            guest_critical_section(a, rest[0] == 'D' ? 2 : rest[0] == 'E');
            *result = STATUS_SUCCESS_NT;
        } else if (!strncmp(rest, "InitializeCriticalSection", 25)) {
            guest_init_critical(a, rest[25] ? (uint32_t)b : 0);
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "IsCriticalSectionLocked")) {
            *result = guest_load(a + 16, 8) != 0;
        } else if (!strcmp(rest, "IsCriticalSectionLockedByThread")) {
            *result = guest_load(a + 16, 8) == guest_identity(1);
        } else if (!strcmp(rest, "SleepConditionVariableSRW") || !strcmp(rest, "SleepConditionVariableCS")) {
            uint32_t ms = nt_timeout_ms(c);
            uint64_t ok = rest[22] == 'S'
                ? call_system("SleepConditionVariableSRW", a, b, ms, d)
                : call_system("SleepConditionVariableCS", a, b, ms, 0);
            *result = ok ? STATUS_SUCCESS_NT : STATUS_TIMEOUT_NT;
        } else if (!strcmp(rest, "WaitOnAddress")) {
            *result = call_system("WaitOnAddress", a, b, c, nt_timeout_ms(d)) ? STATUS_SUCCESS_NT : STATUS_TIMEOUT_NT;
        } else if (!strcmp(rest, "FlsAlloc")) {
            uint64_t index = guest_indirect_call(FLS_ALLOC, a, 0, 0, 0);
            if ((uint32_t)index == UINT32_MAX) {
                *result = STATUS_NO_MEMORY_NT;
            } else {
                guest_store(b, index, 4);
                *result = STATUS_SUCCESS_NT;
            }
        } else if (!strcmp(rest, "FlsFree")) {
            *result = guest_indirect_call(FLS_FREE, a, 0, 0, 0) ? STATUS_SUCCESS_NT : STATUS_INVALID_PARAMETER_NT;
        } else if (!strcmp(rest, "FlsGetValue")) {
            uint64_t value = guest_indirect_call(FLS_GET, a, 0, 0, 0);
            if (last_error) {
                *result = STATUS_INVALID_PARAMETER_NT;
            } else {
                guest_store(b, value, 8);
                *result = STATUS_SUCCESS_NT;
            }
        } else if (!strcmp(rest, "FlsSetValue")) {
            *result = guest_indirect_call(FLS_SET, a, b, 0, 0) ? STATUS_SUCCESS_NT : STATUS_INVALID_PARAMETER_NT;
        } else if (!strcmp(rest, "RaiseException")) {
            if (!regs)
                guest_trap("RtlRaiseException requires a guest context");
            uint64_t rsp = regs[7];
            guest_raise_exception((uint32_t)guest_load(a, 4), (uint32_t)guest_load(a + 4, 4),
                                  (uint32_t)guest_load(a + 24, 4), a + 32, guest_load(rsp, 8), rsp + 8);
            *result = 0;
        } else if (!strcmp(rest, "AddVectoredExceptionHandler")) {
            *result = guest_add_vectored_exception_handler((uint32_t)a, b);
        } else if (!strcmp(rest, "RemoveVectoredExceptionHandler")) {
            *result = guest_remove_vectored_exception_handler(a);
        } else if (!strcmp(rest, "ExitUserProcess")) {
            guest_exit((uint32_t)a);
        } else {
            return false;
        }
        return true;
    }
    if (!strncmp(name, "Nt", 2)) {
        const char *rest = name + 2;
        if (!strcmp(rest, "Close")) {
            *result = guest_close_handle(a) ? STATUS_SUCCESS_NT : 0xc0000008; /* STATUS_INVALID_HANDLE */
        } else if (!strcmp(rest, "QueryPerformanceCounter")) {
            guest_performance_counter(a);
            if (b)
                guest_performance_frequency(b);
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "QuerySystemTime")) {
            guest_system_filetime(a);
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "YieldExecution")) {
            sched_yield();
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "DelayExecution")) {
            uint32_t ms = nt_timeout_ms(b);
            if (ms == UINT32_MAX)
                for (;;)
                    pause();
            if (ms)
                usleep(ms * 1000);
            else
                sched_yield();
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "QueryInformationProcess")) {
            *result = nt_query_information_process(a, (uint32_t)b, c, (uint32_t)d,
                                                   stack ? guest_load(stack, 8) : 0);
        } else if (!strcmp(rest, "InitializeNlsFiles")) {
            /* (void **ptr, LCID *lcid, LARGE_INTEGER *size): locale.nls, en-US */
            uint64_t size = 0, address = nls_file("locale.nls", &size);
            if (!address) {
                *result = 0xc0000034; /* STATUS_OBJECT_NAME_NOT_FOUND */
            } else {
                guest_store(a, address, 8);
                if (b)
                    guest_store(b, 0x409, 4);
                if (c)
                    guest_store(c, size, 8);
                *result = STATUS_SUCCESS_NT;
            }
        } else if (!strcmp(rest, "GetNlsSectionPtr")) {
            /* (type, id, unknown, void **ptr, SIZE_T *size) */
            char file[32] = "";
            uint32_t type = (uint32_t)a, id = (uint32_t)b;
            static const char *const normalize[16] = {
                [1] = "normnfc.nls", [2] = "normnfd.nls", [5] = "normnfkc.nls",
                [6] = "normnfkd.nls", [13] = "normidna.nls",
            };
            if (type == 9)
                snprintf(file, sizeof file, "sortdefault.nls");
            else if (type == 10)
                snprintf(file, sizeof file, "%s", id ? "" : "l_intl.nls");
            else if (type == 11)
                snprintf(file, sizeof file, "c_%03u.nls", id);
            else if (type == 12 && id < 16 && normalize[id])
                snprintf(file, sizeof file, "%s", normalize[id]);
            uint64_t size = 0, address = file[0] ? nls_file(file, &size) : 0;
            if (!address) {
                *result = 0xc0000034;
            } else {
                guest_store(d, address, 8);
                uint64_t size_out = stack ? guest_load(stack, 8) : 0;
                if (size_out)
                    guest_store(size_out, size, 8);
                *result = STATUS_SUCCESS_NT;
            }
        } else if (!strcmp(rest, "QueryDefaultLocale")) {
            /* (user, LCID *): en-US */
            guest_store(b, 0x409, 4);
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "QueryDefaultUILanguage") || !strcmp(rest, "QueryInstallUILanguage")) {
            guest_store(a, 0x409, 2);
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "GetCurrentProcessorNumber")) {
            *result = 0;
        } else if (!strcmp(rest, "AllocateVirtualMemory")) {
            /* (process, PVOID *base, zero_bits, SIZE_T *size, type, protect) */
            uint64_t base = guest_load(b, 8), size = guest_load(d, 8);
            uint32_t type = stack ? (uint32_t)guest_load(stack, 4) : 0x1000;
            uint32_t protect = stack ? (uint32_t)guest_load(stack + 8, 4) : 4;
            uint64_t address = subsys_VirtualAlloc(base, size, type, protect);
            if (address) {
                guest_store(b, address, 8);
                guest_store(d, (size + 0xfff) & ~UINT64_C(0xfff), 8);
            }
            *result = address ? STATUS_SUCCESS_NT : STATUS_NO_MEMORY_NT;
        } else if (!strcmp(rest, "FreeVirtualMemory")) {
            /* (process, PVOID *base, SIZE_T *size, type) */
            *result = subsys_VirtualFree(guest_load(b, 8), guest_load(c, 8), (uint32_t)d)
                      ? STATUS_SUCCESS_NT : STATUS_INVALID_PARAMETER_NT;
        } else if (!strcmp(rest, "ProtectVirtualMemory")) {
            /* (process, PVOID *base, SIZE_T *size, new, ULONG *old) */
            uint64_t old = stack ? guest_load(stack, 8) : 0;
            *result = guest_virtual_protect(guest_load(b, 8), guest_load(c, 8), (uint32_t)d, old)
                      ? STATUS_SUCCESS_NT : STATUS_INVALID_PARAMETER_NT;
        } else if (!strcmp(rest, "TerminateProcess")) {
            if (!a || a == UINT64_MAX)
                guest_exit((uint32_t)b);
            *result = guest_terminate_process(a, (uint32_t)b) ? STATUS_SUCCESS_NT : 0xc0000008;
        } else {
            return false;
        }
        return true;
    }
    if (!strncmp(name, "Ldr", 3)) {
        const char *rest = name + 3;
        if (!strcmp(rest, "LoadDll") || !strcmp(rest, "GetDllHandle") || !strcmp(rest, "GetDllHandleEx")) {
            bool ex = rest[0] == 'G' && rest[12];
            uint64_t string = ex ? d : c, out = ex ? (stack ? guest_load(stack, 8) : 0) : d;
            uint64_t copy = counted_string_copy(string, 2);
            uint64_t handle = !copy ? 0 : rest[0] == 'L' ? guest_load_library(copy, 0, 0)
                                                         : guest_module_handle(copy, 1);
            if (copy && getenv("ARM64_RECOMPILER_TRACE_IMPORTS")) {
                char text[128];
                size_t n = 0;
                for (uint64_t c16; n < sizeof text - 1 && (c16 = guest_load(copy + 2 * n, 2)); ++n)
                    text[n] = c16 < 127 ? (char)c16 : '?';
                text[n] = 0;
                fprintf(stderr, "[ldr] %s(\"%s\") = %#llx\n", name, text, (unsigned long long)handle);
            }
            if (copy)
                guest_heap_free(GUEST_HEAP_HANDLE, 0, copy);
            if (out)
                guest_store(out, handle, 8);
            *result = handle ? STATUS_SUCCESS_NT : STATUS_DLL_NOT_FOUND_NT;
        } else if (!strcmp(rest, "GetProcedureAddress")) {
            uint64_t copy = counted_string_copy(b, 1);
            uint64_t address = guest_get_proc(a, copy ? copy : (c & 0xffff));
            if (copy)
                guest_heap_free(GUEST_HEAP_HANDLE, 0, copy);
            if (d)
                guest_store(d, address, 8);
            *result = address ? STATUS_SUCCESS_NT : b ? STATUS_PROCEDURE_NOT_FOUND_NT : STATUS_ORDINAL_NOT_FOUND_NT;
        } else if (!strcmp(rest, "GetDllPath")) {
            /*
             * (module, flags, WCHAR **path, WCHAR **unknown): the DLL search path for a
             * LoadLibraryEx with LOAD_LIBRARY_SEARCH_* flags. Lifted modules have no
             * directories; the system directory is where the loader says they all are.
             * The caller frees it with RtlReleasePath, from the process heap.
             */
            static const char folder[] = "C:\\windows\\system32";
            uint64_t text = guest_heap_alloc(GUEST_HEAP_HANDLE, 0, 2 * sizeof folder);
            for (size_t i = 0; text && i < sizeof folder; ++i)
                guest_store(text + 2 * i, (unsigned char)folder[i], 2);
            if (text && c)
                guest_store(c, text, 8);
            if (d)
                guest_store(d, 0, 8);
            *result = text ? STATUS_SUCCESS_NT : STATUS_NO_MEMORY_NT;
        } else if (!strcmp(rest, "GetDllFullName")) {
            /* (module, UNICODE_STRING *name): the program's path, or a DLL in the system directory. */
            char path[400];
            uint16_t wide[400];
            size_t length = 0;
            struct guest_module *module = a && a != guest_image_base ? find_guest_module(a) : NULL;
            if (module) {
                snprintf(path, sizeof path, "C:\\windows\\system32\\%s", module->name);
            } else if (a && a != guest_image_base) {
                *result = STATUS_DLL_NOT_FOUND_NT;
                return true;
            } else if (host_peb) { /* hosted: the image path Wine recorded in the process parameters */
                uint64_t parameters = guest_load((uint64_t)(uintptr_t)host_peb + 0x20, 8);
                uint64_t bytes = guest_load(parameters + 0x60, 2), text = guest_load(parameters + 0x68, 8);
                for (; length < bytes / 2 && length < 399; ++length)
                    wide[length] = (uint16_t)guest_load(text + 2 * length, 2);
                path[0] = 0;
            } else {
                snprintf(path, sizeof path, "C:\\program.exe");
            }
            if (!length)
                for (; path[length]; ++length)
                    wide[length] = (unsigned char)path[length];
            uint64_t capacity = guest_load(b + 2, 2), buffer = guest_load(b + 8, 8);
            size_t copied = length * 2 + 2 <= capacity ? length : capacity / 2 ? capacity / 2 - 1 : 0;
            for (size_t i = 0; i < copied; ++i)
                guest_store(buffer + 2 * i, wide[i], 2);
            if (capacity >= 2)
                guest_store(buffer + 2 * copied, 0, 2);
            guest_store(b, copied * 2, 2);
            *result = copied == length ? STATUS_SUCCESS_NT : 0xc0000023; /* STATUS_BUFFER_TOO_SMALL */
        } else if (!strcmp(rest, "UnloadDll")) {
            *result = guest_free_library(a) ? STATUS_SUCCESS_NT : STATUS_DLL_NOT_FOUND_NT;
        } else if (!strcmp(rest, "AddRefDll") || !strcmp(rest, "UnlockLoaderLock")) {
            *result = STATUS_SUCCESS_NT;
        } else if (!strcmp(rest, "LockLoaderLock")) {
            if (b)
                guest_store(b, 1, 4); /* LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED */
            if (c)
                guest_store(c, 1, 8);
            *result = STATUS_SUCCESS_NT;
        } else {
            return false;
        }
        return true;
    }
    return false;
}

#include "console_wine_host.h"

uint64_t guest_named_call(uint64_t *cache, const char *name, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    static int trace = -1;
    if (trace < 0)
        trace = getenv("ARM64_RECOMPILER_TRACE_IMPORTS") != NULL;
    if (trace)
        fprintf(stderr, "[override] %s(%#llx, %#llx, %#llx, %#llx)\n", name, (unsigned long long)a,
                (unsigned long long)b, (unsigned long long)c, (unsigned long long)d);
    uint64_t result;
    if (!trace) {
        /* The hottest runtime-owned entry points: resolve the name once per call site. */
        uint64_t fast = atomic_load_explicit((_Atomic uint64_t *)cache, memory_order_relaxed);
        if (!fast) {
            static const char *const names[] = {"RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap", "RtlSizeHeap",
                                                "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
                                                "RtlGetLastWin32Error", "RtlSetLastWin32Error"};
            for (size_t i = 0; i < sizeof names / sizeof *names; ++i)
                if (!strcmp(name, names[i])) {
                    fast = i + 1;
                    atomic_store_explicit((_Atomic uint64_t *)cache, fast, memory_order_relaxed);
                }
        }
        switch (fast) {
        case 1: return guest_heap_alloc(a, (uint32_t)b & GUEST_HEAP_FLAGS, c);
        case 2: return guest_heap_free(a, (uint32_t)b, c);
        case 3: return guest_heap_realloc(a, (uint32_t)b & GUEST_HEAP_FLAGS, c, d);
        case 4: return guest_heap_handle(a) && guest_heap_block(c) ? malloc_size((void *)(uintptr_t)c) : UINT64_MAX;
        case 5: guest_critical_section(a, 1); return STATUS_SUCCESS_NT;
        case 6: guest_critical_section(a, 0); return STATUS_SUCCESS_NT;
        case 7: return last_error;
        case 8: last_error = (uint32_t)a; return 0;
        default: break;
        }
    }
    if (wine_hosted && wine_host_syscall(cache, name, a, b, c, d, &result))
        return result;
    if (rtl_override(name, a, b, c, d, &result))
        return result;
    uint64_t token = atomic_load_explicit((_Atomic uint64_t *)cache, memory_order_relaxed);
    if (!token) {
        token = system_thunk(name);
        atomic_store_explicit((_Atomic uint64_t *)cache, token, memory_order_relaxed);
    }
    unimplemented_call = NULL;
    result = guest_indirect_call(token, a, b, c, d);
    /* NT entry points report failure through NTSTATUS, not a zero return. */
    if (unimplemented_call && (!strncmp(name, "Nt", 2) || !strncmp(name, "Zw", 2) || !strncmp(name, "Ldr", 3)))
        return STATUS_NOT_IMPLEMENTED_NT;
    return result;
}

void guest_check_return(uint64_t addr, uint64_t expected);

__attribute__((weak)) const struct guest_dispatch_entry guest_dispatch_table[] = {{0, NULL}};
__attribute__((weak)) const uint64_t guest_dispatch_count = 0;

static void (*module_dispatch(const struct guest_module *module, uint64_t target))(void *, uint64_t) {
    if (!module->references || !fits(target, 1, module->base, module->size))
        return NULL;
    size_t low = 0, high = module->dispatch_count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        const struct guest_dispatch_entry *entry = &module->dispatch[mid];
        if (entry->rva == target)
            return entry->fn;
        if (entry->rva < target)
            low = mid + 1;
        else
            high = mid;
    }
    return NULL;
}

/* Slow path: search the module tables, then the primary image's. */
static __attribute__((noinline)) void (*guest_resolve_dispatch(uint64_t target))(void *, uint64_t) {
    if (guest_image_base && target >= guest_image_base && target - guest_image_base < guest_image_span)
        target -= guest_image_base;

    for (size_t i = 0; i < guest_module_count; ++i) {
        void (*fn)(void *, uint64_t) = module_dispatch(&guest_modules[i], target);
        if (fn)
            return fn;
    }
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next) {
        void (*fn)(void *, uint64_t) = module_dispatch(item->module, target);
        if (fn)
            return fn;
    }

    size_t low = 0, high = guest_dispatch_count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (guest_dispatch_table[mid].rva == target)
            return guest_dispatch_table[mid].fn;
        if (guest_dispatch_table[mid].rva < target)
            low = mid + 1;
        else
            high = mid;
    }
    return NULL;
}

/*
 * Guest code address -> lifted function. Every indirect call and every call
 * between DLLs comes through here, so a direct-mapped cache fronts the table
 * search. The cache is shared by all threads without a lock (a thread-local
 * one costs a TLS lookup per call): a writer clears the key, stores the
 * function, then stores the key, and a reader accepts the function only if
 * the key matched both before and after reading it. Unloading a module
 * (dispatch_generation) empties the cache.
 */
enum { DISPATCH_SLOTS = 8192 };
static struct {
    _Atomic uint64_t target;
    void (*_Atomic fn)(void *, uint64_t);
} dispatch_cache[DISPATCH_SLOTS];
static _Atomic uint64_t dispatch_cache_generation;

static inline __attribute__((always_inline)) void (*guest_lookup_dispatch(uint64_t target))(void *, uint64_t) {
    size_t slot = (target ^ (target >> 4) ^ (target >> 17)) & (DISPATCH_SLOTS - 1);
    if (atomic_load_explicit(&dispatch_cache[slot].target, memory_order_relaxed) == target &&
        atomic_load_explicit(&dispatch_cache_generation, memory_order_relaxed) ==
            atomic_load_explicit(&dispatch_generation, memory_order_relaxed)) {
        void (*cached)(void *, uint64_t) = atomic_load_explicit(&dispatch_cache[slot].fn, memory_order_relaxed);
        if (cached && atomic_load_explicit(&dispatch_cache[slot].target, memory_order_relaxed) == target)
            return cached;
    }
    uint64_t generation = atomic_load(&dispatch_generation);
    if (atomic_load(&dispatch_cache_generation) != generation) {
        for (size_t i = 0; i < DISPATCH_SLOTS; ++i)
            atomic_store(&dispatch_cache[i].target, 0);
        atomic_store(&dispatch_cache_generation, generation);
    }
    void (*fn)(void *, uint64_t) = guest_resolve_dispatch(target);
    if (fn && target) {
        atomic_store(&dispatch_cache[slot].target, 0);
        atomic_store(&dispatch_cache[slot].fn, fn);
        atomic_store(&dispatch_cache[slot].target, target);
    }
    return fn;
}

#include "x86_interpret.h"

static void dispatch_guest_exception(uint32_t, uint32_t, uint32_t, const uint64_t *,
                                     uint64_t, uint64_t, bool);
bool subsys_vm_tracked(uint64_t);

/*
 * Control reached a VirtualAlloc page that is not PAGE_EXECUTE*: report the
 * access violation Windows raises under DEP (ExceptionInformation[0] = 8),
 * with Rip at the target and the return address on top of the stack.
 */
static __attribute__((noreturn)) void guest_execute_violation(uint64_t *regs, uint64_t target) {
    uint64_t arguments[] = {8, target};
    current_cpu = regs;
    delivering_fault = true;
    dispatch_guest_exception(0xc0000005, 0, 2, arguments, target, regs[7], true);
    guest_trap("execute access violation did not transfer control");
    __builtin_unreachable();
}

__attribute__((always_inline)) uint64_t guest_indirect_dispatch(void *cpu, uint64_t target, uint64_t return_va, uint32_t tail) {
    current_cpu = cpu;
    if (guest_image_base && target >= guest_image_base && target - guest_image_base < guest_image_span)
        target -= guest_image_base;
    void (*fn)(void *, uint64_t) = guest_lookup_dispatch(target);
    uint64_t *regs = (uint64_t *)cpu;
    if (fn) {
        fn(cpu, return_va);
        return regs[0];
    }
    if (guest_code_contains(target, 1) || subsys_vm_executable(target, 1))
        return x86_interpret(regs, target, return_va);
    if (subsys_vm_tracked(target))
        guest_execute_violation(regs, target);
    uint64_t rcx = regs[1], rdx = regs[2], r8 = regs[3], r9 = regs[4];
    uint64_t result = guest_indirect_call(target, rcx, rdx, r8, r9);
    regs[0] = result;
    if (!tail) {
        regs[7] += 8;
    } else {
        guest_check_return(regs[7], return_va);
        regs[7] += 8;
    }
    return result;
}

struct guest_qsort_context {
    uint64_t guest_base;
    uintptr_t host_base;
    void (*target_fn)(void *, uint64_t);
};

static int guest_qsort_thunk(void *thunk, const void *a, const void *b) {
    struct guest_qsort_context *ctx = (struct guest_qsort_context *)thunk;
    if (!current_cpu || !ctx->target_fn) return 0;

    uint64_t guest_a = ctx->guest_base + ((uintptr_t)a - ctx->host_base);
    uint64_t guest_b = ctx->guest_base + ((uintptr_t)b - ctx->host_base);

    uint64_t saved_cpu[128];
    memcpy(saved_cpu, current_cpu, sizeof(saved_cpu));

    uint64_t *regs = (uint64_t *)current_cpu;
    regs[1] = guest_a;
    regs[2] = guest_b;
    regs[7] -= 40;
    guest_store(regs[7], 0, 8);

    ctx->target_fn(current_cpu, 0);

    int res = (int)(int32_t)regs[0];
    memcpy(current_cpu, saved_cpu, sizeof(saved_cpu));
    return res;
}

uint64_t guest_qsort(uint64_t base, uint64_t num, uint64_t width, uint64_t compar) {
    if (!base || num <= 1 || !width || !compar) return 0;
    void (*fn)(void *, uint64_t) = guest_lookup_dispatch(compar);
    if (!fn) {
        fprintf(stderr, "[WARN] qsort compar function %#llx not found in dispatch table\n", (unsigned long long)compar);
        return 0;
    }
    const unsigned char *host_span = read_span(base, num * width);
    if (!host_span) return 0;
    struct guest_qsort_context ctx = {
        .guest_base = base,
        .host_base = (uintptr_t)host_span,
        .target_fn = fn
    };
    qsort_r((void *)host_span, (size_t)num, (size_t)width, &ctx, guest_qsort_thunk);
    return 0;
}

uint64_t guest_identity(uint32_t thread);

void guest_init_critical(uint64_t address, uint32_t spin_count) {
    /* Like Windows, give every section a zeroed RTL_CRITICAL_SECTION_DEBUG
       block; Wine's CRT writes DebugInfo->Spare[0] right after initializing. */
    guest_store(address, guest_heap_alloc(0x7fff2001, 8, 0x30), 8);
    guest_store(address + 8, UINT32_MAX, 8);
    guest_store(address + 16, 0, 8);
    guest_store(address + 24, 0, 8);
    guest_store(address + 32, spin_count, 8);
}

static int win32_to_posix_prot(uint32_t win_prot) {
    switch (win_prot & 0xff) {
        case 0x01:
            return PROT_NONE;
        case 0x02:
            return PROT_READ;
        case 0x04:
        case 0x08:
            return PROT_READ | PROT_WRITE;
        case 0x10:
            return PROT_EXEC;
        case 0x20:
            return PROT_EXEC | PROT_READ;
        case 0x40:
        case 0x80:
            return PROT_EXEC | PROT_READ | PROT_WRITE;
        default:
            return PROT_READ | PROT_WRITE;
    }
}

uint64_t guest_virtual_protect(uint64_t address, uint64_t size, uint32_t new_protect, uint64_t old_protect_ptr) {
    uint32_t region_old;
    bool region_ok;
    if (subsys_vm_protect(address, size, new_protect, &region_old, &region_ok)) {
        if (region_ok && old_protect_ptr)
            guest_store(old_protect_ptr, region_old, 4);
        return region_ok;
    }
    if (guest_image_base && address >= guest_image_base && address - guest_image_base < guest_image_span)
        address -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *section = &guest_sections[i];
        if (address >= section->address && address < section->address + section->size) {
            uint32_t old = section_protection ? section_protection[i] : (section->writable ? 0x04 : 0x02);
            if (section_protection)
                section_protection[i] = new_protect;
            int prot = win32_to_posix_prot(new_protect);
            uint64_t section_end = section->address + section->size;
            uint64_t range_end = size < section_end - address ? address + size : section_end;
            uint64_t first = address >> 12, end = (range_end + 0xfff) >> 12;
            if (end > image_prot_pages)
                end = image_prot_pages;
            for (uint64_t page = first; page < end; ++page)
                image_prot[page] = (uint8_t)prot;
            /* Host pages are larger than guest pages: each gets the union of its guest pages. */
            uint64_t scale = (uint64_t)sysconf(_SC_PAGESIZE) >> 12;
            if (!scale)
                scale = 1;
            for (uint64_t host = first / scale; host * scale < end; ++host) {
                int all = 0;
                for (uint64_t page = host * scale; page < (host + 1) * scale && page < image_prot_pages; ++page)
                    all |= image_prot[page];
                mprotect(image[0] - guest_sections[0].address + (host * scale << 12), scale << 12, all);
            }
            for (uint64_t j = 0; j < guest_section_count; ++j)
                image_update_fast(j, guest_sections[j].writable);
            if (old_protect_ptr)
                guest_store(old_protect_ptr, old, 4);
            return 1;
        }
    }
    if (old_protect_ptr)
        guest_store(old_protect_ptr, 0x04, 4);
    return 1;
}

/*
 * Critical sections are real locks: the owner field (OwningThread) is claimed
 * with a compare-and-swap, so the uncontended path takes no host lock. A
 * thread that finds the section owned waits on one shared condition, which a
 * leaving owner signals only when some thread is waiting.
 */
static pthread_mutex_t critical_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t critical_released = PTHREAD_COND_INITIALIZER;
static atomic_uint critical_waiters;

static _Atomic uint64_t *critical_owner(uint64_t address) {
    /* Sections live in writable guest memory (data, heap or stack). */
    return (_Atomic uint64_t *)(uintptr_t)read_span(address + 16, 8);
}

static void critical_enter_owned(uint64_t address) {
    uint64_t depth = guest_load(address + 12, 4);
    if (depth == UINT32_MAX)
        guest_trap("unsupported critical section ownership state");
    guest_store(address + 8, depth, 4);
    guest_store(address + 12, depth + 1, 4);
}

/* TryEnterCriticalSection: take the section unless another thread owns it. */
static bool guest_try_critical_section(uint64_t address) {
    _Atomic uint64_t *owner = critical_owner(address);
    uint64_t thread = guest_identity(1), expected = 0;
    if (atomic_load(owner) != thread && !atomic_compare_exchange_strong(owner, &expected, thread))
        return false;
    critical_enter_owned(address);
    return true;
}

void guest_critical_section(uint64_t address, uint32_t entering) {
    if (entering == 2) {
        if (guest_load(address + 12, 4) || guest_load(address + 16, 8))
            guest_trap("cannot delete an owned critical section");
        guest_heap_free(0x7fff2001, 0, guest_load(address, 8));
        for (unsigned offset = 0; offset < 40; offset += 8)
            guest_store(address + offset, 0, 8);
        return;
    }
    _Atomic uint64_t *owner = critical_owner(address);
    uint64_t thread = guest_identity(1);
    if (entering) {
        uint64_t expected = 0;
        if (atomic_load(owner) != thread && !atomic_compare_exchange_strong(owner, &expected, thread)) {
            /* Owned by another thread: wait for it to leave. */
            pthread_mutex_lock(&critical_wait_lock);
            atomic_fetch_add(&critical_waiters, 1);
            for (expected = 0; !atomic_compare_exchange_strong(owner, &expected, thread); expected = 0)
                pthread_cond_wait(&critical_released, &critical_wait_lock);
            atomic_fetch_sub(&critical_waiters, 1);
            pthread_mutex_unlock(&critical_wait_lock);
        }
        critical_enter_owned(address);
        return;
    }
    uint64_t depth = guest_load(address + 12, 4);
    if (atomic_load(owner) != thread || !depth)
        guest_trap("unsupported critical section ownership state");
    --depth;
    guest_store(address + 8, depth - 1, 4);
    guest_store(address + 12, depth, 4);
    if (!depth) {
        atomic_store(owner, 0);
        if (atomic_load(&critical_waiters)) {
            pthread_mutex_lock(&critical_wait_lock);
            pthread_cond_broadcast(&critical_released);
            pthread_mutex_unlock(&critical_wait_lock);
        }
    }
}

void guest_check_return(uint64_t addr, uint64_t expected) {
    uint64_t actual = guest_load(addr, 8);
    if (actual != expected) {
        fputs("guest return address mismatch\n", stderr);
        fprintf(stderr, "actual %#llx != expected %#llx at rsp %#llx, last traced RVA %#llx\n",
                (unsigned long long)actual, (unsigned long long)expected, (unsigned long long)addr,
                (unsigned long long)guest_pc);
        exit(125);
    }
}

uint64_t guest_identity(uint32_t thread) {
    if (wine_hosted) /* the ids wineserver assigned: TEB->ClientId */
        return *(uint64_t *)(void *)(teb + (thread ? 0x48 : 0x40));
    if (!thread)
        return (uint32_t)getpid();
    uint64_t id;
    if (pthread_threadid_np(NULL, &id) != 0)
        fault();
    return (uint32_t)id;
}

uint64_t guest_performance_counter(uint64_t address) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    guest_store(address, (uint64_t)now.tv_sec * UINT64_C(1000000000)
                         + (uint64_t)now.tv_nsec, 8);
    return 1;
}

void guest_system_filetime(uint64_t address) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        fault();
    uint64_t ticks = (UINT64_C(11644473600) + (uint64_t)now.tv_sec) * UINT64_C(10000000)
                     + (uint64_t)now.tv_nsec / 100;
    guest_store(address, ticks, 8);
}

void guest_set_last_error(uint32_t value) {
    last_error = value;
}

uint64_t guest_get_last_error(void) {
    return last_error;
}

uint64_t guest_tick_count_64(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

uint64_t guest_tick_count(void) {
    return (uint32_t)guest_tick_count_64();
}

uint64_t guest_performance_frequency(uint64_t address) {
    if (address)
        guest_store(address, UINT64_C(1000000000), 8);
    return 1;
}

uint64_t guest_is_processor_feature_present(uint32_t feature) {
    if (feature == 6 || feature == 10 || feature == 13 || feature == 2 || feature == 14 || feature == 25)
        return 1;
    return 0;
}

uint64_t guest_unhandled_exception_filter(uint64_t info) {
    (void)info;
    return 0;
}

uint64_t guest_terminate_process(uint64_t handle, uint32_t exit_code) {
    (void)handle;
    exit((int)exit_code);
}

static void capture_guest_context(uint64_t ctx, uint64_t pc, uint64_t rsp) {
    guest_memset(ctx, 0, 0x4d0);
    const uint64_t *cpu = current_cpu;
    if (!cpu)
        return;
    guest_store(ctx + 0x30, 0x10000b, 4);
    uint32_t flags = 2 | ((cpu[48] & 1) << 6) | (cpu[49] & 1) |
                     ((cpu[51] & 1) << 11) | ((cpu[52] & 1) << 7);
    guest_store(ctx + 0x44, flags, 4);
    for (unsigned i = 0; i < 16; ++i)
        guest_store(ctx + 0x78 + i * 8, i == 4 ? rsp : cpu[x86_register_slots[i]], 8);
    guest_store(ctx + 0xf8, pc, 8);
    for (unsigned i = 0; i < 32; ++i)
        guest_store(ctx + 0x1a0 + i * 8, cpu[16 + i], 8);
}

void guest_rtl_capture_context(uint64_t ctx) {
    if (ctx)
        capture_guest_context(ctx, guest_pc, current_cpu ? ((uint64_t *)current_cpu)[7] : 0);
}



static void restore_guest_context(uint64_t *cpu, uint64_t context) {
    init_guest_cpu(cpu);
    for (unsigned i = 0; i < 16; ++i)
        cpu[x86_register_slots[i]] = guest_load(context + 0x78 + i * 8, 8);
    for (unsigned i = 0; i < 32; ++i)
        cpu[16 + i] = guest_load(context + 0x1a0 + i * 8, 8);
    uint64_t flags = guest_load(context + 0x44, 4);
    cpu[48] = (flags >> 6) & 1;
    cpu[49] = flags & 1;
    cpu[51] = (flags >> 11) & 1;
    cpu[52] = (flags >> 7) & 1;
    cpu[50] = cpu[51] ^ cpu[52];
}

static uint64_t invoke_unwind_callback(uint64_t context, uint64_t stack, uint64_t target,
                                       uint64_t first, uint64_t second, uint64_t third,
                                       uint64_t fourth) {
    uint64_t cpu[128] = {0};
    restore_guest_context(cpu, context);
    cpu[1] = first;
    cpu[2] = second;
    cpu[3] = third;
    cpu[4] = fourth;
    cpu[7] = (stack & ~UINT64_C(15)) - 40;
    guest_store(cpu[7], 0, 8);
    void *previous = current_cpu;
    jmp_buf boundary;
    jmp_buf *previous_boundary = guest_resume_boundary;
    guest_resume_boundary = &boundary;
    uint64_t result = setjmp(boundary) ? resume_guest() :
                                       guest_indirect_dispatch(cpu, target, 0, 0);
    guest_resume_boundary = previous_boundary;
    current_cpu = previous;
    return result;
}

static _Thread_local uint64_t active_search_context;

void guest_rtl_unwind_ex(uint64_t target_frame, uint64_t target_ip, uint64_t record,
                         uint64_t value, uint64_t context, uint64_t history,
                         uint64_t start_pc, uint64_t start_rsp) {
    if (!context || !record || !target_frame || !guest_resume_boundary)
        guest_trap("RtlUnwindEx requires a target frame, record, context and resume boundary");
    if (active_search_context) {
        guest_memcpy(context, active_search_context, 0x4d0);
        start_pc = guest_load(context + 0xf8, 8);
    } else {
        capture_guest_context(context, start_pc, start_rsp);
    }
    uint64_t scratch = guest_heap_alloc(0x7fff2001, 8, 0x540);
    if (!scratch)
        guest_trap("cannot allocate unwind dispatcher context");
    uint64_t base_slot = scratch + 0x4d0, frame_slot = base_slot + 8;
    uint64_t data_slot = frame_slot + 8, dispatcher = data_slot + 8;
    uint32_t flags = (uint32_t)guest_load(record + 4, 4) | 2;
    bool reached = false;
    uint64_t pc = start_pc;
    for (unsigned depth = 0; depth < 128 && pc; ++depth) {
        uint64_t rsp = guest_load(context + 0x98, 8);
        if (rsp > target_frame)
            break;
        uint64_t entry = guest_rtl_lookup_function_entry(pc, base_slot, history);
        guest_memcpy(scratch, context, 0x4d0);
        uint64_t frame = rsp, handler = 0, base = 0;
        if (entry) {
            base = guest_load(base_slot, 8);
            handler = guest_rtl_virtual_unwind(2, base, pc, entry, scratch, data_slot, frame_slot, 0);
            frame = guest_load(frame_slot, 8);
        } else {
            uint64_t rva = pc >= guest_image_base ? pc - guest_image_base : pc;
            if (!guest_code_contains(rva, 1))
                break;
            guest_store(scratch + 0xf8, guest_load(rsp, 8), 8);
            guest_store(scratch + 0x98, rsp + 8, 8);
        }
        if (frame > target_frame)
            break;
        reached = frame == target_frame;
        guest_store(record + 4, flags | (reached ? 0x20 : 0), 4);
        if (getenv("GUEST_TRACE_SEH"))
            fprintf(stderr, "unwind pc=%#llx frame=%#llx handler=%#llx\n",
                    (unsigned long long)pc, (unsigned long long)frame, (unsigned long long)handler);
        if (handler) {
            uint64_t fields[] = {pc, base, entry, frame, target_ip, scratch, handler,
                                 guest_load(data_slot, 8), history, 0};
            for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i)
                guest_store(dispatcher + i * 8, fields[i], 8);
            if ((uint32_t)invoke_unwind_callback(context, start_rsp, handler, record, frame,
                                                 context, dispatcher) != 1)
                guest_trap("unsupported unwind handler disposition");
        }
        if (reached)
            break;
        uint64_t next_pc = guest_load(scratch + 0xf8, 8);
        if (guest_load(scratch + 0x98, 8) <= rsp || next_pc == pc)
            break;
        guest_memcpy(context, scratch, 0x4d0);
        pc = next_pc;
    }
    guest_heap_free(0x7fff2001, 0, scratch);
    if (!reached) {
        fprintf(stderr, "target=%#llx start_pc=%#llx start_rsp=%#llx last_pc=%#llx\n", (unsigned long long)target_frame,(unsigned long long)start_pc,(unsigned long long)start_rsp,(unsigned long long)pc);
        guest_trap("RtlUnwindEx could not reach target frame");
    }
    if (guest_load(record, 4) == 0x80000029) {
        if (!guest_load(record + 24, 4))
            guest_trap("missing unwind consolidation callback");
        uint64_t callback = guest_load(record + 32, 8);
        target_ip = invoke_unwind_callback(context, start_rsp,
                                            callback, record, 0, 0, 0);
    }
    if (!target_ip)
        guest_trap("missing unwind continuation");
    guest_store(context + 0xf8, target_ip, 8);
    guest_store(context + 0x78, value, 8);
    restore_guest_context(resume_cpu, context);
    resume_pc = target_ip < guest_image_base && guest_code_contains(target_ip, 1)
                    ? guest_image_base + target_ip : target_ip;
    active_search_context = 0;
    delivering_fault = false;
    longjmp(*guest_resume_boundary, 1);
}

/* Search AMD64 language handlers for a continuable software exception. */
static bool search_exception_frames(uint64_t record, uint64_t context, uint64_t pc,
                                    uint64_t rsp, const uint64_t *original_cpu) {
    uint64_t scratch = guest_heap_alloc(0x7fff2001, 8, 0x540);
    if (!scratch)
        guest_trap("cannot allocate exception dispatcher context");
    uint64_t base_slot = scratch + 0x4d0, frame_slot = base_slot + 8;
    uint64_t data_slot = frame_slot + 8, dispatcher = data_slot + 8;
    guest_memcpy(scratch, context, 0x4d0);
    void *saved_cpu = current_cpu;
    bool handled = false;
    bool trace = getenv("GUEST_TRACE_SEH") != NULL;
    for (unsigned depth = 0; depth < 128 && pc; ++depth) {
        uint64_t entry = guest_rtl_lookup_function_entry(pc, base_slot, 0);
        uint64_t frame_rsp = guest_load(scratch + 0x98, 8);
        if (trace) fprintf(stderr, "SEH pc=%#llx rsp=%#llx entry=%#llx\n", (unsigned long long)pc, (unsigned long long)frame_rsp, (unsigned long long)entry);
        if (!entry) {
            uint64_t rva = pc >= guest_image_base ? pc - guest_image_base : pc;
            if (!guest_code_contains(rva, 1))
                break;
            guest_store(scratch + 0xf8, guest_load(frame_rsp, 8), 8);
            guest_store(scratch + 0x98, frame_rsp + 8, 8);
        } else {
            uint64_t base = guest_load(base_slot, 8);
            uint64_t handler = guest_rtl_virtual_unwind(1, base, pc, entry, scratch,
                                                       data_slot, frame_slot, 0);
            if (trace) fprintf(stderr, "SEH handler=%#llx\n", (unsigned long long)handler);
            if (handler) {
                uint64_t frame = guest_load(frame_slot, 8);
                uint64_t fields[] = {pc, base, entry, frame, 0, scratch, handler,
                                     guest_load(data_slot, 8), 0, 0};
                for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i)
                    guest_store(dispatcher + i * 8, fields[i], 8);
                uint64_t callback[128];
                memcpy(callback, original_cpu, sizeof callback);
                init_guest_cpu(callback);
                callback[1] = record;
                callback[2] = frame;
                callback[3] = context;
                callback[4] = dispatcher;
                callback[7] = (rsp & ~UINT64_C(15)) - 40;
                guest_store(callback[7], 0, 8);
                uint64_t previous_context = active_search_context;
                active_search_context = context;
                guest_indirect_dispatch(callback, handler, 0, 0);
                active_search_context = previous_context;
                current_cpu = saved_cpu;
                uint32_t disposition = (uint32_t)callback[0];
                if (trace) fprintf(stderr, "SEH disposition=%u\n", disposition);
                if (disposition == 0) {
                    handled = !(guest_load(record + 4, 4) & 1);
                    break;
                }
                if (disposition != 1)
                    break;
            }
        }
        uint64_t next = guest_load(scratch + 0xf8, 8);
        if (guest_load(scratch + 0x98, 8) <= frame_rsp || next == pc)
            break;
        pc = next;
    }
    guest_heap_free(0x7fff2001, 0, scratch);
    return handled;
}

static void dispatch_guest_exception(uint32_t code, uint32_t flags, uint32_t count,
                           const uint64_t *arguments, uint64_t pc, uint64_t rsp, bool faulting) {
    uint64_t original_cpu[128];
    uint64_t *saved = current_cpu;
    if (!saved)
        guest_trap("RaiseException requires a guest context");
    memcpy(original_cpu, saved, sizeof original_cpu);
    uint64_t addresses[64];
    pthread_mutex_lock(&vectored_lock);
    size_t handlers = vectored_count;
    for (size_t i = 0; i < handlers; ++i)
        addresses[i] = vectored[i].address;
    pthread_mutex_unlock(&vectored_lock);

    uint64_t record = guest_heap_alloc(0x7fff2001, 8, 0x580);
    if (!record)
        guest_trap("cannot allocate guest exception record");
    uint64_t context = record + 0xa0, info = record + 0x570;
    capture_guest_context(context, pc, rsp);
    if (count > 15)
        count = 15;
    guest_store(record, code, 4);
    guest_store(record + 4, flags & 1, 4);
    guest_store(record + 16, pc, 8);
    guest_store(record + 24, count, 4);
    for (uint32_t i = 0; i < count; ++i)
        guest_store(record + 32 + i * 8, arguments[i], 8);
    guest_store(info, record, 8);
    guest_store(info + 8, context, 8);
    bool continued = false;
    for (size_t i = 0; i < handlers; ++i) {
        uint64_t callback[128];
        memcpy(callback, original_cpu, sizeof callback);
        callback[1] = info;
        callback[7] = (rsp & ~UINT64_C(15)) - 40;
        init_guest_cpu(callback);
        guest_store(callback[7], 0, 8);
        guest_indirect_dispatch(callback, addresses[i], 0, 0);
        current_cpu = saved;
        if ((uint32_t)callback[0] == UINT32_MAX && !(flags & 1)) {
            continued = true;
            break;
        }
    }
    if (!continued)
        continued = search_exception_frames(record, context, pc, rsp, original_cpu);
    if (continued) {
        uint64_t next = guest_load(context + 0xf8, 8);
        uint64_t next_rsp = guest_load(context + 0x98, 8);
        if (!faulting && next == pc && next_rsp == rsp) {
            guest_heap_free(0x7fff2001, 0, record);
            return;
        }
        if (guest_resume_boundary && next && (next != pc || next_rsp != rsp)) {
            restore_guest_context(resume_cpu, context);
            resume_pc = next < guest_image_base && guest_code_contains(next, 1)
                            ? guest_image_base + next : next;
            guest_heap_free(0x7fff2001, 0, record);
            delivering_fault = false;
            longjmp(*guest_resume_boundary, 1);
        }
    }
    if (code == 0x80000100 && guest_load(record + 24, 4) >= 2) {
        /* EXCEPTION_WINE_STUB: a Wine DLL export that is declared but not implemented. */
        char names[2][96];
        for (int i = 0; i < 2; ++i) {
            uint64_t text = guest_load(record + 32 + i * 8, 8);
            size_t n = 0;
            if (text >> 16) /* a name; otherwise an ordinal */
                for (uint64_t c; n < sizeof names[i] - 1 && (c = guest_load(text + n, 1)); ++n)
                    names[i][n] = c >= 32 && c < 127 ? (char)c : '?';
            else
                n = (size_t)snprintf(names[i], sizeof names[i], "#%llu", (unsigned long long)text);
            names[i][n] = 0;
        }
        fprintf(stderr, "Call to unimplemented Wine function %s.%s\n", names[0], names[1]);
    }
    guest_heap_free(0x7fff2001, 0, record);
    fprintf(stderr, "Unhandled guest exception 0x%08x at %#llx\n", code, (unsigned long long)pc);
    exit(125);
}

void guest_raise_exception(uint32_t code, uint32_t flags, uint32_t count,
                           uint64_t arguments, uint64_t pc, uint64_t rsp) {
    uint64_t values[15];
    if (count > 15)
        count = 15;
    for (uint32_t i = 0; i < count; ++i)
        values[i] = guest_load(arguments + i * 8, 8);
    dispatch_guest_exception(code, flags, count, values, pc, rsp, false);
}

static void guest_access_violation(uint64_t address, bool writing) {
    uint64_t arguments[] = {writing, address};
    delivering_fault = true;
    dispatch_guest_exception(0xc0000005, 0, 2, arguments, guest_fault_pc,
                             ((uint64_t *)current_cpu)[7], true);
    guest_trap("access violation did not transfer control");
}

__attribute__((weak)) const uint64_t guest_exception_rva = 0;
__attribute__((weak)) const uint64_t guest_exception_size = 0;

static uint64_t lookup_unwind_entry(uint64_t pc, uint64_t base, uint64_t table,
                                    uint64_t size, uint64_t image_base_ptr) {
    uint64_t low = 0, high = size / 12;
    while (low < high) {
        uint64_t mid = low + (high - low) / 2;
        uint64_t entry = table + mid * 12;
        uint64_t start = guest_load(entry, 4), end = guest_load(entry + 4, 4);
        if (pc < start)
            high = mid;
        else if (pc >= end)
            low = mid + 1;
        else {
            if (image_base_ptr)
                guest_store(image_base_ptr, base, 8);
            return entry;
        }
    }
    return 0;
}

static uint64_t lookup_module_unwind(const struct guest_module *module, uint64_t pc,
                                     uint64_t image_base_ptr) {
    if (!module->references || !fits(pc, 1, module->base, module->size) ||
        !fits(module->exception_rva, module->exception_size, 0, module->size))
        return 0;
    return lookup_unwind_entry(pc - module->base, module->base,
                               module->base + module->exception_rva,
                               module->exception_size, image_base_ptr);
}

uint64_t guest_rtl_lookup_function_entry(uint64_t pc, uint64_t image_base_ptr, uint64_t history_table) {
    (void)history_table;
    for (size_t i = 0; i < guest_module_count; ++i) {
        uint64_t entry = lookup_module_unwind(&guest_modules[i], pc, image_base_ptr);
        if (entry)
            return entry;
    }
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next) {
        uint64_t entry = lookup_module_unwind(item->module, pc, image_base_ptr);
        if (entry)
            return entry;
    }
    if (pc >= guest_image_base)
        pc -= guest_image_base;
    return lookup_unwind_entry(pc, guest_image_base, guest_image_base + guest_exception_rva,
                               guest_exception_size, image_base_ptr);
}

/* AMD64 CONTEXT offsets for RAX through R15 in Windows register order. */
static uint64_t unwind_register(uint64_t context, unsigned reg) {
    return context + 0x78 + reg * 8;
}

/* Recognize an ADD RSP / POP / RET epilogue before mutating the context. */
static bool unwind_return_epilogue(uint64_t pc, uint64_t end, uint64_t ctx,
                                   uint64_t pointers, uint64_t *rsp) {
    uint64_t cursor = pc, adjustment = 0;
    if (end - cursor >= 4 && guest_load(cursor, 1) == 0x48 &&
        guest_load(cursor + 2, 1) == 0xc4) {
        uint64_t opcode = guest_load(cursor + 1, 1);
        if (opcode == 0x83) {
            adjustment = guest_load(cursor + 3, 1);
            if (adjustment > INT8_MAX)
                return false;
            cursor += 4;
        } else if (opcode == 0x81 && end - cursor >= 7) {
            adjustment = guest_load(cursor + 3, 4);
            if (adjustment > INT32_MAX)
                return false;
            cursor += 7;
        }
    }
    unsigned registers[16], count = 0;
    while (cursor < end && count < 16) {
        unsigned opcode = (unsigned)guest_load(cursor++, 1);
        if (opcode == 0xc3) {
            *rsp += adjustment;
            for (unsigned i = 0; i < count; ++i) {
                unsigned reg = registers[i];
                guest_store(unwind_register(ctx, reg), guest_load(*rsp, 8), 8);
                if (pointers)
                    guest_store(pointers + 128 + reg * 8, *rsp, 8);
                *rsp += 8;
            }
            return true;
        }
        unsigned extension = 0;
        if (opcode == 0x41 && cursor < end) {
            extension = 8;
            opcode = (unsigned)guest_load(cursor++, 1);
        }
        if (opcode < 0x58 || opcode > 0x5f)
            return false;
        unsigned reg = opcode - 0x58 + extension;
        if (reg != 3 && reg != 5 && reg != 6 && reg != 7 && reg < 12)
            return false;
        registers[count++] = reg;
    }
    return false;
}

uint64_t guest_rtl_virtual_unwind(uint32_t handler_type, uint64_t image_base, uint64_t control_pc,
                                  uint64_t entry, uint64_t ctx, uint64_t data, uint64_t frame, uint64_t pointers) {
    if (!ctx || !entry)
        return 0;

    uint32_t begin = (uint32_t)guest_load(entry, 4);
    uint32_t end = (uint32_t)guest_load(entry + 4, 4);
    if (control_pc < image_base + begin || control_pc >= image_base + end)
        guest_trap("control PC is outside the unwind function");
    uint64_t offset = control_pc - (image_base + begin);
    uint64_t rsp = guest_load(unwind_register(ctx, 4), 8);
    uint64_t establisher = rsp;
    bool in_prolog = false, machine_frame = false;
    uint64_t machine_pc = 0;
    uint64_t handler = 0;
    unsigned flags = 0;
    for (unsigned depth = 0;; ++depth) {
        if (depth == 32)
            guest_trap("AMD64 unwind chain exceeds nesting limit");
        uint64_t info = image_base + guest_load(entry + 8, 4);
        unsigned header = (unsigned)guest_load(info, 1);
        flags = header >> 3;
        if ((header & 7) != 1 || (flags & ~7u) || ((flags & 4) && (flags & 3)))
            guest_trap("unsupported AMD64 unwind header");

        unsigned prolog = (unsigned)guest_load(info + 1, 1);
        unsigned count = (unsigned)guest_load(info + 2, 1);
        unsigned frame_spec = (unsigned)guest_load(info + 3, 1);
        if (!depth) {
            in_prolog = offset < prolog;
            if ((frame_spec & 15) && !in_prolog)
                establisher = guest_load(unwind_register(ctx, frame_spec & 15), 8)
                              - (frame_spec >> 4) * 16;
        }
        if (!depth && !in_prolog &&
            unwind_return_epilogue(control_pc, image_base + end, ctx, pointers, &rsp)) {
            flags = 0;
            break;
        }
        uint64_t codes = info + 4;
        for (unsigned i = 0; i < count;) {
            unsigned instruction = (unsigned)guest_load(codes + i * 2, 1);
            unsigned byte = (unsigned)guest_load(codes + i * 2 + 1, 1);
            unsigned operation = byte & 15, reg = byte >> 4;
            unsigned extra = 0, scale = 1;
            switch (operation) {
            case 0: case 2: case 3: break;
            case 10:
                if (reg > 1)
                    guest_trap("invalid UWOP_PUSH_MACHFRAME encoding");
                break;
            case 1:
                if (reg > 1)
                    guest_trap("invalid UWOP_ALLOC_LARGE encoding");
                extra = reg ? 2 : 1;
                scale = reg ? 1 : 8;
                break;
            case 4: extra = 1; scale = 8; break;
            case 5: case 9: extra = 2; break;
            case 8: extra = 1; scale = 16; break;
            default: guest_trap("unsupported AMD64 unwind opcode");
            }
            if (extra >= count - i)
                guest_trap("truncated AMD64 unwind opcode");
            uint64_t amount = extra ? guest_load(codes + (i + 1) * 2, extra * 2) * scale : 0;
            i += 1 + extra;
            if (offset < instruction)
                continue;

            if (operation == 10) {
                uint64_t machine = rsp + reg * 8;
                machine_pc = guest_load(machine, 8);
                guest_store(ctx + 0x38, guest_load(machine + 8, 2), 2);
                guest_store(ctx + 0x44, guest_load(machine + 16, 4), 4);
                guest_store(ctx + 0x42, guest_load(machine + 32, 2), 2);
                rsp = guest_load(machine + 24, 8);
                machine_frame = true;
            } else if (operation == 1 || operation == 2) {
                rsp += operation == 1 ? amount : reg * 8 + 8;
            } else if (operation == 3) {
                if (!(frame_spec & 15))
                    guest_trap("missing AMD64 unwind frame register");
                rsp = guest_load(unwind_register(ctx, frame_spec & 15), 8) - (frame_spec >> 4) * 16;
                establisher = rsp;
            } else if (operation == 8 || operation == 9) {
                uint64_t saved = rsp + amount;
                uint64_t xmm = ctx + 0x1a0 + reg * 16;
                guest_store(xmm, guest_load(saved, 8), 8);
                guest_store(xmm + 8, guest_load(saved + 8, 8), 8);
                if (pointers)
                    guest_store(pointers + reg * 8, saved, 8);
            } else {
                uint64_t saved = rsp + amount;
                guest_store(unwind_register(ctx, reg), guest_load(saved, 8), 8);
                if (pointers)
                    guest_store(pointers + 128 + reg * 8, saved, 8);
                if (operation == 0)
                    rsp += 8;
            }
        }
        handler = codes + ((count + 1) & ~1u) * 2;
        if (!(flags & 4))
            break;
        entry = handler;
        offset = UINT64_MAX;
    }
    guest_store(ctx + 0xf8, machine_frame ? machine_pc : guest_load(rsp, 8), 8);
    guest_store(unwind_register(ctx, 4), machine_frame ? rsp : rsp + 8, 8);
    if (frame)
        guest_store(frame, establisher, 8);
    bool has_handler = (flags & handler_type) && !in_prolog;
    if (data)
        guest_store(data, has_handler ? handler + 4 : 0, 8);
    return has_handler ? image_base + guest_load(handler, 4) : 0;
}

uint64_t guest_stdout(uint32_t selector) {
    if (selector == (uint32_t)-10) return 3;
    if (selector == (uint32_t)-11) return 1;
    if (selector == (uint32_t)-12) return 2;
    last_error = 87;
    return UINT64_MAX;
}

uint64_t guest_file_type(uint64_t handle) {
    struct stat info;
    if (handle < 1 || handle > 3 || fstat(handle == 3 ? 0 : (int)handle, &info) != 0) {
        last_error = 6;
        return 0;
    }
    last_error = 0;
    if (S_ISFIFO(info.st_mode) || S_ISSOCK(info.st_mode)) return 3;
    if (S_ISCHR(info.st_mode)) return 2;
    return S_ISREG(info.st_mode) ? 1 : 0;
}

uint64_t guest_write(uint64_t handle, uint64_t address, uint32_t count,
                     uint64_t written, uint64_t overlapped) {
    if (written && written != UINT64_MAX && written != 0xffffffff) guest_store(written, 0, 4);
    if (overlapped != 0) {
        last_error = 87;
        return 0;
    }
    int fd = -1;
    if (handle == 1 || handle == 2) {
        fd = (int)handle;
    } else {
        struct HandleEntry *e = get_handle(handle);
        if (e && e->kind == HANDLE_KIND_FILE && e->fd >= 0)
            fd = e->fd;
    }
    if (fd < 0) {
        last_error = 6;
        return 0;
    }
    ssize_t result = write(fd, read_span(address, count), count);
    if (result < 0) {
        last_error = 6;
        return 0;
    }
    if (written && written != UINT64_MAX && written != 0xffffffff) guest_store(written, (uint32_t)result, 4);
    last_error = 0;
    return 1;
}

uint64_t guest_get_handle_info(uint64_t handle, uint64_t flags_ptr) {
    if (handle == 0x10 || handle == 0x14 || handle == 0x18 || (handle >= 1 && handle <= 3) || get_handle(handle)) {
        if (flags_ptr)
            guest_store(flags_ptr, 0, 4);
        last_error = 0;
        return 1;
    }
    last_error = 6;
    return 0;
}

uint64_t guest_exception_filter(uint64_t handler) {
    static uint64_t current;
    uint64_t previous = current;
    current = handler;
    return previous;
}

uint64_t guest_environment(void) {
    static const char environment[] = "SystemRoot=C:\\Windows\0";
    uint64_t address = guest_heap_alloc(0x7fff2001, 0, sizeof environment * 2);
    if (address)
        for (size_t i = 0; i < sizeof environment; ++i)
            guest_store(address + 2 * i, (unsigned char)environment[i], 2);
    return address;
}

uint64_t guest_convert_text(uint32_t wide, uint32_t page, uint32_t flags,
                            uint64_t source, int32_t length, uint64_t dest, uint64_t size) {
    /* Every code page converts unit by unit, which is exact for ASCII text. */
    (void)flags;
    (void)page;
    if (length < -1 || length == 0 || size > INT32_MAX) {
        last_error = 87; /* ERROR_INVALID_PARAMETER, as Windows reports */
        return 0;
    }
    unsigned in_width = wide ? 1 : 2;
    unsigned out_width = wide ? 2 : 1;
    uint64_t count = 0;
    while (length == -1 || count < (uint32_t)length) {
        if (length == -1 && count == 16 * 1024 * 1024)
            guest_trap("unterminated Windows text conversion input");
        uint64_t unit = guest_load(source + count * in_width, in_width);
        ++count;
        if (!unit && length == -1)
            break;
    }
    if (size && size < count) {
        last_error = 122;
        return 0;
    }
    if (size)
        for (uint64_t i = 0; i < count; ++i) {
            uint64_t unit = guest_load(source + i * in_width, in_width);
            guest_store(dest + i * out_width, unit & (out_width == 1 ? 0xff : 0xffff), out_width);
        }
    return count;
}

uint64_t guest_system_directory(uint64_t buffer, uint32_t size, uint32_t wide) {
    static const char directory[] = "C:\\Windows\\System32";
    if (!buffer || size < sizeof directory)
        return sizeof directory;
    unsigned width = wide ? 2 : 1;
    for (size_t i = 0; i < sizeof directory; ++i)
        guest_store(buffer + i * width, (unsigned char)directory[i], width);
    return sizeof directory - 1;
}

uint64_t guest_module_filename(uint64_t module, uint64_t buffer, uint32_t size) {
    static const char name[] = "C:\\program.exe";
    if (module && module != guest_image_base) {
        last_error = 6;
        return 0;
    }
    if (!size) {
        last_error = 122;
        return 0;
    }
    size_t written = size < sizeof name ? size : sizeof name;
    for (size_t i = 0; i + 1 < written; ++i)
        guest_store(buffer + 2 * i, (unsigned char)name[i], 2);
    guest_store(buffer + 2 * (written - 1), 0, 2);
    if (written < sizeof name) {
        last_error = 122;
        return size;
    }
    return written - 1;
}

static uint64_t command_lines[2];

static void append_command_byte(char *line, size_t *length, unsigned char byte) {
    if (*length >= 32766 || byte >= 128)
        guest_trap("command line exceeds the ASCII startup subset");
    line[(*length)++] = (char)byte;
}

uint64_t guest_command_line(uint32_t wide) {
    if (command_lines[wide])
        return command_lines[wide];
    char line[32767];
    size_t length = 0;
    for (int i = 0; i < host_argc; ++i) {
        const char *p = i ? host_argv[i] : "program.exe";
        if (i)
            append_command_byte(line, &length, ' ');
        append_command_byte(line, &length, '"');
        while (*p) {
            size_t slashes = 0;
            while (*p == '\\') {
                ++slashes;
                ++p;
            }
            size_t copies = (*p == '"' || !*p) ? 2 * slashes : slashes;
            while (copies--)
                append_command_byte(line, &length, '\\');
            if (*p == '"')
                append_command_byte(line, &length, '\\');
            if (*p)
                append_command_byte(line, &length, *p++);
        }
        append_command_byte(line, &length, '"');
    }
    line[length] = 0;
    unsigned width = wide ? 2 : 1;
    uint64_t pointer = guest_heap_alloc(0x7fff2001, 0, (length + 1) * width);
    if (!pointer)
        guest_trap("command line allocation failed");
    for (size_t i = 0; i <= length; ++i)
        guest_store(pointer + i * width, (unsigned char)line[i], width);
    return command_lines[wide] = pointer;
}

/* Fill a UNICODE_STRING at field with a guest heap copy of an ASCII host string. */
static void put_unicode_string(uint64_t field, const char *text, size_t extra) {
    size_t length = strlen(text);
    uint64_t buffer = guest_heap_alloc(GUEST_HEAP_HANDLE, 8, (length + 1 + extra) * 2);
    for (size_t i = 0; buffer && i < length; ++i)
        guest_store(buffer + i * 2, (unsigned char)text[i], 2);
    guest_store(field, buffer ? length * 2 : 0, 2);
    guest_store(field + 2, buffer ? (length + 1 + extra) * 2 : 0, 2);
    guest_store(field + 8, buffer, 8);
}

/*
 * PEB->ProcessParameters (RTL_USER_PROCESS_PARAMETERS, normalized): Wine's
 * kernelbase reads the environment, command line, current directory and
 * standard handles from it rather than calling into the loader.
 */
static void init_process_parameters(void) {
    enum { SIZE = 0x410 };
    uint64_t params = guest_heap_alloc(GUEST_HEAP_HANDLE, 8, SIZE);
    if (!params)
        return;
    guest_store(params + 0x00, SIZE, 4);           /* MaximumLength */
    guest_store(params + 0x04, SIZE, 4);           /* Length */
    guest_store(params + 0x08, 1, 4);              /* PROCESS_PARAMS_FLAG_NORMALIZED */
    guest_store(params + 0x20, guest_stdout((uint32_t)-10), 8);
    guest_store(params + 0x28, guest_stdout((uint32_t)-11), 8);
    guest_store(params + 0x30, guest_stdout((uint32_t)-12), 8);
    char directory[1024] = "C:\\";
    char host[1024];
    if (getcwd(host, sizeof host)) {
        snprintf(directory, sizeof directory, "Z:%s\\", host);
        for (char *c = directory; *c; ++c)
            if (*c == '/')
                *c = '\\';
    }
    put_unicode_string(params + 0x38, directory, 260);   /* CurrentDirectory.DosPath */
    put_unicode_string(params + 0x50, "C:\\Windows\\System32;C:\\Windows", 0); /* DllPath */
    char image_path[1024];
    snprintf(image_path, sizeof image_path, "%s%s", directory,
             host_argc > 0 && host_argv[0] ? (strrchr(host_argv[0], '/') ? strrchr(host_argv[0], '/') + 1 : host_argv[0])
                                           : "app.exe");
    const char *hosted_program = wine_hosted ? getenv("ARM64_RECOMPILER_WINE_EXE") : NULL;
    char resolved[1024];
    if (wine_hosted && realpath(hosted_program ? hosted_program : host_argv[0], resolved)) {
        /* The original .exe, as Wine's Z: drive names it. */
        snprintf(image_path, sizeof image_path, "Z:%s", resolved);
        for (char *c = image_path; *c; ++c)
            if (*c == '/')
                *c = '\\';
    }
    put_unicode_string(params + 0x60, image_path, 0);     /* ImagePathName */
    /* CommandLine (wide). guest_command_line stops on non-ASCII arguments, so
       only build it eagerly when every argument is ASCII. */
    bool ascii = true;
    for (int i = 1; i < host_argc && ascii; ++i)
        for (const unsigned char *c = (const unsigned char *)host_argv[i]; *c && ascii; ++c)
            ascii = *c < 0x80;
    uint64_t line = ascii ? guest_command_line(1) : 0;
    uint64_t length = 0;
    while (line && guest_load(line + length * 2, 2))
        ++length;
    guest_store(params + 0x70, length * 2, 2);
    guest_store(params + 0x72, (length + 1) * 2, 2);
    guest_store(params + 0x78, line, 8);
    uint64_t environment = guest_environment();
    uint64_t units = 0;
    while (environment && (guest_load(environment + units * 2, 2) || guest_load(environment + units * 2 + 2, 2)))
        ++units;
    guest_store(params + 0x80, environment, 8);           /* Environment */
    put_unicode_string(params + 0xb0, image_path, 0);     /* WindowTitle */
    put_unicode_string(params + 0xc0, "", 0);             /* Desktop */
    put_unicode_string(params + 0xd0, "", 0);             /* ShellInfo */
    guest_store(params + 0x3f0, environment ? (units + 2) * 2 : 0, 8); /* EnvironmentSize */
    if (!wine_hosted) {
        put64(peb, 0x20, params);
    } else {
        /*
         * Hosted: Wine built the real process parameters, but for its start.exe
         * fallback (it could not map the program at its base, which the lifted
         * image occupies). Name the program and its command line correctly.
         */
        uint64_t wine_params = *(uint64_t *)(void *)(peb + 0x20);
        static const unsigned fields[] = {0x60, 0x70, 0xb0}; /* ImagePathName, CommandLine, WindowTitle */
        for (size_t i = 0; wine_params && i < sizeof fields / sizeof *fields; ++i)
            memcpy((void *)(uintptr_t)(wine_params + fields[i]), (const void *)(uintptr_t)(params + fields[i]), 16);
    }
    /* FastPebLock: RtlAcquirePebLock enters it around ProcessParameters updates. */
    uint64_t lock = guest_heap_alloc(GUEST_HEAP_HANDLE, 8, 40);
    if (lock) {
        guest_init_critical(lock, 0);
        put64(peb, 0x38, lock);
    }
    long processors = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t fields[][2] = {
        {0xb8, processors > 0 ? (uint32_t)processors : 1}, /* NumberOfProcessors */
        {0x118, 10}, {0x11c, 0}, {0x120, 19045}, {0x124, 2}, /* OS version: Windows 10 22H2 */
        {0x128, 3}, {0x12c, 6}, {0x130, 0},                  /* console subsystem 6.0 */
    };
    for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i)
        memcpy(peb + fields[i][0], &fields[i][1], 4);
}

/*
 * Claim every linked-in module's guest address range before the host
 * allocator can place anything there. The pages stay untouched until a load.
 */
static void reserve_guest_modules(void) {
    for (size_t i = 0; i < guest_module_count; ++i)
        if (!guest_map_fixed(guest_modules[i].base, guest_modules[i].size)) {
            fprintf(stderr, "cannot reserve guest address %#llx for %s\n",
                    (unsigned long long)guest_modules[i].base, guest_modules[i].name);
            exit(125);
        }
}

/*
 * Fill guest_modules from the shared libraries the program was built against.
 * Each is looked for in ARM64_RECOMPILER_MODULE_DIR, beside the program, in
 * ../Frameworks (an application bundle), then in the build's module store.
 */
extern int _NSGetExecutablePath(char *, uint32_t *); /* <mach-o/dyld.h> defines its own struct section */

static void load_module_libraries(void) {
    if (!guest_module_libraries)
        return;
    char program[PATH_MAX], folder[PATH_MAX] = "";
    uint32_t size = sizeof program;
    if (!_NSGetExecutablePath(program, &size) && realpath(program, folder)) {
        char *slash = strrchr(folder, '/');
        if (slash)
            *slash = 0;
    }
    char bundle[PATH_MAX + 16] = "";
    if (*folder)
        snprintf(bundle, sizeof bundle, "%s/../Frameworks", folder);
    const char *const folders[] = {getenv("ARM64_RECOMPILER_MODULE_DIR"), folder, bundle, guest_module_store};
    for (size_t i = 0; i < guest_module_count; ++i) {
        const char *name = guest_module_libraries[i];
        void *library = NULL;
        char reason[512] = "not found";
        for (size_t j = 0; !library && j < sizeof folders / sizeof *folders; ++j) {
            char path[PATH_MAX + 256];
            if (!folders[j] || !*folders[j])
                continue;
            snprintf(path, sizeof path, "%s/%s", folders[j], name);
            if (access(path, R_OK))
                continue;
            library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            if (!library)
                snprintf(reason, sizeof reason, "%s", dlerror());
        }
        const struct guest_module *module = library ? dlsym(library, "translated_guest_module") : NULL;
        if (!module) {
            fprintf(stderr, "cannot load lifted module %s: %s\n", name, reason);
            exit(125);
        }
        guest_modules[i] = *module;
    }
}

static int guest_run(void);
static int wine_host_boot(const char *directory, int argc, char **argv);

int main(int argc, char **argv) {
    const char *watch = getenv("GUEST_WATCH_RVA");
    if (watch && *watch) {
        char *end;
        uint64_t value = strtoull(watch, &end, 0);
        if (!*end)
            watched_rva = value;
    }
    host_argc = argc;
    host_argv = argv;
    trace_time("main", NULL);
    image = calloc(guest_section_count ? guest_section_count : 1, sizeof *image);
    section_protection = calloc(guest_section_count ? guest_section_count : 1, sizeof *section_protection);
    if (!image || !section_protection)
        fault();
    uint64_t image_size = 0;
    for (uint64_t i = 0; i < guest_section_count; ++i)
        if (guest_sections[i].address + guest_sections[i].size > image_size)
            image_size = guest_sections[i].address + guest_sections[i].size;
    if (!image_size)
        image_size = 1;
    unsigned char *mapping = guest_map_fixed(guest_image_base, image_size);
    load_module_libraries();
    reserve_guest_modules();
    if (!mapping) {
        fprintf(stderr, "cannot map the program image at guest address %#llx\n",
                (unsigned long long)guest_image_base);
        exit(125);
    }
    guest_image_span = image_size;
    guest_primary_base = guest_image_base;
    guest_primary_span = image_size;
    image_prot_pages = (image_size + 0xfff) >> 12;
    image_prot = malloc(image_prot_pages);
    if (!image_prot)
        fault();
    memset(image_prot, PROT_READ | PROT_WRITE, image_prot_pages);
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *section = &guest_sections[i];
        image[i] = mapping + section->address;
        section_protection[i] = section->writable ? 0x04 : 0x02;
        if (section->initial_size)
            memcpy(image[i], section->initial, section->initial_size);
        image_update_fast(i, section->writable);
    }
    for (uint64_t i = 0; i < guest_section_count && i < 64; ++i) {
        uint64_t end = (guest_sections[i].address + guest_sections[i].size + 0xfff) >> 12;
        if (end > image_page_limit && end <= (0x20000000 >> 12))
            image_page_limit = end;
    }
    image_page_section = calloc(image_page_limit ? image_page_limit : 1, 1);
    if (!image_page_section)
        fault();
    for (uint64_t i = guest_section_count < 64 ? guest_section_count : 64; i-- > 0;) {
        uint64_t first = guest_sections[i].address >> 12;
        uint64_t end = (guest_sections[i].address + guest_sections[i].size + 0xfff) >> 12;
        for (uint64_t page = first; page < end && page < image_page_limit; ++page)
            if (!image_page_section[page] || (guest_sections[i].address & 0xfff) == 0)
                image_page_section[page] = (uint8_t)(i + 1);
    }
    /* The image and module ranges are claimed; Wine may now place its own mappings. */
    const char *host = getenv("ARM64_RECOMPILER_WINE_HOST");
    if (host && *host)
        return wine_host_boot(host, argc, argv);
    return guest_run();
}

/*
 * Windows' ntdll sets up the PEB's TLS bitmaps at process start; the runtime
 * loader stands in for that code, and a lifted kernelbase.dll's TlsAlloc
 * allocates from them. RTL_BITMAP is { ULONG SizeOfBitMap; ULONG *Buffer }.
 */
static void init_peb_tls_bitmaps(void) {
    uint64_t bitmaps = guest_heap_alloc(GUEST_HEAP_HANDLE, 8, 32);
    if (!bitmaps)
        return;
    guest_store(bitmaps, 64, 4);
    guest_store(bitmaps + 8, PEB_BASE + 0x80, 8);     /* TlsBitmapBits */
    guest_store(bitmaps + 16, 1024, 4);
    guest_store(bitmaps + 24, PEB_BASE + 0x240, 8);   /* TlsExpansionBitmapBits */
    memset(peb + 0x80, 0, 8);
    memset(peb + 0x240, 0, 128);
    peb[0x80] = 1;                                    /* TLS index 0 is reserved */
    put64(peb, 0x78, bitmaps);
    put64(peb, 0x238, bitmaps + 16);
}

/* Process and main-thread setup, then the program's entry point. */
static int guest_run(void) {
    init_runtime_data();
    put64(peb, 0x10, guest_image_base);
    put64(peb, 0x30, 0x7fff2001); /* ProcessHeap, read directly by Wine's CRT */
    init_process_parameters();
    init_peb_tls_bitmaps();
    init_guest_thread_data();
    if (guest_tls_index_va) {
        uint64_t idx_addr = guest_tls_index_va;
        if (guest_image_base && idx_addr >= guest_image_base && idx_addr - guest_image_base < guest_image_span)
            idx_addr -= guest_image_base;
        for (uint64_t i = 0; i < guest_section_count; ++i) {
            const struct section *sec = &guest_sections[i];
            if (fits(idx_addr, 4, sec->address, sec->size)) {
                uint32_t zero = 0;
                memcpy(image[i] + (idx_addr - sec->address), &zero, 4);
                break;
            }
        }
    }
    jmp_buf boundary;
    guest_resume_boundary = &boundary;
    if (!setjmp(boundary)) {
        if (guest_fault_signals_enabled())
            init_guest_signal_handler();
        trace_time("entering program", NULL);
        return (int)lifted_console();
    }
    return (int)resume_guest();
}
