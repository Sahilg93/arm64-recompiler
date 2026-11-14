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
#include <spawn.h>
#include <sys/wait.h>
#include <errno.h>

#include "console_modules.h"
__attribute__((weak)) struct guest_module *guest_modules;
__attribute__((weak)) const size_t guest_module_count = 0;
extern const struct section guest_sections[];
extern const uint64_t guest_section_count;
static unsigned char **image;
static uint32_t *section_protection;
static _Thread_local void *current_cpu = NULL;
void guest_set_cpu(void *cpu) { current_cpu = cpu; }
#define GUEST_HEAP_TAG UINT64_C(0x1000000000000000)
extern const uint64_t guest_image_base;
extern uint32_t lifted_console(void);

void guest_init_critical(uint64_t address, uint32_t spin_count);
void guest_critical_section(uint64_t address, uint32_t entering);
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
    STACK_BASE = 0x2000000, STACK_SIZE = 1048576,
    TEB_BASE = 0x2101000, PEB_BASE = 0x2102000,
    IOBUF_BASE = 0x2103000, IOBUF_ENTRY_SIZE = 48, IOBUF_COUNT = 3,
    ERRNO_BASE = 0x2104000,
    RUNTIME_DATA_BASE = 0x2105000, RUNTIME_DATA_SIZE = 4096,
    ARGC_BASE = 0x2105000,
    ARGV_BASE = 0x2105010,
    WARGV_BASE = 0x2105020,
    FMODE_BASE = 0x2105030,
    COMMODE_BASE = 0x2105038,
    WENVIRON_BASE = 0x2105040,
    ENVIRON_BASE = 0x2105048,
    TLS_BASE = 0x2106000, TLS_SIZE = 1048576
};
static unsigned char stack[STACK_SIZE];
static bool initialized[STACK_SIZE];
static _Thread_local unsigned char teb[4096];
static unsigned char peb[4096];
static unsigned char iobuf[IOBUF_COUNT * IOBUF_ENTRY_SIZE];
static _Thread_local int guest_errno_storage;
static unsigned char runtime_data[RUNTIME_DATA_SIZE];
static _Thread_local unsigned char tls_storage[TLS_SIZE];

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
static _Thread_local uint32_t last_error;

static bool fits(uint64_t addr, uint64_t size, uint64_t start, uint64_t length) {
    return addr >= start && size <= length && addr - start <= length - size;
}

static _Thread_local uint64_t guest_pc, guest_fault_pc;
static _Thread_local bool delivering_fault;
static void guest_access_violation(uint64_t, bool);

void guest_mark_fault_pc(uint64_t address) {
    guest_fault_pc = address;
}
static uint64_t watched_rva = UINT64_MAX;

uint64_t guest_load(uint64_t addr, uint32_t width);
void guest_set_pc(uint64_t address) {
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

void guest_exit(uint32_t status) {
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
 * tagged heap block), the handler runs on the alternate stack, translates the
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

static void fault(void) {
    fprintf(stderr, "RVA %#llx: unsupported guest memory access\n", (unsigned long long)guest_pc);
    exit(125);
}

unsigned char *subsys_mapping_span(uint64_t addr, uint64_t size);

static inline unsigned char *heap_span(uint64_t address, uint64_t size) {
    (void)size;
    if ((address & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG)
        return (unsigned char *)(uintptr_t)(address & ~UINT64_C(0xFF00000000000000));
    return subsys_mapping_span(address, size);
}

uint64_t guest_heap_alloc(uint64_t handle, uint32_t flags, uint64_t size) {
    if (handle != 0x7fff2001 || (flags & ~8u))
        guest_trap("unsupported HeapAlloc handle or flags");
    if (!size)
        size = 1;
    void *data = (flags & 8u) ? calloc(size, 1) : malloc(size);
    if (!data)
        return 0;
    return GUEST_HEAP_TAG | (uint64_t)(uintptr_t)data;
}

uint64_t guest_heap_free(uint64_t handle, uint32_t flags, uint64_t address) {
    (void)handle; (void)flags;
    if (address && (address & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG) {
        free((void *)(uintptr_t)(address & ~UINT64_C(0xFF00000000000000)));
        return 1;
    }
    return 0;
}

uint64_t guest_heap_realloc(uint64_t handle, uint32_t flags, uint64_t address, uint64_t size) {
    if (!address)
        return guest_heap_alloc(handle, flags, size);
    if ((address & UINT64_C(0xFF00000000000000)) != GUEST_HEAP_TAG)
        return 0;
    void *old_ptr = (void *)(uintptr_t)(address & ~UINT64_C(0xFF00000000000000));
    void *new_ptr = realloc(old_ptr, size ? size : 1);
    if (!new_ptr)
        return 0;
    return GUEST_HEAP_TAG | (uint64_t)(uintptr_t)new_ptr;
}

struct translated_module {
    struct guest_module *module;
    struct translated_module *next;
};
static _Atomic(struct translated_module *) translated_modules;
static pthread_mutex_t module_translation_lock = PTHREAD_MUTEX_INITIALIZER;

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

static const unsigned char *read_span(uint64_t addr, uint64_t size) {
    uint64_t original = addr;
    if (!addr && guest_fault_pc && current_cpu && !delivering_fault)
        guest_access_violation(addr, false);
    if ((addr & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG)
        return (const unsigned char *)(uintptr_t)(addr & ~UINT64_C(0xFF00000000000000));
    if (fits(addr, size, STACK_BASE, STACK_SIZE)) {
        uint64_t offset = addr - STACK_BASE;
        return stack + offset;
    }
    if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < 0x20000000)
        addr -= guest_image_base;
    if (fits(addr, size, TEB_BASE, sizeof teb))
        return teb + (addr - TEB_BASE);
    if (fits(addr, size, PEB_BASE, sizeof peb))
        return peb + (addr - PEB_BASE);
    if (fits(addr, size, IOBUF_BASE, sizeof iobuf))
        return iobuf + (addr - IOBUF_BASE);
    if (fits(addr, size, ERRNO_BASE, sizeof guest_errno_storage))
        return (const unsigned char *)&guest_errno_storage + (addr - ERRNO_BASE);
    if (fits(addr, size, RUNTIME_DATA_BASE, sizeof runtime_data))
        return runtime_data + (addr - RUNTIME_DATA_BASE);
    if (fits(addr, size, TEB_BASE, sizeof teb))
        return teb + (addr - TEB_BASE);
    if (fits(addr, size, PEB_BASE, sizeof peb))
        return peb + (addr - PEB_BASE);
    if (fits(addr, size, TLS_BASE, sizeof tls_storage))
        return tls_storage + (addr - TLS_BASE);
    for (uint64_t i = 0; i < guest_section_count; ++i)
        if (fits(addr, size, guest_sections[i].address, guest_sections[i].size))
            return image[i] + (addr - guest_sections[i].address);
    unsigned char *module = module_span(addr, size, false);
    if (module)
        return module;
    unsigned char *heap = heap_span(addr, size);
    if (heap)
        return heap;
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
    if (guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
        guest_faultable_copy(&value, source, width, addr, false);
    else
        memcpy(&value, source, width);
    return value;
}

__attribute__((always_inline)) uint64_t guest_load(uint64_t addr, uint32_t width) {
    if ((addr & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG) {
        uint64_t val = 0;
        const void *source = (const void *)(uintptr_t)(addr & ~UINT64_C(0xFF00000000000000));
        if (guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
            guest_faultable_copy(&val, source, width, addr, false);
        else
            memcpy(&val, source, width);
        return val;
    }
    if (fits(addr, width, STACK_BASE, STACK_SIZE)) {
        uint64_t val = 0;
        memcpy(&val, stack + (addr - STACK_BASE), width);
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

static uint64_t service_module(const char *name) {
    static const char *const names[] = {"bcrypt", "advapi32", "ws2_32"};
    for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
        size_t length = strlen(names[i]);
        if (!strncasecmp(name, names[i], length) &&
            (!name[length] || !strcasecmp(name + length, ".dll")))
            return BCRYPT_MODULE + i;
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

static bool is_kernel_module_name(const char *name) {
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
    char name[129];
    module_string(name, sizeof name, address, wide ? 2 : 1);
    uint64_t service = service_module(name);
    if (service && service_references[service - BCRYPT_MODULE])
        return service;
    if (is_kernel_module_name(name))
        return KERNEL_MODULE;
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

static void unmap_guest_module(struct guest_module *module) {
    for (size_t i = 0; i < module->section_count; ++i)
        free(module->memory[i]);
    free(module->memory);
    module->memory = NULL;
    module->references = 0;
}

static void init_guest_cpu(uint64_t *cpu) {
    // The low byte of each width slot describes the initialized register.
    enum { GPR_COUNT = 16, CPU_WIDTH_OFFSET = GPR_COUNT + 32 + 5 };
    for (size_t i = 0; i < GPR_COUNT; ++i)
        cpu[CPU_WIDTH_OFFSET + i] = 64;
    for (size_t i = 6; i < 16; ++i)
        cpu[CPU_WIDTH_OFFSET + GPR_COUNT + i * 2] = 128;
}

static uint32_t call_module_entry(struct guest_module *module, uint64_t reason) {
    uint64_t cpu[128] = {0};
    uint64_t *caller = current_cpu;
    if (!caller)
        guest_trap("DLL initialization requires a guest CPU");
    cpu[1] = module->base;
    cpu[2] = reason;
    init_guest_cpu(cpu);
    cpu[7] = (caller[7] & ~UINT64_C(15)) - 40;
    guest_store(cpu[7], 0, 8);
    current_cpu = cpu;
    module->entry(cpu, 0);
    current_cpu = caller;
    return (uint32_t)cpu[0];
}

static uint64_t load_application_module(const char *name);
static void release_application_module(struct guest_module *module);

static uint64_t module_export(const struct guest_module *module, const char *name, uint64_t ordinal) {
    for (size_t i = 0; i < module->export_count; ++i) {
        const struct guest_module_export *export = &module->exports[i];
        if (name ? export->name && !strcmp(name, export->name) : ordinal == export->ordinal)
            return export->address;
    }
    return 0;
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
    call_module_entry(module, 0);
    unmap_guest_module(module);
    release_module_dependencies(module);
}

static uint64_t load_guest_module(struct guest_module *module, const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        last_error = 126;
        return 0;
    }
    unsigned char buffer[4096];
    size_t offset = 0;
    while (offset < module->file_size) {
        size_t remaining = module->file_size - offset;
        size_t count = remaining < sizeof buffer ? remaining : sizeof buffer;
        if (fread(buffer, 1, count, file) != count ||
            memcmp(buffer, module->file + offset, count) != 0)
            break;
        offset += count;
    }
    bool matches = offset == module->file_size && fgetc(file) == EOF && !ferror(file);
    fclose(file);
    if (!matches) {
        last_error = 193;
        return 0;
    }
    if (module->references) {
        ++module->references;
        return module->base;
    }
    module->memory = calloc(module->section_count, sizeof *module->memory);
    if (!module->memory) {
        last_error = 8;
        return 0;
    }
    for (size_t i = 0; i < module->section_count; ++i) {
        const struct section *section = &module->sections[i];
        module->memory[i] = calloc(1, section->size);
        if (!module->memory[i]) {
            unmap_guest_module(module);
            last_error = 8;
            return 0;
        }
        if (section->initial_size)
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
            uint64_t handle = load_application_module(import->dll);
            if (!handle)
                goto fail;
            module->dependencies[i] = handle;
            uint64_t target = module_export(find_guest_module(handle), import->name, import->ordinal);
            unsigned char *slot = mapped_module_span(module, import->slot, sizeof target, false);
            if (!target || !slot) {
                last_error = 127;
                goto fail;
            }
            memcpy(slot, &target, sizeof target);
        }
    }
    if (!call_module_entry(module, 1)) {
        last_error = 1114;
        goto fail;
    }
    module->loading = false;
    return module->base;

fail: {
    uint32_t error = last_error;
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
    if (!module || module->loading) {
        last_error = 126;
        return 0;
    }
    return load_guest_module(module, module->name);
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
    char module[129];
    module_string(module, sizeof module, address, 2);
    return load_named_module(module, reserved, flags);
}

uint64_t guest_load_library_a(uint64_t address) {
    char module[129];
    module_string(module, sizeof module, address, 1);
    static const char system[] = "C:\\Windows\\System32\\";
    const char *name = module;
    if (strncasecmp(module, system, sizeof system - 1) == 0)
        name += sizeof system - 1;
    return load_named_module(name, 0, 0);
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
    struct guest_module *module = find_guest_module(handle);
    if (module) {
        uint64_t target = module_export(module, address <= UINT16_MAX ? NULL : symbol, address);
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
    if (fits(addr, width, IOBUF_BASE, sizeof iobuf))
        return iobuf + (addr - IOBUF_BASE);
    if (fits(addr, width, ERRNO_BASE, sizeof guest_errno_storage))
        return (unsigned char *)&guest_errno_storage + (addr - ERRNO_BASE);
    if (fits(addr, width, RUNTIME_DATA_BASE, sizeof runtime_data))
        return runtime_data + (addr - RUNTIME_DATA_BASE);
    if (fits(addr, width, TLS_BASE, sizeof tls_storage))
        return tls_storage + (addr - TLS_BASE);
    if (!fits(addr, width, STACK_BASE, STACK_SIZE)) {
        if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < 0x20000000)
            addr -= guest_image_base;
        for (uint64_t i = 0; i < guest_section_count; ++i) {
            const struct section *section = &guest_sections[i];
            if (fits(addr, width, section->address, section->size))
                return image[i] + (addr - section->address);
        }
        unsigned char *module = module_span(addr, width, false);
        if (module)
            return module;
        unsigned char *heap = heap_span(addr, width);
        if (!heap) {
            fprintf(stderr, "address %#llx size %u\n", (unsigned long long)addr, width);
            fault();
        }
        return heap;
    }
    uint64_t offset = addr - STACK_BASE;
    for (uint32_t i = 0; i < width; ++i)
        initialized[offset + i] = true;
    return stack + offset;
}

void guest_store_slow(uint64_t addr, uint64_t value, uint32_t width) {
    uint64_t original = addr;
    if (!width || width > sizeof value)
        fault();
    if (fits(addr, width, TEB_BASE, sizeof teb)) {
        memcpy(teb + (addr - TEB_BASE), &value, width);
        return;
    }
    if (fits(addr, width, PEB_BASE, sizeof peb)) {
        memcpy(peb + (addr - PEB_BASE), &value, width);
        return;
    }
    if (fits(addr, width, IOBUF_BASE, sizeof iobuf)) {
        memcpy(iobuf + (addr - IOBUF_BASE), &value, width);
        return;
    }
    if (fits(addr, width, ERRNO_BASE, sizeof guest_errno_storage)) {
        memcpy((unsigned char *)&guest_errno_storage + (addr - ERRNO_BASE), &value, width);
        return;
    }
    if (fits(addr, width, RUNTIME_DATA_BASE, sizeof runtime_data)) {
        memcpy(runtime_data + (addr - RUNTIME_DATA_BASE), &value, width);
        return;
    }
    if (fits(addr, width, TLS_BASE, sizeof tls_storage)) {
        memcpy(tls_storage + (addr - TLS_BASE), &value, width);
        return;
    }
    if (!fits(addr, width, STACK_BASE, STACK_SIZE)) {
        if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < 0x20000000)
            addr -= guest_image_base;
        for (uint64_t i = 0; i < guest_section_count; ++i) {
            const struct section *section = &guest_sections[i];
            bool writable = section_protection ? ((section_protection[i] & 0xcc) != 0) : section->writable;
            if (writable && fits(addr, width, section->address, section->size)) {
                memcpy(image[i] + (addr - section->address), &value, width);
                return;
            }
        }
        unsigned char *module = module_span(addr, width, true);
        if (module) {
            memcpy(module, &value, width);
            return;
        }
        unsigned char *heap = heap_span(addr, width);
        if (!heap) {
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
        if (guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
            guest_faultable_copy(heap, &value, width, original, true);
        else
            memcpy(heap, &value, width);
        return;
    }
    uint64_t offset = addr - STACK_BASE;
    memcpy(stack + offset, &value, width);
    for (uint32_t i = 0; i < width; ++i)
        initialized[offset + i] = true;
}

__attribute__((always_inline)) void guest_store(uint64_t addr, uint64_t value, uint32_t width) {
    if ((addr & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG) {
        void *destination = (void *)(uintptr_t)(addr & ~UINT64_C(0xFF00000000000000));
        if (guest_signal_ready && guest_fault_pc && current_cpu && !delivering_fault)
            guest_faultable_copy(destination, &value, width, addr, true);
        else
            memcpy(destination, &value, width);
        return;
    }
    if (fits(addr, width, STACK_BASE, STACK_SIZE)) {
        memcpy(stack + (addr - STACK_BASE), &value, width);
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
    if ((addr & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG)
        return (unsigned char *)(uintptr_t)(addr & ~UINT64_C(0xFF00000000000000));
    if (fits(addr, size, STACK_BASE, STACK_SIZE)) {
        uint64_t offset = addr - STACK_BASE;
        for (uint64_t i = 0; i < size; ++i)
            initialized[offset + i] = true;
        return stack + offset;
    }
    if (fits(addr, size, TEB_BASE, sizeof teb))
        return teb + (addr - TEB_BASE);
    if (fits(addr, size, PEB_BASE, sizeof peb))
        return peb + (addr - PEB_BASE);
    if (fits(addr, size, TLS_BASE, sizeof tls_storage))
        return tls_storage + (addr - TLS_BASE);
    if (fits(addr, size, RUNTIME_DATA_BASE, sizeof runtime_data))
        return runtime_data + (addr - RUNTIME_DATA_BASE);
    if (fits(addr, size, IOBUF_BASE, sizeof iobuf))
        return iobuf + (addr - IOBUF_BASE);
    if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < 0x20000000)
        addr -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *sec = &guest_sections[i];
        bool writable = section_protection ? ((section_protection[i] & 0xcc) != 0) : sec->writable;
        if (writable && fits(addr, size, sec->address, sec->size))
            return image[i] + (addr - sec->address);
    }
    unsigned char *module = module_span(addr, size, true);
    if (module)
        return module;
    return heap_span(addr, size);
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
    put64(teb, 0x30, TEB_BASE);
    put64(teb, 0x40, guest_identity(0));
    put64(teb, 0x48, guest_identity(1));
    put64(teb, 0x58, TLS_BASE);
    put64(teb, 0x60, PEB_BASE);
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
    uint64_t stack_base = GUEST_HEAP_TAG | (uint64_t)(uintptr_t)thread->stack_memory;
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

uint64_t guest_indirect_call(uint64_t target, uint64_t first, uint64_t second,
                             uint64_t third, uint64_t fourth) {
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
    if (target < 0x20000000) {
        char name[128] = {0};
        bool valid = true;
        for (size_t i = 0; i < sizeof(name) - 1; ++i) {
            uint8_t c = (uint8_t)guest_load(target + 2 + i, 1);
            if (!c) { name[i] = 0; break; }
            if (c < 32 || c >= 127) { valid = false; break; }
            name[i] = (char)c;
        }
        if (valid && name[0]) {
            uint64_t shim_res = 0;
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
            if (strcmp(name, "TryEnterCriticalSection") == 0) return 1;
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

            return guest_unimplemented_stub(name, "wine_api");
        }
    }
    if (target >= 0x7fff0000 && target < 0x80000000)
        return 0;
    fprintf(stderr, "RVA 0x%llx: unsupported indirect call target 0x%llx\n",
            (unsigned long long)guest_pc, (unsigned long long)target);
    exit(125);
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

static inline __attribute__((always_inline)) void (*guest_lookup_dispatch(uint64_t target))(void *, uint64_t) {
    if (guest_image_base && target >= guest_image_base && target - guest_image_base < 0x20000000)
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

    static _Thread_local struct { uint64_t rva; void (*fn)(void *, uint64_t); } cache[1024];
    size_t slot = (target ^ (target >> 6)) & 1023;
    if (cache[slot].rva == target && cache[slot].fn)
        return cache[slot].fn;

    size_t low = 0, high = guest_dispatch_count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (guest_dispatch_table[mid].rva == target) {
            cache[slot].rva = target;
            cache[slot].fn = guest_dispatch_table[mid].fn;
            return guest_dispatch_table[mid].fn;
        }
        if (guest_dispatch_table[mid].rva < target)
            low = mid + 1;
        else
            high = mid;
    }
    return NULL;
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
    if (guest_image_base && target >= guest_image_base && target - guest_image_base < 0x20000000)
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
    guest_store(address, 0, 8);
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
    if (guest_image_base && address >= guest_image_base && address - guest_image_base < 0x20000000)
        address -= guest_image_base;
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *section = &guest_sections[i];
        if (address >= section->address && address < section->address + section->size) {
            uint32_t old = section_protection ? section_protection[i] : (section->writable ? 0x04 : 0x02);
            if (section_protection)
                section_protection[i] = new_protect;
            int prot = win32_to_posix_prot(new_protect);
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            uintptr_t host_addr = (uintptr_t)(image[i] + (address - section->address));
            uintptr_t page_start = host_addr & ~(page_size - 1);
            uintptr_t page_end = (host_addr + size + page_size - 1) & ~(page_size - 1);
            uintptr_t max_end = (uintptr_t)image[i] + ((section->size + page_size - 1) & ~(page_size - 1));
            if (page_end > max_end)
                page_end = max_end;
            if (page_start < (uintptr_t)image[i])
                page_start = (uintptr_t)image[i];
            if (page_end > page_start)
                mprotect((void *)page_start, page_end - page_start, prot);
            if (old_protect_ptr)
                guest_store(old_protect_ptr, old, 4);
            return 1;
        }
    }
    if ((address & UINT64_C(0xFF00000000000000)) == GUEST_HEAP_TAG) {
        if (old_protect_ptr)
            guest_store(old_protect_ptr, 0x04, 4);
        return 1;
    }
    if (old_protect_ptr)
        guest_store(old_protect_ptr, 0x04, 4);
    return 1;
}

void guest_critical_section(uint64_t address, uint32_t entering) {
    uint64_t depth = guest_load(address + 12, 4);
    uint64_t owner = guest_load(address + 16, 8);
    if (entering == 2) {
        if (depth || owner)
            guest_trap("cannot delete an owned critical section");
        for (unsigned offset = 0; offset < 40; offset += 8)
            guest_store(address + offset, 0, 8);
        return;
    }
    uint64_t thread = guest_identity(1);
    if ((owner && owner != thread) || (!entering && !depth) ||
        (entering && depth == UINT32_MAX))
        guest_trap("unsupported critical section ownership state");
    depth = entering ? depth + 1 : depth - 1;
    guest_store(address + 8, depth - 1, 4);
    guest_store(address + 12, depth, 4);
    guest_store(address + 16, depth ? thread : 0, 8);
}

void guest_check_return(uint64_t addr, uint64_t expected) {
    uint64_t actual = guest_load(addr, 8);
    if (actual != expected) {
        fputs("guest return address mismatch\n", stderr);
        fprintf(stderr, "actual %#llx != expected %#llx at rsp %#llx\n",
                (unsigned long long)actual, (unsigned long long)expected, (unsigned long long)addr);
        exit(125);
    }
}

uint64_t guest_identity(uint32_t thread) {
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
    (void)flags;
    if ((page != 0 && page != 65001 && page != 1252 && page != 437) ||
        length < -1 || length == 0 || length > 65536 || size > INT32_MAX)
        guest_trap("unsupported Windows text conversion parameters");
    unsigned in_width = wide ? 1 : 2;
    unsigned out_width = wide ? 2 : 1;
    uint64_t count = 0;
    while (length == -1 || count < (uint32_t)length) {
        if (count == 65536)
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
    init_runtime_data();
    put64(peb, 0x10, guest_image_base);
    image = calloc(guest_section_count ? guest_section_count : 1, sizeof *image);
    section_protection = calloc(guest_section_count ? guest_section_count : 1, sizeof *section_protection);
    if (!image || !section_protection)
        fault();
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    for (uint64_t i = 0; i < guest_section_count; ++i) {
        const struct section *section = &guest_sections[i];
        size_t alloc_size = (section->size + page_size - 1) & ~(page_size - 1);
        if (!alloc_size)
            alloc_size = page_size;
        image[i] = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (image[i] == MAP_FAILED)
            fault();
        section_protection[i] = section->writable ? 0x04 : 0x02;
        if (section->initial_size)
            memcpy(image[i], section->initial, section->initial_size);
    }
    init_guest_thread_data();
    if (guest_tls_index_va) {
        uint64_t idx_addr = guest_tls_index_va;
        if (guest_image_base && idx_addr >= guest_image_base && idx_addr - guest_image_base < 0x20000000)
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
        return (int)lifted_console();
    }
    return (int)resume_guest();
}
