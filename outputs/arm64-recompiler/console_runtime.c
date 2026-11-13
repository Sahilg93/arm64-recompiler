#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>

struct section {
    uint64_t address, size, initial_size;
    const unsigned char *initial;
    uint64_t writable;
};
extern const struct section guest_sections[];
extern const uint64_t guest_section_count;
static unsigned char **image;
static uint32_t *section_protection;
static struct allocation { uint64_t base, size, requested; unsigned char *data; } allocations[8192];
static uint64_t next_allocation = UINT64_C(0x1000000000000000);
extern const uint64_t guest_image_base;
extern uint32_t lifted_console(void);

void guest_init_critical(uint64_t address, uint32_t spin_count);
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
uint64_t guest_cexit(void);
uint64_t guest_set_thread_stack_guarantee(uint64_t size_ptr);

enum { STACK_BASE = 0x2000000, STACK_SIZE = 1048576 };
static unsigned char stack[STACK_SIZE];
static bool initialized[STACK_SIZE];
enum { TEB_BASE = 0x2101000, PEB_BASE = 0x2102000 };
static unsigned char teb[4096], peb[4096];
enum { IOBUF_BASE = 0x2103000, IOBUF_ENTRY_SIZE = 48, IOBUF_COUNT = 3 };
static unsigned char iobuf[IOBUF_COUNT * IOBUF_ENTRY_SIZE];
enum { ERRNO_BASE = 0x2104000 };
static int guest_errno_storage;
enum { ARGC_BASE = 0x2105000, ARGV_BASE = 0x2105010, WARGV_BASE = 0x2105020, FMODE_BASE = 0x2105030, COMMODE_BASE = 0x2105038 };
static int guest_argc_storage = 1;
static uint64_t guest_argv_storage[4] = { 0x2105040, 0, 0, 0 };
static uint64_t guest_wargv_storage[4] = { 0x2105080, 0, 0, 0 };
static int guest_fmode_storage = 0;
static int guest_commode_storage = 0;

static void put64(unsigned char *data, unsigned offset, uint64_t value) {
    memcpy(data + offset, &value, sizeof value);
}
static uint32_t last_error;

static bool fits(uint64_t addr, uint64_t size, uint64_t start, uint64_t length) {
    return addr >= start && size <= length && addr - start <= length - size;
}

static uint64_t guest_pc;
static uint64_t watched_rva = UINT64_MAX;

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

static void fault(void) {
    fprintf(stderr, "RVA %#llx: unsupported guest memory access\n", (unsigned long long)guest_pc);
    exit(125);
}

static unsigned char *heap_span(uint64_t address, uint64_t size) {
    for (size_t i = 0; i < sizeof allocations / sizeof *allocations; ++i)
        if (allocations[i].data && fits(address, size, allocations[i].base, allocations[i].size))
            return allocations[i].data + (address - allocations[i].base);
    return NULL;
}

uint64_t guest_heap_alloc(uint64_t handle, uint32_t flags, uint64_t size) {
    if (handle != 0x7fff2001 || (flags & ~8u))
        guest_trap("unsupported HeapAlloc handle or flags");
    if (!size)
        size = 1;
    if (size > 16 * 1024 * 1024 || next_allocation > UINT64_C(0x1000000010000000))
        return 0;
    for (size_t i = 0; i < sizeof allocations / sizeof *allocations; ++i)
        if (!allocations[i].data) {
            uint64_t capacity = (size + 15) & ~UINT64_C(15);
            unsigned char *data = calloc(capacity, 1);
            if (!data)
                return 0;
            allocations[i] = (struct allocation){next_allocation, capacity, size, data};
            next_allocation += capacity;
            return allocations[i].base;
        }
    return 0;
}

uint64_t guest_heap_free(uint64_t handle, uint32_t flags, uint64_t address) {
    if (handle != 0x7fff2001 || flags)
        guest_trap("unsupported HeapFree handle or flags");
    for (size_t i = 0; i < sizeof allocations / sizeof *allocations; ++i)
        if (allocations[i].data && allocations[i].base == address) {
            free(allocations[i].data);
            allocations[i].data = NULL;
            return 1;
        }
    return 0;
}

uint64_t guest_heap_realloc(uint64_t handle, uint32_t flags, uint64_t address, uint64_t size) {
    if (!address)
        return guest_heap_alloc(handle, flags, size);
    for (size_t i = 0; i < sizeof allocations / sizeof *allocations; ++i) {
        struct allocation *old = &allocations[i];
        if (!old->data || old->base != address)
            continue;
        uint64_t replacement = guest_heap_alloc(handle, flags, size);
        if (!replacement)
            return 0;
        uint64_t copy = old->requested < size ? old->requested : size;
        if (copy)
            memcpy(heap_span(replacement, copy), old->data, copy);
        guest_heap_free(handle, 0, address);
        return replacement;
    }
    return 0;
}

static const unsigned char *read_span(uint64_t addr, uint64_t size) {
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
    if (fits(addr, size, ARGC_BASE, sizeof guest_argc_storage))
        return (const unsigned char *)&guest_argc_storage + (addr - ARGC_BASE);
    if (fits(addr, size, ARGV_BASE, sizeof guest_argv_storage))
        return (const unsigned char *)guest_argv_storage + (addr - ARGV_BASE);
    if (fits(addr, size, WARGV_BASE, sizeof guest_wargv_storage))
        return (const unsigned char *)guest_wargv_storage + (addr - WARGV_BASE);
    if (fits(addr, size, FMODE_BASE, sizeof guest_fmode_storage))
        return (const unsigned char *)&guest_fmode_storage + (addr - FMODE_BASE);
    if (fits(addr, size, COMMODE_BASE, sizeof guest_commode_storage))
        return (const unsigned char *)&guest_commode_storage + (addr - COMMODE_BASE);
    for (uint64_t i = 0; i < guest_section_count; ++i)
        if (fits(addr, size, guest_sections[i].address, guest_sections[i].size))
            return image[i] + (addr - guest_sections[i].address);
    unsigned char *heap = heap_span(addr, size);
    if (heap)
        return heap;
    fprintf(stderr, "read address %#llx size %llu\n", (unsigned long long)addr, (unsigned long long)size);
    fault();
    return NULL;
}

uint64_t guest_load(uint64_t addr, uint32_t width) {
    uint64_t value = 0;
    if (!width || width > sizeof value)
        fault();
    memcpy(&value, read_span(addr, width), width);
    return value;
}

enum { SYNC_MODULE = 0x7fff0001, FIBER_MODULE = 0x7fff0002, KERNEL_MODULE = 0x7fff0003, INIT_CRITICAL = 0x7fff1001, FLS_ALLOC, FLS_GET, FLS_SET, FLS_FREE, FILE_APIS_ANSI, DEFAULT_DLL_DIRS, VIRTUAL_PROTECT };
static unsigned sync_references, fiber_references, kernel_references;

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

static uint64_t load_named_module(const char *module, uint64_t reserved, uint32_t flags) {
    if (!reserved && (flags == 0 || flags == 0x800)) {
        if (is_kernel_module_name(module)) {
            ++kernel_references;
            return KERNEL_MODULE;
        }
        if (strcasecmp(module, "api-ms-win-appmodel-runtime-l1-1-2") == 0 ||
            strcasecmp(module, "api-ms-win-appmodel-runtime-l1-1-2.dll") == 0) {
            last_error = 126;
            return 0;
        }
    }
    fprintf(stderr, "RVA %#llx: unsupported LoadLibraryExW module %s, flags %#x\n",
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
    if (handle == KERNEL_MODULE && (strcmp(symbol, "AddVectoredExceptionHandler") == 0 || strcmp(symbol, "RemoveVectoredExceptionHandler") == 0))
        return 0x7fff3001;
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
    fprintf(stderr, "RVA %#llx: unsupported dynamic import %s!%s\n",
            (unsigned long long)guest_pc,
            handle == SYNC_MODULE ? "api-ms-win-core-synch-l1-2-0" :
            handle == FIBER_MODULE ? "api-ms-win-core-fibers-l1-1-1" : "kernel32.dll", symbol);
    exit(125);
}

void *guest_pointer(uint64_t addr, uint32_t width) {
    if (!width || width > sizeof(uint64_t))
        fault();
    if (fits(addr, width, IOBUF_BASE, sizeof iobuf))
        return iobuf + (addr - IOBUF_BASE);
    if (fits(addr, width, ERRNO_BASE, sizeof guest_errno_storage))
        return (unsigned char *)&guest_errno_storage + (addr - ERRNO_BASE);
    if (fits(addr, width, ARGC_BASE, sizeof guest_argc_storage))
        return (unsigned char *)&guest_argc_storage + (addr - ARGC_BASE);
    if (fits(addr, width, ARGV_BASE, sizeof guest_argv_storage))
        return (unsigned char *)guest_argv_storage + (addr - ARGV_BASE);
    if (fits(addr, width, WARGV_BASE, sizeof guest_wargv_storage))
        return (unsigned char *)guest_wargv_storage + (addr - WARGV_BASE);
    if (fits(addr, width, FMODE_BASE, sizeof guest_fmode_storage))
        return (unsigned char *)&guest_fmode_storage + (addr - FMODE_BASE);
    if (fits(addr, width, COMMODE_BASE, sizeof guest_commode_storage))
        return (unsigned char *)&guest_commode_storage + (addr - COMMODE_BASE);
    if (!fits(addr, width, STACK_BASE, STACK_SIZE)) {
        if (guest_image_base && addr >= guest_image_base && addr - guest_image_base < 0x20000000)
            addr -= guest_image_base;
        for (uint64_t i = 0; i < guest_section_count; ++i) {
            const struct section *section = &guest_sections[i];
            bool writable = section_protection ? ((section_protection[i] & 0xcc) != 0) : section->writable;
            if (writable && fits(addr, width, section->address, section->size))
                return image[i] + (addr - section->address);
        }
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

void guest_store(uint64_t addr, uint64_t value, uint32_t width) {
    if (!width || width > sizeof value)
        fault();
    if (fits(addr, width, IOBUF_BASE, sizeof iobuf)) {
        memcpy(iobuf + (addr - IOBUF_BASE), &value, width);
        return;
    }
    if (fits(addr, width, ERRNO_BASE, sizeof guest_errno_storage)) {
        memcpy((unsigned char *)&guest_errno_storage + (addr - ERRNO_BASE), &value, width);
        return;
    }
    if (fits(addr, width, ARGC_BASE, sizeof guest_argc_storage)) {
        memcpy((unsigned char *)&guest_argc_storage + (addr - ARGC_BASE), &value, width);
        return;
    }
    if (fits(addr, width, FMODE_BASE, sizeof guest_fmode_storage)) {
        memcpy((unsigned char *)&guest_fmode_storage + (addr - FMODE_BASE), &value, width);
        return;
    }
    if (fits(addr, width, COMMODE_BASE, sizeof guest_commode_storage)) {
        memcpy((unsigned char *)&guest_commode_storage + (addr - COMMODE_BASE), &value, width);
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
        unsigned char *heap = heap_span(addr, width);
        if (!heap) {
            fprintf(stderr, "write address %#llx size %u\n", (unsigned long long)addr, width);
            fault();
        }
        memcpy(heap, &value, width);
        return;
    }
    uint64_t offset = addr - STACK_BASE;
    memcpy(stack + offset, &value, width);
    for (uint32_t i = 0; i < width; ++i)
        initialized[offset + i] = true;
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

uint64_t guest_add_vectored_exception_handler(uint32_t first, uint64_t handler) {
    (void)first;
    return handler ? handler : UINT64_C(0x7fff3001);
}

uint64_t guest_remove_vectored_exception_handler(uint64_t handle) {
    (void)handle;
    return 1;
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
uint64_t guest_crt_atexit(uint64_t fn) { (void)fn; return 0; }
uint64_t guest_register_onexit(uint64_t table, uint64_t fn) { (void)table; (void)fn; return 0; }
uint64_t guest_init_onexit(uint64_t table) { (void)table; return 0; }
uint64_t guest_exec_onexit(uint64_t table) { (void)table; return 0; }
uint64_t guest_initterm(uint64_t start, uint64_t end) { (void)start; (void)end; return 0; }
uint64_t guest_initterm_e(uint64_t start, uint64_t end) { (void)start; (void)end; return 0; }
uint64_t guest_configure_argv(uint32_t mode) { (void)mode; return 0; }
uint64_t guest_init_env(void) { return 0; }
uint64_t guest_get_initial_env(void) { return 0; }
uint64_t guest_set_app_type(uint32_t type) { (void)type; return 0; }
uint64_t guest_seh_filter_exe(uint32_t code, uint64_t info) { (void)info; return (uint64_t)code; }
uint64_t guest_set_invalid_param(uint64_t handler) { (void)handler; return 0; }
uint64_t guest_cexit(void) { return 0; }
uint64_t guest_set_thread_stack_guarantee(uint64_t size_ptr) { (void)size_ptr; return 1; }

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

uint64_t guest_system_directory(uint64_t buffer, uint32_t size, uint32_t wide);

uint64_t guest_indirect_call(uint64_t target, uint64_t first, uint64_t second,
                             uint64_t third, uint64_t fourth) {
    (void)fourth;
    if (target == 0x7fff1030)
        return 2; // The guest registry has no configured keys.
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
    static struct { bool allocated; uint64_t callback, value; } slots[128];
    if (target == FLS_ALLOC) {
        for (unsigned i = 0; i < sizeof slots / sizeof *slots; ++i)
            if (!slots[i].allocated) {
                slots[i].allocated = true;
                slots[i].callback = first;
                return i;
            }
        last_error = 8;
        return UINT32_MAX;
    }
    if (target == FLS_GET || target == FLS_SET || target == FLS_FREE) {
        uint32_t index = (uint32_t)first;
        if (index >= sizeof slots / sizeof *slots || !slots[index].allocated) {
            last_error = 87;
            return 0;
        }
        if (target == FLS_GET) {
            last_error = 0;
            return slots[index].value;
        }
        if (target == FLS_SET) {
            slots[index].value = second;
            return 1;
        }
        if (slots[index].callback && slots[index].value) {
            fprintf(stderr, "RVA %#llx: FlsFree needs guest callback %#llx\n",
                    (unsigned long long)guest_pc, (unsigned long long)slots[index].callback);
            exit(125);
        }
        memset(&slots[index], 0, sizeof slots[index]);
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
    fprintf(stderr, "RVA %#llx: unsupported indirect call target %#llx\n",
            (unsigned long long)guest_pc, (unsigned long long)target);
    exit(125);
}

struct guest_dispatch_entry {
    uint64_t rva;
    void (*fn)(void *cpu, uint64_t return_va);
};

void guest_check_return(uint64_t addr, uint64_t expected);

__attribute__((weak)) const struct guest_dispatch_entry guest_dispatch_table[] = {{0, NULL}};
__attribute__((weak)) const uint64_t guest_dispatch_count = 0;

static void (*guest_lookup_dispatch(uint64_t target))(void *, uint64_t) {
    if (guest_image_base && target >= guest_image_base && target - guest_image_base < 0x20000000)
        target -= guest_image_base;
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

uint64_t guest_indirect_dispatch(void *cpu, uint64_t target, uint64_t return_va, uint32_t tail) {
    if (guest_image_base && target >= guest_image_base && target - guest_image_base < 0x20000000)
        target -= guest_image_base;
    void (*fn)(void *, uint64_t) = guest_lookup_dispatch(target);
    uint64_t *regs = (uint64_t *)cpu;
    if (fn) {
        fn(cpu, return_va);
        return regs[0];
    }
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
    for (size_t i = 0; i < sizeof allocations / sizeof *allocations; ++i) {
        if (allocations[i].data && address >= allocations[i].base && address < allocations[i].base + allocations[i].size) {
            if (old_protect_ptr)
                guest_store(old_protect_ptr, 0x04, 4);
            return 1;
        }
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
    if (guest_load(addr, 8) != expected) {
        fputs("guest return address mismatch\n", stderr);
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
    guest_store(written, 0, 4);
    if ((handle != 1 && handle != 2) || overlapped != 0) {
        last_error = (handle != 1 && handle != 2) ? 6 : 87;
        return 0;
    }
    ssize_t result = write((int)handle, read_span(address, count), count);
    if (result < 0) {
        last_error = 6;
        return 0;
    }
    guest_store(written, (uint32_t)result, 4);
    return 1;
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
    if ((page != 0 && page != 65001 && page != 1252 && page != 437) ||
        length < -1 || length == 0 || length > 65536 || size > INT32_MAX ||
        (flags & ~(wide ? 8u : 0x80u)))
        guest_trap("unsupported Windows text conversion parameters");
    unsigned in_width = wide ? 1 : 2;
    unsigned out_width = wide ? 2 : 1;
    uint64_t count = 0;
    while (length == -1 || count < (uint32_t)length) {
        if (count == 65536)
            guest_trap("unterminated Windows text conversion input");
        uint64_t unit = guest_load(source + count * in_width, in_width);
        if (unit >= 128)
            guest_trap("non-ASCII Windows text conversion is unsupported");
        ++count;
        if (!unit && length == -1)
            break;
    }
    if (size && size < count) {
        last_error = 122;
        return 0;
    }
    if (size)
        for (uint64_t i = 0; i < count; ++i)
            guest_store(dest + i * out_width, guest_load(source + i * in_width, in_width), out_width);
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

static int host_argc;
static char **host_argv;
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
    put64(teb, 0x08, STACK_BASE + STACK_SIZE);
    put64(teb, 0x10, STACK_BASE);
    put64(teb, 0x30, TEB_BASE);
    put64(teb, 0x40, guest_identity(0));
    put64(teb, 0x48, guest_identity(1));
    put64(teb, 0x60, PEB_BASE);
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
    return (int)lifted_console();
}
