/*
 * Hosting on Wine's unix side (ARM64_RECOMPILER_WINE_HOST=<host>/lib/wine/x86_64-unix,
 * built by wine-host/build.sh).
 *
 * The process boots Wine's patched ntdll.so, which connects to wineserver and
 * hands control back on Wine's main thread; the original thread stays in the
 * run loop Cocoa needs. From then on the runtime is the CPU and the loader for
 * the lifted Windows code, and Wine is the kernel:
 *   - every Nt*, NtUser* and NtGdi* syscall stub runs the native function in
 *     ntdll.so / win32u.so, through a marshalling thunk (hostthunks.dylib);
 *   - a lifted DLL's unix calls run its unix library (<name>.so);
 *   - win32u's user-mode callbacks re-enter the lifted code through the
 *     table user32.dll installs in PEB->KernelCallbackTable.
 */
struct wine_host_callbacks {
    void (*start_thread)(void *entry, void *arg, int suspend, void *teb_address);
    int (*user_callback)(unsigned id, const void *args, unsigned len, void **ret_ptr, unsigned *ret_len);
};

typedef uint64_t (*host_thunk)(const uint64_t *slots);
static host_thunk (*wine_host_thunk_lookup)(const char *name);
static char wine_host_directory[1024];

static bool wine_host_trace(void) {
    static int trace = -1;
    if (trace < 0)
        trace = getenv("ARM64_RECOMPILER_TRACE_IMPORTS") != NULL;
    return trace;
}

static void *wine_host_load(const char *name) {
    char path[1200];
    snprintf(path, sizeof path, "%s/%s", wine_host_directory, name);
    return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
}

static struct guest_module *wine_host_module_at(uint64_t address) {
    for (size_t i = 0; i < guest_module_count; ++i)
        if (guest_modules[i].references && fits(address, 1, guest_modules[i].base, guest_modules[i].size))
            return &guest_modules[i];
    for (struct translated_module *item = atomic_load(&translated_modules); item; item = item->next)
        if (item->module->references && fits(address, 1, item->module->base, item->module->size))
            return item->module;
    return NULL;
}

/* NtQueryVirtualMemory(MemoryWineUnixFuncs): the unix call table of the DLL at this address. */
static uint64_t wine_host_unix_funcs(uint64_t address, uint64_t buffer, uint64_t length, uint64_t returned) {
    enum { STATUS_INFO_LENGTH_MISMATCH_NT = 0xc0000004, STATUS_DLL_NOT_FOUND_NT = 0xc0000135 };
    const struct guest_module *module = wine_host_module_at(address);
    if (length != 8)
        return STATUS_INFO_LENGTH_MISMATCH_NT;
    if (!module)
        return STATUS_DLL_NOT_FOUND_NT;
    char name[160];
    size_t n = 0;
    for (const char *c = module->name; *c && n < sizeof name - 4; ++c)
        name[n++] = (char)tolower((unsigned char)*c);
    name[n] = 0;
    char *dot = strrchr(name, '.');
    strcpy(dot ? dot : name + n, ".so");
    void *library = wine_host_load(name);
    void *funcs = library ? dlsym(library, "__wine_unix_call_funcs") : NULL;
    if (wine_host_trace())
        fprintf(stderr, "[unixlib] %s -> %s %p\n", module->name, name, funcs);
    if (!funcs)
        return STATUS_DLL_NOT_FOUND_NT;
    guest_store(buffer, (uint64_t)(uintptr_t)funcs, 8);
    if (returned)
        guest_store(returned, 8, 8);
    return 0;
}

/* __wine_unix_call_dispatcher( handle, code, args ) */
static uint64_t wine_host_unix_call(uint64_t handle, uint32_t code, uint64_t args) {
    int (*const *funcs)(void *) = (int (*const *)(void *))(uintptr_t)handle;
    if (handle < GUEST_HOST_FLOOR)
        return 0xc0000008; /* STATUS_INVALID_HANDLE */
    uint32_t status = (uint32_t)funcs[code]((void *)(uintptr_t)args);
    if (wine_host_trace())
        fprintf(stderr, "[unixcall] %#llx[%u](%#llx) = %#x\n", (unsigned long long)handle, code,
                (unsigned long long)args, status);
    return status;
}

/* One frame per user-mode callback in progress on this thread. */
struct wine_host_callback {
    jmp_buf environment;
    uint64_t ret_ptr;
    uint32_t ret_len, status;
    struct wine_host_callback *previous;
};
static _Thread_local struct wine_host_callback *wine_host_callback_top;

/* NtCallbackReturn( ret_ptr, ret_len, status ): leave the current callback with a reply. */
static uint64_t wine_host_callback_return(const uint64_t *slots) {
    struct wine_host_callback *frame = wine_host_callback_top;
    if (!frame)
        return 0xc0000258; /* STATUS_NO_CALLBACK_ACTIVE */
    frame->ret_ptr = slots[0];
    frame->ret_len = (uint32_t)slots[1];
    frame->status = (uint32_t)slots[2];
    longjmp(frame->environment, 1);
}

static host_thunk wine_host_query_virtual_memory;
static uint64_t wine_host_NtQueryVirtualMemory(const uint64_t *slots) {
    if ((uint32_t)slots[2] == 1000) /* MemoryWineUnixFuncs */
        return wine_host_unix_funcs(slots[1], slots[3], slots[4], slots[5]);
    return wine_host_query_virtual_memory(slots);
}

/*
 * Run a syscall stub natively. cache is the override site's slot: a thunk
 * pointer once resolved (never below the host floor), or the runtime's own
 * token when the runtime keeps the call.
 */
static bool wine_host_syscall(uint64_t *cache, const char *name, uint64_t a, uint64_t b, uint64_t c,
                              uint64_t d, uint64_t *result) {
    if (name[0] != 'N' || name[1] != 't')
        return false;
    uint64_t cached = atomic_load_explicit((_Atomic uint64_t *)cache, memory_order_relaxed);
    host_thunk thunk = cached >= GUEST_HOST_FLOOR ? (host_thunk)(uintptr_t)cached : NULL;
    if (!thunk) {
        /*
         * Exceptions still belong to the runtime. Wine creates threads itself (the
         * server and win32u must know them) and hands each to wine_host_start_thread.
         */
        static const char *const runtime_owned[] = {
            "NtContinue", "NtRaiseException", "NtTerminateThread",
            "NtSetContextThread", "NtGetContextThread",
        };
        if (cached || !wine_host_thunk_lookup)
            return false;
        for (size_t i = 0; i < sizeof runtime_owned / sizeof *runtime_owned; ++i)
            if (!strcmp(name, runtime_owned[i]))
                return false;
        if (!strcmp(name, "NtCallbackReturn")) {
            thunk = wine_host_callback_return;
        } else if (!strcmp(name, "NtQueryVirtualMemory")) {
            wine_host_query_virtual_memory = wine_host_thunk_lookup(name);
            thunk = wine_host_NtQueryVirtualMemory;
        } else {
            thunk = wine_host_thunk_lookup(name);
        }
        if (!thunk)
            return false;
        atomic_store_explicit((_Atomic uint64_t *)cache, (uint64_t)(uintptr_t)thunk, memory_order_relaxed);
    }
    /* x64: four register arguments, the rest in 8-byte stack slots above the return address and home space. */
    enum { SLOTS = 20 };
    uint64_t slots[SLOTS] = {a, b, c, d};
    uint64_t stack = current_cpu ? ((uint64_t *)current_cpu)[7] + 40 : 0;
    size_t available = stack ? SLOTS - 4 : 0;
    if (fits(stack, 8, STACK_BASE, STACK_SIZE) && (STACK_BASE + STACK_SIZE - stack) / 8 < available)
        available = (STACK_BASE + STACK_SIZE - stack) / 8;
    if (available)
        memcpy(slots + 4, (const void *)(uintptr_t)stack, available * 8);
    *result = thunk(slots);
    if (name[2] == 'U' && !strcmp(name, "NtUserShowWindow"))
        trace_time("NtUserShowWindow returned", NULL);
    if (wine_host_trace())
        fprintf(stderr, "[syscall] %s(%#llx, %#llx, %#llx, %#llx) = %#llx\n", name, (unsigned long long)a,
                (unsigned long long)b, (unsigned long long)c, (unsigned long long)d, (unsigned long long)*result);
    return true;
}

/*
 * KeUserModeCallback: win32u calls back into user32. Like the kernel, copy the
 * arguments onto the guest stack (win32u frees its copy before it reads the
 * reply, which may point into them) and run the function user32 registered
 * for this id; it replies through NtCallbackReturn or by returning a status.
 */
static int wine_host_user_callback(unsigned id, const void *args, unsigned len, void **ret_ptr, unsigned *ret_len) {
    enum { STATUS_NOT_IMPLEMENTED_HOST = (int)0xc0000002 };
    *ret_ptr = NULL;
    *ret_len = 0;
    uint64_t *caller = current_cpu;
    uint64_t table = caller && host_peb ? *(uint64_t *)(void *)(host_peb + 0x58) : 0; /* KernelCallbackTable */
    uint64_t function = table ? *(uint64_t *)(uintptr_t)(table + 8 * (uint64_t)id) : 0;
    void (*lifted)(void *, uint64_t) = function ? guest_lookup_dispatch(function) : NULL;
    if (wine_host_trace())
        fprintf(stderr, "[callback] %u (%u bytes) -> %#llx\n", id, len, (unsigned long long)function);
    if (!lifted)
        return STATUS_NOT_IMPLEMENTED_HOST;
    uint64_t data = (caller[7] - len - 0x100) & ~UINT64_C(15);
    memcpy((void *)(uintptr_t)data, args, len);
    uint64_t cpu[128] = {0};
    init_guest_cpu(cpu);
    cpu[1] = data;
    cpu[2] = len;
    cpu[7] = data - 40;
    *(uint64_t *)(uintptr_t)cpu[7] = 0;
    struct wine_host_callback frame = {.previous = wine_host_callback_top};
    wine_host_callback_top = &frame;
    volatile int status;
    if (!setjmp(frame.environment)) {
        current_cpu = cpu;
        lifted(cpu, 0);
        status = (int)(uint32_t)cpu[0];
    } else {
        status = (int)frame.status;
        *ret_ptr = (void *)(uintptr_t)frame.ret_ptr;
        *ret_len = frame.ret_len;
    }
    wine_host_callback_top = frame.previous;
    current_cpu = caller;
    return status;
}

static int guest_run(void);

/*
 * A thread Wine created (NtCreateThreadEx): run its lifted start routine on the
 * stack Wine allocated, as RtlUserThreadStart would, then end it through Wine so
 * the server sees the exit code. DLL_THREAD_ATTACH is not delivered.
 */
static void wine_host_run_thread(uint64_t entry, uint64_t argument) {
    uint64_t stack_top = *(uint64_t *)(void *)(host_teb + 0x08), stack_base = *(uint64_t *)(void *)(host_teb + 0x10);
    init_guest_thread_data();
    put64(teb, 0x08, stack_top);
    put64(teb, 0x10, stack_base);
    void (*lifted)(void *, uint64_t) = guest_lookup_dispatch(entry);
    uint64_t cpu[128] = {0};
    init_guest_cpu(cpu);
    cpu[1] = argument;
    /* Room above the first frame: syscalls copy stack arguments from above rsp. */
    cpu[7] = stack_top - 0x200 - 40;
    current_cpu = cpu;
    *(uint64_t *)(uintptr_t)cpu[7] = 0;
    jmp_buf boundary;
    guest_resume_boundary = &boundary;
    volatile uint32_t status = 0xc0000005;
    if (!lifted) {
        fprintf(stderr, "thread start routine %#llx is not lifted code\n", (unsigned long long)entry);
    } else if (!setjmp(boundary)) {
        if (guest_fault_signals_enabled())
            init_guest_signal_handler();
        lifted(cpu, 0);
        status = (uint32_t)cpu[0];
    } else {
        status = (uint32_t)resume_guest();
    }
    host_thunk terminate = wine_host_thunk_lookup("NtTerminateThread");
    if (terminate) {
        uint64_t slots[20] = {UINT64_C(0xfffffffffffffffe), status}; /* the current thread */
        terminate(slots);
    }
    pthread_exit(NULL);
}

/* Wine's thread start: the main thread first, on a TEB Wine allocated. */
static void wine_host_start_thread(void *entry, void *arg, int suspend, void *teb_address) {
    static _Atomic bool started;
    (void)suspend;
    host_teb = teb_address;
    host_peb = *(unsigned char **)(void *)(host_teb + 0x60);
    if (atomic_exchange(&started, true))
        wine_host_run_thread((uint64_t)(uintptr_t)entry, (uint64_t)(uintptr_t)arg);
    trace_time("Wine unix side booted", NULL);
    void *thunks = wine_host_load("hostthunks.dylib");
    wine_host_thunk_lookup = thunks ? (host_thunk (*)(const char *))dlsym(thunks, "host_syscall_thunk") : NULL;
    if (!wine_host_thunk_lookup)
        guest_trap("cannot load hostthunks.dylib from ARM64_RECOMPILER_WINE_HOST");
    exit(guest_run());
}

static int wine_host_boot(const char *directory, int argc, char **argv) {
    snprintf(wine_host_directory, sizeof wine_host_directory, "%s", directory);
    /* Wine maps and inspects the original program; the launcher runs this binary under its name. */
    const char *program = getenv("ARM64_RECOMPILER_WINE_EXE");
    if (!program)
        program = argv[0];
    unsigned char magic[2] = {0};
    FILE *file = fopen(program, "rb");
    if (!file || fread(magic, 1, 2, file) != 2 || magic[0] != 'M' || magic[1] != 'Z') {
        fprintf(stderr, "Wine host mode needs the original .exe: run as it, or set ARM64_RECOMPILER_WINE_EXE\n");
        return 125;
    }
    fclose(file);
    void *ntdll = wine_host_load("ntdll.so");
    struct wine_host_callbacks **slot = ntdll ? (struct wine_host_callbacks **)dlsym(ntdll, "__wine_host") : NULL;
    void (*wine_main)(int, char **) = ntdll ? (void (*)(int, char **))dlsym(ntdll, "__wine_main") : NULL;
    if (!slot || !wine_main) {
        fprintf(stderr, "ARM64_RECOMPILER_WINE_HOST has no host-mode ntdll.so: %s\n", directory);
        return 125;
    }
    static struct wine_host_callbacks callbacks = {wine_host_start_thread, wine_host_user_callback};
    *slot = &callbacks;
    setenv("WINELOADERNOEXEC", "1", 1); /* this process is the loader */
    if (!getenv("ARM64_RECOMPILER_NLS_DIR")) {
        char nls[1200];
        snprintf(nls, sizeof nls, "%s/../../../share/wine/nls", directory);
        setenv("ARM64_RECOMPILER_NLS_DIR", nls, 1);
    }
    char **wine_argv = calloc((size_t)argc + 2, sizeof *wine_argv);
    if (!wine_argv)
        return 125;
    wine_argv[0] = argv[0];
    wine_argv[1] = (char *)program;
    for (int i = 1; i < argc; ++i)
        wine_argv[i + 1] = argv[i];
    wine_hosted = true;
    wine_main(argc + 1, wine_argv);
    return 125;
}
