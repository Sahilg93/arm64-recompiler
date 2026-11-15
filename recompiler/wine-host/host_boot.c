/*
 * Boots Wine's unix-side ntdll.so (patched for host mode) inside this native
 * arm64 process, with no Windows-side code running: the process connects to
 * wineserver as an x86-64 process, then control comes back to host_start()
 * where a real program would start running lifted x86-64 code.
 *
 * usage: host_boot <host-wine>/lib/wine/x86_64-unix <program.exe>
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int NTSTATUS;
typedef unsigned int ULONG;

struct wine_host_callbacks {
    void (*start_thread)(void *entry, void *arg, int suspend, void *teb);
    NTSTATUS (*user_callback)(ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len);
};

static const char *unix_dir;

static void *load(const char *name) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", unix_dir, name);
    void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "host: cannot load %s: %s\n", path, dlerror());
        exit(2);
    }
    return handle;
}

static NTSTATUS host_user_callback(ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len) {
    (void)args;
    fprintf(stderr, "host: user callback %u (%u bytes)\n", id, len);
    *ret_ptr = NULL;
    *ret_len = 0;
    return 0;
}

static void host_start(void *entry, void *arg, int suspend, void *teb) {
    (void)suspend;
    printf("host: Wine unix side is up; entry %p peb %p teb %p\n", entry, arg, teb);
    void *win32u = load("win32u.so");
    NTSTATUS (**funcs)(void *) = dlsym(win32u, "__wine_unix_call_funcs");
    printf("host: win32u init -> %#x\n", funcs ? funcs[0](NULL) : -1);
    ULONG (*double_click)(void) = dlsym(win32u, "NtUserGetDoubleClickTime");
    void *(*desktop)(ULONG) = dlsym(win32u, "NtUserGetThreadDesktop");
    ULONG (*thread_id)(void) = dlsym(RTLD_DEFAULT, "GetCurrentThreadId");
    (void)thread_id;
    if (double_click)
        printf("host: NtUserGetDoubleClickTime -> %u ms\n", double_click());
    if (desktop)
        printf("host: NtUserGetThreadDesktop(0) -> %p\n", desktop(0));
    fflush(stdout);
    exit(0);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <unix-lib-dir> <program.exe> [args]\n", argv[0]);
        return 2;
    }
    unix_dir = argv[1];
    static struct wine_host_callbacks callbacks = {host_start, host_user_callback};
    void *ntdll = load("ntdll.so");
    struct wine_host_callbacks **slot = dlsym(ntdll, "__wine_host");
    void (*wine_main)(int, char **) = dlsym(ntdll, "__wine_main");
    if (!slot || !wine_main) {
        fprintf(stderr, "host: ntdll.so lacks the host-mode entry points\n");
        return 2;
    }
    *slot = &callbacks;
    /* This process is the loader: Wine must not re-exec its own. */
    setenv("WINELOADERNOEXEC", "1", 1);
    /* Wine expects argv[0] to be the loader and argv[1] the program. */
    argv[1] = argv[0];
    wine_main(argc - 1, argv + 1);
    return 1;
}
