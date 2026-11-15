/*
 * Opens a window through Wine's unix-side win32u.so and winemac.so running
 * natively on arm64 macOS, with no Windows-side (x86) code at all. This file
 * plays the part of user32.dll: it registers a class, creates and shows a
 * window, pumps messages, and answers win32u's user-mode callbacks
 * (KeUserModeCallback) in plain C. It is the reference for what the lifted
 * user32.dll will do through the same boundary.
 *
 * usage: host_window <host-wine>/lib/wine/x86_64-unix <program.exe> [seconds]
 */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wingdi.h"
#include "winuser.h"
#include "ntgdi.h"
#include "ntuser.h"

struct wine_host_callbacks {
    void (*start_thread)(void *entry, void *arg, int suspend, void *teb);
    NTSTATUS (*user_callback)(ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len);
};

/* winemac.drv's unixlib.h */
struct localized_string { UINT id; UINT len; UINT64 str; };
struct macdrv_init_params { struct localized_string *strings; UINT64 app_icon_callback, app_quit_request_callback; };

static const char *unix_dir;
static int run_seconds = 5;
static int paints, creates;

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

static void ustr(UNICODE_STRING *str, const WCHAR *text) {
    USHORT length = 0;
    while (text[length]) ++length;
    str->Buffer = (WCHAR *)text;
    str->Length = length * sizeof(WCHAR);
    str->MaximumLength = str->Length + sizeof(WCHAR);
}

/* The window procedure a guest program would supply. */
static LRESULT window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_CREATE:
        ++creates;
        NtUserSetTimer(hwnd, 1, (UINT)run_seconds * 1000, NULL, 0);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = NtUserBeginPaint(hwnd, &ps);
        HBRUSH brush = NtGdiCreateSolidBrush(RGB(40, 110, 200), NULL);
        HGDIOBJ old = NtGdiSelectBrush(hdc, brush);
        NtGdiPatBlt(hdc, ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right - ps.rcPaint.left,
                    ps.rcPaint.bottom - ps.rcPaint.top, PATCOPY);
        NtGdiSelectBrush(hdc, old);
        NtGdiDeleteObjectApp(brush);
        NtUserEndPaint(hwnd, &ps);
        ++paints;
        return 0;
    }
    case WM_TIMER:
    case WM_CLOSE:
        NtUserDestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        NtUserPostQuitMessage(0);
        return 0;
    }
    return NtUserMessageCall(hwnd, msg, wparam, lparam, 0, NtUserDefWindowProc, FALSE);
}

static NTSTATUS load_driver(const WCHAR *path) {
    char name[64] = {0};
    size_t n = 0;
    for (const WCHAR *p = path; *p && n < sizeof name - 1; ++p) name[n++] = (char)*p;
    fprintf(stderr, "host: win32u asks for display driver \"%s\"\n", name);
    void *driver = load("winemac.so");
    NTSTATUS (**funcs)(void *) = dlsym(driver, "__wine_unix_call_funcs");
    static const WCHAR wine[] = {'W','i','n','e',0}, hide[] = {'H','i','d','e',0}, quit[] = {'Q','u','i','t',0},
                       others[] = {'H','i','d','e',' ','O','t','h','e','r','s',0}, all[] = {'S','h','o','w',' ','A','l','l',0},
                       window[] = {'W','i','n','d','o','w',0}, minimize[] = {'M','i','n','i','m','i','z','e',0},
                       zoom[] = {'Z','o','o','m',0}, full[] = {'F','u','l','l',' ','S','c','r','e','e','n',0},
                       front[] = {'B','r','i','n','g',' ','A','l','l',' ','t','o',' ','F','r','o','n','t',0};
    const WCHAR *texts[] = {wine, hide, hide, others, all, quit, quit, window, minimize, zoom, full, front};
    static const UINT ids[] = {0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x110, 0x111, 0x112, 0x113, 0x114};
    static struct localized_string strings[13];
    for (unsigned i = 0; i < 12; ++i) {
        UINT len = 0;
        while (texts[i][len]) ++len;
        strings[i] = (struct localized_string){ids[i], len, (UINT64)(UINT_PTR)texts[i]};
    }
    struct macdrv_init_params params = {strings, 0, 0};
    NTSTATUS status = funcs ? funcs[0](&params) : STATUS_DLL_NOT_FOUND;
    fprintf(stderr, "host: winemac init -> %#x\n", (unsigned)status);
    return status;
}

/* What user32.dll's KernelCallbackTable does, for the callbacks a plain window needs. */
static NTSTATUS host_user_callback(ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len) {
    static _Thread_local LRESULT result;
    *ret_ptr = NULL;
    *ret_len = 0;
    switch (id) {
    case NtUserLoadDriver:
        return load_driver(args);
    case NtUserInitBuiltinClasses:
        return STATUS_SUCCESS;
    case NtUserLoadImage:
    case NtUserLoadSysMenu:
        /* Built-in cursors, icons and the system menu come from user32's resources; none here. */
        return STATUS_SUCCESS;
    case NtUserCallWinProc: {
        const struct win_proc_params *params = args;
        if (getenv("HOST_TRACE"))
            fprintf(stderr, "host: winproc func %p procW %p hwnd %p msg %#x (%u bytes)\n", (void *)params->func,
                    (void *)params->procW, (void *)params->hwnd, params->msg, (unsigned)len);
        /* func is win32u's handle for the procedure; procW is the address the class registered. */
        LRESULT value = params->procW == (WNDPROC)window_proc
            ? window_proc(params->hwnd, params->msg, params->wparam, params->lparam)
            : NtUserMessageCall(params->hwnd, params->msg, params->wparam, params->lparam, 0, NtUserDefWindowProc, FALSE);
        /*
         * Messages with pointer arguments arrive with a packed copy of the pointed-to
         * data after the params (len > sizeof *params), for clients in another address
         * space. This client shares win32u's address space, so it used the original
         * lparam directly and returns only the result: win32u then copies nothing
         * back. (It frees the packed copy before reading the reply, so the reply must
         * not point into it.)
         */
        result = value;
        *ret_ptr = &result;
        *ret_len = sizeof result;
        return STATUS_SUCCESS;
    }
    default:
        fprintf(stderr, "host: unhandled user callback %u (%u bytes)\n", (unsigned)id, (unsigned)len);
        return STATUS_NOT_IMPLEMENTED;
    }
}

static void host_start(void *entry, void *arg, int suspend, void *teb) {
    (void)entry; (void)arg; (void)suspend; (void)teb;
    void *win32u = load("win32u.so");
    NTSTATUS (**funcs)(void *) = dlsym(win32u, "__wine_unix_call_funcs");
    NTSTATUS status = funcs[0](NULL);
    fprintf(stderr, "host: win32u init -> %#x\n", (unsigned)status);

    /* user32.dll's DllMain hands win32u its table of built-in window procedures; this
       also attaches the process to its window station and desktop. The entries only
       need to be distinct: host_user_callback routes them all to DefWindowProc. */
    static char placeholders[2 * NTUSER_NB_PROCS + NTUSER_NB_WORKERS];
    static ntuser_client_func_ptr procs_a[NTUSER_NB_PROCS], procs_w[NTUSER_NB_PROCS], workers[NTUSER_NB_WORKERS];
    for (unsigned i = 0; i < NTUSER_NB_PROCS; ++i) {
        procs_a[i][0] = (WNDPROC)(void *)&placeholders[i];
        procs_w[i][0] = (WNDPROC)(void *)&placeholders[NTUSER_NB_PROCS + i];
    }
    for (unsigned i = 0; i < NTUSER_NB_WORKERS; ++i)
        workers[i][0] = (WNDPROC)(void *)&placeholders[2 * NTUSER_NB_PROCS + i];
    /* The module handle stands for user32.dll; it must differ from the program's own. */
    status = NtUserInitializeClientPfnArrays(procs_a, procs_w, workers, (HINSTANCE)(void *)placeholders);
    fprintf(stderr, "host: NtUserInitializeClientPfnArrays -> %#x\n", (unsigned)status);

    static const WCHAR class_name[] = {'H','o','s','t','W','i','n','d','o','w',0};
    static const WCHAR title[] = {'N','a','t','i','v','e',' ','w','i','n','3','2','u',' ','o','n',' ','a','r','m','6','4',0};
    UNICODE_STRING name, version, window_name;
    ustr(&name, class_name);
    ustr(&version, class_name);
    ustr(&window_name, title);
    struct client_menu_name menu_name = {0};
    WNDCLASSEXW wc = {.cbSize = sizeof wc, .style = CS_HREDRAW | CS_VREDRAW, .lpfnWndProc = (WNDPROC)window_proc,
                      .hInstance = (HINSTANCE)entry, .lpszClassName = class_name};
    ATOM atom = NtUserRegisterClassExWOW(&wc, &name, &version, &menu_name, 0, 0, NULL);
    fprintf(stderr, "host: RegisterClass -> %#x\n", atom);
    HWND hwnd = NtUserCreateWindowEx(0, &name, &version, &window_name, WS_OVERLAPPEDWINDOW,
                                     200, 200, 480, 320, NULL, NULL, (HINSTANCE)entry, NULL, 0,
                                     (HINSTANCE)entry, class_name, FALSE);
    fprintf(stderr, "host: CreateWindowEx -> %p (WM_CREATE seen %d)\n", (void *)hwnd, creates);
    if (!hwnd)
        exit(3);
    NtUserShowWindow(hwnd, SW_SHOWNORMAL);
    MSG msg;
    while (NtUserGetMessage(&msg, NULL, 0, 0)) {
        NtUserTranslateMessage(&msg, 0);
        NtUserDispatchMessage(&msg);
    }
    fprintf(stderr, "host: message loop ended; WM_PAINT handled %d time(s)\n", paints);
    exit(paints ? 0 : 4);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <unix-lib-dir> <program.exe> [seconds]\n", argv[0]);
        return 2;
    }
    unix_dir = argv[1];
    if (argc > 3)
        run_seconds = atoi(argv[3]);
    static struct wine_host_callbacks callbacks = {host_start, host_user_callback};
    void *ntdll = load("ntdll.so");
    struct wine_host_callbacks **slot = dlsym(ntdll, "__wine_host");
    void (*wine_main)(int, char **) = dlsym(ntdll, "__wine_main");
    if (!slot || !wine_main) {
        fprintf(stderr, "host: ntdll.so lacks the host-mode entry points\n");
        return 2;
    }
    *slot = &callbacks;
    setenv("WINELOADERNOEXEC", "1", 1);
    char *wine_argv[] = {argv[0], argv[2], NULL};
    wine_main(2, wine_argv);
    return 1;
}
