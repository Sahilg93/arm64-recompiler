/*
 * Drives a running notepad through window messages and times it. Runs as an
 * ordinary x86-64 Windows program under Wine in the same prefix, so the sender
 * side is identical whichever notepad (lifted or Wine's own) is the target.
 *
 * usage: probe.exe            measure, then close notepad
 *        probe.exe close      only close notepad
 * Output: one "name value unit" line per measurement.
 */
#include <stddef.h>
#include <stdint.h>

#define WINAPI __attribute__((ms_abi))
#define IMPORT __declspec(dllimport)
typedef void *HANDLE, *HWND;
typedef uint16_t WCHAR;
typedef uint32_t DWORD, UINT;
typedef int32_t BOOL;
typedef uint64_t WPARAM;
typedef int64_t LPARAM, LRESULT;

IMPORT __declspec(noreturn) void WINAPI ExitProcess(UINT);
IMPORT HANDLE WINAPI GetStdHandle(DWORD);
IMPORT BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
IMPORT BOOL WINAPI QueryPerformanceCounter(int64_t *);
IMPORT BOOL WINAPI QueryPerformanceFrequency(int64_t *);
IMPORT void WINAPI Sleep(DWORD);
IMPORT WCHAR *WINAPI GetCommandLineW(void);
IMPORT HWND WINAPI FindWindowW(const WCHAR *, const WCHAR *);
IMPORT HWND WINAPI FindWindowExW(HWND, HWND, const WCHAR *, const WCHAR *);
IMPORT LRESULT WINAPI SendMessageW(HWND, UINT, WPARAM, LPARAM);
IMPORT BOOL WINAPI PostMessageW(HWND, UINT, WPARAM, LPARAM);
IMPORT BOOL WINAPI RedrawWindow(HWND, const void *, HANDLE, UINT);

enum { WM_NULL = 0, WM_SETTEXT = 0x000c, WM_GETTEXTLENGTH = 0x000e, WM_CLOSE = 0x0010, WM_VSCROLL = 0x0115,
       EM_SETSEL = 0x00b1, EM_REPLACESEL = 0x00c2, EM_SETMODIFY = 0x00b9, EM_GETLINECOUNT = 0x00ba,
       EM_SCROLLCARET = 0x00b7, EM_LINESCROLL = 0x00b6, EM_GETFIRSTVISIBLELINE = 0x00ce,
       SB_PAGEDOWN = 3, SB_PAGEUP = 2, RDW_INVALIDATE = 1, RDW_ERASE = 4, RDW_UPDATENOW = 0x100 };

static int64_t frequency;
static WCHAR big[1100000];

static double now_us(void) {
    int64_t counter;
    QueryPerformanceCounter(&counter);
    return (double)counter * 1e6 / (double)frequency;
}

static void put(const char *text) {
    DWORD length = 0, written;
    while (text[length]) ++length;
    WriteFile(GetStdHandle((DWORD)-11), text, length, &written, NULL);
}

/* "name value unit": value printed with two decimals. */
static void report(const char *name, double value, const char *unit) {
    char digits[40], *p = digits + sizeof digits;
    if (value < 0) value = 0;
    uint64_t scaled = (uint64_t)(value * 100 + 0.5);
    *--p = 0;
    *--p = (char)('0' + scaled % 10); scaled /= 10;
    *--p = (char)('0' + scaled % 10); scaled /= 10;
    *--p = '.';
    do *--p = (char)('0' + scaled % 10); while (scaled /= 10);
    put(name); put(" "); put(p); put(" "); put(unit); put("\n");
}

void entry(void) {
    static const WCHAR notepad[] = {'N','o','t','e','p','a','d',0}, edit_class[] = {'E','d','i','t',0};
    static const WCHAR empty[] = {0};
    QueryPerformanceFrequency(&frequency);
    HWND main = NULL, edit = NULL;
    for (int i = 0; i < 400 && !edit; ++i) {
        main = FindWindowW(notepad, NULL);
        edit = main ? FindWindowExW(main, NULL, edit_class, NULL) : NULL;
        if (!edit) Sleep(25);
    }
    if (!edit) {
        put("error notepad window not found\n");
        ExitProcess(2);
    }
    const WCHAR *line = GetCommandLineW();
    int only_close = 0;
    for (const WCHAR *c = line; *c; ++c)
        if (c[0] == ' ' && c[1] == 'c' && c[2] == 'l' && c[3] == 'o' && c[4] == 's' && c[5] == 'e')
            only_close = 1;
    if (!only_close) {
        /* 1. Message round trips: a query the edit control answers from memory. */
        double start = now_us(), worst = 0;
        enum { PINGS = 3000 };
        for (int i = 0; i < PINGS; ++i) {
            double t = now_us();
            SendMessageW(edit, WM_GETTEXTLENGTH, 0, 0);
            double d = now_us() - t;
            if (d > worst) worst = d;
        }
        report("message_roundtrip_mean", (now_us() - start) / PINGS, "us");
        report("message_roundtrip_worst", worst, "us");

        /* 2. Typing-like edits: append 300 lines one at a time (layout + invalidate each). */
        static const WCHAR text[] = {'T','h','e',' ','q','u','i','c','k',' ','b','r','o','w','n',' ','f','o','x',' ',
                                     'j','u','m','p','s',' ','o','v','e','r',' ','t','h','e',' ','l','a','z','y',' ',
                                     'd','o','g',' ','0','1','2','3','4','5','6','7','8','9','\r','\n',0};
        SendMessageW(edit, WM_SETTEXT, 0, (LPARAM)empty);
        enum { APPENDS = 300 };
        start = now_us();
        for (int i = 0; i < APPENDS; ++i) {
            SendMessageW(edit, EM_SETSEL, (WPARAM)-1, -1);
            SendMessageW(edit, EM_REPLACESEL, 0, (LPARAM)text);
        }
        RedrawWindow(edit, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
        report("append_line_mean", (now_us() - start) / APPENDS, "us");
        report("lines_after_append", (double)SendMessageW(edit, EM_GETLINECOUNT, 0, 0), "lines");

        /* 3. Full repaint of a window full of text (GDI text output). */
        enum { REPAINTS = 100 };
        start = now_us();
        for (int i = 0; i < REPAINTS; ++i)
            RedrawWindow(edit, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
        report("repaint_mean", (now_us() - start) / REPAINTS, "us");

        /* 4. Scrolling: page up and down through the text, painting each step. */
        enum { SCROLLS = 100 };
        start = now_us();
        for (int i = 0; i < SCROLLS; ++i) {
            SendMessageW(edit, WM_VSCROLL, i % 12 < 6 ? SB_PAGEUP : SB_PAGEDOWN, 0);
            RedrawWindow(edit, NULL, NULL, RDW_UPDATENOW);
        }
        report("scroll_page_mean", (now_us() - start) / SCROLLS, "us");
        /* Check that scrolling really moves the view: where it is after six pages up
           from the end, then after six pages back down. */
        SendMessageW(edit, EM_SETSEL, (WPARAM)-1, -1);
        SendMessageW(edit, EM_SCROLLCARET, 0, 0);
        report("first_visible_at_end", (double)SendMessageW(edit, EM_GETFIRSTVISIBLELINE, 0, 0), "line");
        for (int i = 0; i < 3; ++i)
            SendMessageW(edit, WM_VSCROLL, SB_PAGEUP, 0);
        report("first_visible_after_3_pages_up", (double)SendMessageW(edit, EM_GETFIRSTVISIBLELINE, 0, 0), "line");
        for (int i = 0; i < 3; ++i)
            SendMessageW(edit, WM_VSCROLL, SB_PAGEDOWN, 0);
        report("first_visible_after_3_pages_down", (double)SendMessageW(edit, EM_GETFIRSTVISIBLELINE, 0, 0), "line");

        /* 5. Bulk load: replace the contents with about 1 MB of text (20,000 lines). */
        size_t n = 0;
        for (int row = 0; row < 20000; ++row) {
            for (int col = 0; col < 50; ++col)
                big[n++] = (WCHAR)('a' + (row + col) % 26);
            big[n++] = '\r';
            big[n++] = '\n';
        }
        big[n] = 0;
        start = now_us();
        SendMessageW(edit, WM_SETTEXT, 0, (LPARAM)big);
        RedrawWindow(edit, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
        report("set_text_1mb", (now_us() - start) / 1000, "ms");
        report("lines_after_set_text", (double)SendMessageW(edit, EM_GETLINECOUNT, 0, 0), "lines");
        start = now_us();
        SendMessageW(edit, EM_SETSEL, (WPARAM)-1, -1);
        SendMessageW(edit, EM_SCROLLCARET, 0, 0);
        RedrawWindow(edit, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
        report("jump_to_end_1mb", (now_us() - start) / 1000, "ms");
        start = now_us();
        SendMessageW(edit, EM_REPLACESEL, 0, (LPARAM)text);
        RedrawWindow(edit, NULL, NULL, RDW_UPDATENOW);
        report("append_line_at_1mb", (now_us() - start) / 1000, "ms");
    }
    /* Leave nothing to save, then ask notepad to close. */
    SendMessageW(edit, WM_SETTEXT, 0, (LPARAM)empty);
    SendMessageW(edit, EM_SETMODIFY, 0, 0);
    double t = now_us();
    PostMessageW(main, WM_CLOSE, 0, 0);
    for (int i = 0; i < 2000 && FindWindowW(notepad, NULL); ++i)
        Sleep(5);
    report("close_window", (now_us() - t) / 1000, "ms");
    ExitProcess(0);
}
