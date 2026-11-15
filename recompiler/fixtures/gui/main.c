/*
 * A minimal Win32 GUI program: registers a class, opens a window, paints it,
 * and closes itself on a timer. Hosted on Wine's unix side, every user32 and
 * gdi32 call below runs lifted Wine code down to the NtUser/NtGdi syscalls,
 * which win32u.so and winemac.so serve natively.
 */
#include <stddef.h>
#include <stdint.h>

#define WINAPI __attribute__((ms_abi))
#define IMPORT __declspec(dllimport)
typedef void *HANDLE, *HWND, *HDC, *HBRUSH, *HINSTANCE, *HICON, *HCURSOR, *HMENU;
typedef uint16_t WCHAR, ATOM;
typedef uint32_t DWORD, UINT;
typedef int32_t BOOL, LONG;
typedef uint64_t WPARAM, UINT_PTR;
typedef int64_t LPARAM, LRESULT;
typedef LRESULT (WINAPI *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef struct { LONG left, top, right, bottom; } RECT;
typedef struct { LONG x, y; } POINT;
typedef struct { HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT pt; DWORD lPrivate; } MSG;
typedef struct { HDC hdc; BOOL fErase; RECT rcPaint; BOOL fRestore, fIncUpdate; uint8_t rgbReserved[32]; } PAINTSTRUCT;
typedef struct {
    UINT cbSize, style; WNDPROC lpfnWndProc; int cbClsExtra, cbWndExtra; HINSTANCE hInstance;
    HICON hIcon; HCURSOR hCursor; HBRUSH hbrBackground; const WCHAR *lpszMenuName, *lpszClassName; HICON hIconSm;
} WNDCLASSEXW;

IMPORT __declspec(noreturn) void WINAPI ExitProcess(UINT);
IMPORT HANDLE WINAPI GetStdHandle(DWORD);
IMPORT BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
IMPORT HINSTANCE WINAPI GetModuleHandleW(const WCHAR *);
IMPORT ATOM WINAPI RegisterClassExW(const WNDCLASSEXW *);
IMPORT HWND WINAPI CreateWindowExW(DWORD, const WCHAR *, const WCHAR *, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, void *);
IMPORT BOOL WINAPI ShowWindow(HWND, int);
IMPORT BOOL WINAPI GetMessageW(MSG *, HWND, UINT, UINT);
IMPORT BOOL WINAPI TranslateMessage(const MSG *);
IMPORT LRESULT WINAPI DispatchMessageW(const MSG *);
IMPORT LRESULT WINAPI DefWindowProcW(HWND, UINT, WPARAM, LPARAM);
IMPORT BOOL WINAPI DestroyWindow(HWND);
IMPORT void WINAPI PostQuitMessage(int);
IMPORT UINT_PTR WINAPI SetTimer(HWND, UINT_PTR, UINT, void *);
IMPORT HDC WINAPI BeginPaint(HWND, PAINTSTRUCT *);
IMPORT BOOL WINAPI EndPaint(HWND, const PAINTSTRUCT *);
IMPORT int WINAPI FillRect(HDC, const RECT *, HBRUSH);
IMPORT BOOL WINAPI GetClientRect(HWND, RECT *);
IMPORT HBRUSH WINAPI CreateSolidBrush(DWORD);
IMPORT BOOL WINAPI DeleteObject(void *);

enum { WM_CREATE = 0x0001, WM_DESTROY = 0x0002, WM_PAINT = 0x000f, WM_TIMER = 0x0113,
       WS_OVERLAPPEDWINDOW = 0x00cf0000, SW_SHOWNORMAL = 1 };

static int created, painted;
static LONG client_width, client_height;

static void say(const char *text) {
    DWORD length = 0, written;
    while (text[length]) ++length;
    WriteFile(GetStdHandle((DWORD)-11), text, length, &written, NULL);
}

static void say_number(const char *label, long value) {
    char digits[24], *end = digits + sizeof digits, *p = end;
    *--p = 0;
    *--p = '\n';
    unsigned long v = value < 0 ? 0 : (unsigned long)value;
    do *--p = (char)('0' + v % 10); while (v /= 10);
    say(label);
    say(p);
}

static LRESULT WINAPI window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        ++created;
        SetTimer(hwnd, 1, 2000, NULL);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        RECT client;
        HDC hdc = BeginPaint(hwnd, &ps);
        HBRUSH brush = CreateSolidBrush(0x00c86e28); /* BGR */
        GetClientRect(hwnd, &client);
        FillRect(hdc, &client, brush);
        DeleteObject(brush);
        EndPaint(hwnd, &ps);
        client_width = client.right - client.left;
        client_height = client.bottom - client.top;
        ++painted;
        return 0;
    }
    case WM_TIMER:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

void entry(void) {
    static const WCHAR class_name[] = {'F','i','x','t','u','r','e','W','i','n','d','o','w',0};
    static const WCHAR title[] = {'L','i','f','t','e','d',' ','w','i','n','d','o','w',0};
    HINSTANCE instance = GetModuleHandleW(NULL);
    WNDCLASSEXW wc = {.cbSize = sizeof wc, .style = 3, .lpfnWndProc = window_proc, .hInstance = instance,
                      .lpszClassName = class_name};
    if (!RegisterClassExW(&wc)) {
        say("RegisterClassExW failed\n");
        ExitProcess(10);
    }
    say("registered class\n");
    HWND hwnd = CreateWindowExW(0, class_name, title, WS_OVERLAPPEDWINDOW, 200, 200, 480, 320,
                                NULL, NULL, instance, NULL);
    if (!hwnd || created != 1) {
        say("CreateWindowExW failed\n");
        ExitProcess(11);
    }
    say("created window\n");
    ShowWindow(hwnd, SW_SHOWNORMAL);
    MSG message;
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    say_number("paints ", painted);
    say_number("client width ", client_width);
    say_number("client height ", client_height);
    ExitProcess(painted ? 0 : 12);
}
