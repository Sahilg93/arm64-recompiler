/*
 * A Winsock client: connects to a TCP echo server on 127.0.0.1 (port in
 * WINSOCK_PORT), sends a line, waits for the reply with select, and prints it.
 * Hosted on Wine's unix side, every call below runs Wine's lifted ws2_32.dll,
 * which reaches the socket through ntdll.so's device ioctls and ws2_32.so.
 */
#include <stddef.h>
#include <stdint.h>

#define WINAPI __attribute__((ms_abi))
#define IMPORT __declspec(dllimport)
typedef void *HANDLE;
typedef uint32_t DWORD, UINT;
typedef int32_t BOOL;
typedef uint64_t SOCKET;
struct sockaddr_in { uint16_t family, port; uint32_t address; uint8_t zero[8]; };
struct fd_set { UINT count; SOCKET sockets[64]; };
struct timeval { int32_t sec, usec; };

IMPORT __declspec(noreturn) void WINAPI ExitProcess(UINT);
IMPORT HANDLE WINAPI GetStdHandle(DWORD);
IMPORT BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
IMPORT DWORD WINAPI GetEnvironmentVariableA(const char *, char *, DWORD);
IMPORT int WINAPI WSAStartup(uint16_t, void *);
IMPORT int WINAPI WSACleanup(void);
IMPORT int WINAPI WSAGetLastError(void);
IMPORT SOCKET WINAPI socket(int, int, int);
IMPORT int WINAPI connect(SOCKET, const struct sockaddr_in *, int);
IMPORT int WINAPI send(SOCKET, const char *, int, int);
IMPORT int WINAPI recv(SOCKET, char *, int, int);
IMPORT int WINAPI select(int, struct fd_set *, struct fd_set *, struct fd_set *, const struct timeval *);
IMPORT int WINAPI closesocket(SOCKET);
IMPORT uint16_t WINAPI htons(uint16_t);

static void put(const char *text) {
    DWORD length = 0, written;
    while (text[length])
        ++length;
    WriteFile(GetStdHandle((DWORD)-11), text, length, &written, NULL);
}

static void number(const char *label, long value) {
    char digits[24], *end = digits + sizeof digits - 1;
    unsigned long magnitude = value < 0 ? -(unsigned long)value : (unsigned long)value;
    *end = 0;
    do
        *--end = (char)('0' + magnitude % 10);
    while (magnitude /= 10);
    if (value < 0)
        *--end = '-';
    put(label);
    put(end);
    put("\n");
}

static void fail(const char *what) {
    number(what, WSAGetLastError());
    ExitProcess(1);
}

void entry(void) {
    unsigned char data[512]; /* WSADATA */
    char text[16];
    unsigned port = 0;
    DWORD length = GetEnvironmentVariableA("WINSOCK_PORT", text, sizeof text);
    for (DWORD i = 0; i < length && i < sizeof text; ++i)
        port = port * 10 + (unsigned)(text[i] - '0');
    int status = WSAStartup(0x0202, data);
    if (status) {
        number("WSAStartup failed ", status);
        ExitProcess(1);
    }
    number("winsock version ", data[0]);
    SOCKET s = socket(2, 1, 6); /* AF_INET, SOCK_STREAM, IPPROTO_TCP */
    if (s == (SOCKET)-1)
        fail("socket failed ");
    struct sockaddr_in address = {2, htons((uint16_t)port), 0x0100007f, {0}};
    if (connect(s, &address, sizeof address))
        fail("connect failed ");
    put("connected\n");
    static const char request[] = "hello from winsock\n";
    number("sent ", send(s, request, sizeof request - 1, 0));
    static struct fd_set readable; /* static: no memset call in a program without a CRT */
    readable.count = 1;
    readable.sockets[0] = s;
    struct timeval timeout = {5, 0};
    number("select ", select(0, &readable, NULL, NULL, &timeout));
    char reply[64];
    int received = recv(s, reply, sizeof reply - 1, 0);
    if (received < 0)
        fail("recv failed ");
    reply[received] = 0;
    put("reply ");
    put(reply);
    number("closesocket ", closesocket(s));
    number("WSACleanup ", WSACleanup());
    ExitProcess(0);
}
