/*
 * A program that uses the real Universal CRT. Built against the Windows SDK's
 * ucrt.lib, its CRT imports name API-set contracts (api-ms-win-crt-*-l1-1-0.dll)
 * that resolve to ucrtbase.dll. It also imports:
 *   - strlen from ucrtbase.dll by ordinal only (ordinal.def, made by test.sh),
 *   - __threadid, which ucrtbase.dll forwards to kernel32.GetCurrentThreadId,
 *   - order_message from crtorder.dll, whose DllMain needs an initialized CRT.
 * There is no CRT startup code: start() is the entry point and leaves through
 * exit(), which flushes stdio.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int _fltused;

__declspec(dllimport) size_t crt_strlen_by_ordinal(const char *);
__declspec(dllimport) unsigned long __threadid(void);
__declspec(dllimport) const char *order_message(void);

static int compare(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

void start(void) {
    printf("printf: %d %s %.3f %x %5.1e\n", 42, "text", 3.14159, 255u, 12345.678);

    static const int initial[] = {5, 3, 9, 1, 7, 2, 8, 4};
    int *values = malloc(sizeof initial);
    if (!values)
        exit(2);
    for (int i = 0; i < 8; ++i)
        values[i] = initial[i];
    qsort(values, 8, sizeof *values, compare);
    printf("qsort:");
    for (int i = 0; i < 8; ++i)
        printf(" %d", values[i]);
    printf("\n");
    free(values);

    char *end;
    double parsed = strtod("  -12.5e2xyz", &end);
    printf("strtod: %.1f rest=%s\n", parsed, end);

    FILE *file = fopen("crt-fixture.tmp", "wb");
    if (!file || fwrite("hello file\n", 1, 11, file) != 11 || fclose(file))
        exit(3);
    char buffer[32];
    file = fopen("crt-fixture.tmp", "rb");
    if (!file)
        exit(4);
    size_t count = fread(buffer, 1, sizeof buffer - 1, file);
    buffer[count] = 0;
    if (fclose(file) || remove("crt-fixture.tmp"))
        exit(5);
    printf("fread: %u %s", (unsigned)count, buffer);

    printf("ordinal strlen: %u\n", (unsigned)crt_strlen_by_ordinal("ordinal"));
    printf("forwarded __threadid matches: %d\n", __threadid() == GetCurrentThreadId());
    printf("DllMain: %s\n", order_message());
    exit(0);
}
