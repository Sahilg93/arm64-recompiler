/*
 * Waits for an on-screen window whose title contains a string, and prints
 * "<elapsed ms> <owner pid> <width>x<height> <title>". Used to time how long a
 * program takes to show its window, without needing its process id up front.
 *
 * usage: winwait <title substring> <timeout seconds> [exclude pid]
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3)
        return 2;
    double timeout = atof(argv[2]);
    int exclude = argc > 3 ? atoi(argv[3]) : 0;
    mach_timebase_info_data_t base;
    mach_timebase_info(&base);
    uint64_t start = mach_absolute_time();
    for (;;) {
        double elapsed = (double)(mach_absolute_time() - start) * base.numer / base.denom / 1e6;
        CFArrayRef list = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
        for (CFIndex i = 0; list && i < CFArrayGetCount(list); ++i) {
            CFDictionaryRef window = CFArrayGetValueAtIndex(list, i);
            CFStringRef title = CFDictionaryGetValue(window, kCGWindowName);
            char name[512] = "";
            if (!title || !CFStringGetCString(title, name, sizeof name, kCFStringEncodingUTF8) || !strstr(name, argv[1]))
                continue;
            int pid = 0;
            CGRect bounds = {0};
            CFNumberGetValue(CFDictionaryGetValue(window, kCGWindowOwnerPID), kCFNumberIntType, &pid);
            CGRectMakeWithDictionaryRepresentation(CFDictionaryGetValue(window, kCGWindowBounds), &bounds);
            if (pid == exclude)
                continue;
            printf("%.1f %d %.0fx%.0f %s\n", elapsed, pid, bounds.size.width, bounds.size.height, name);
            return 0;
        }
        if (list)
            CFRelease(list);
        if (elapsed > timeout * 1000)
            return 1;
        usleep(5000);
    }
}
