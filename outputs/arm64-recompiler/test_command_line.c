#include <assert.h>
#include <string.h>

#define main console_entry
#include "console_runtime.c"
#undef main

const struct section guest_sections[1] = {{0}};
const uint64_t guest_section_count = 0;
const uint64_t guest_image_base = 0;

uint32_t lifted_console(void) {
    const char expected[] = "\"program.exe\" \"-V\" \"two words\" \"a\\\"b\" \"tail\\\\\" \"\"";
    uint64_t ansi = guest_command_line(0);
    uint64_t wide = guest_command_line(1);
    assert(ansi == guest_command_line(0));
    assert(wide == guest_command_line(1));
    assert(memcmp(read_span(ansi, sizeof expected), expected, sizeof expected) == 0);
    for (size_t i = 0; i < sizeof expected; ++i)
        assert(guest_load(wide + 2 * i, 2) == (unsigned char)expected[i]);
    const char directory[] = "C:\\Windows\\System32";
    uint64_t buffer = guest_heap_alloc(0x7fff2001, 0, sizeof directory * 2);
    assert(guest_system_directory(0, 0, 0) == sizeof directory);
    assert(guest_system_directory(buffer, sizeof directory - 1, 0) == sizeof directory);
    assert(guest_system_directory(buffer, sizeof directory, 0) == sizeof directory - 1);
    assert(memcmp(read_span(buffer, sizeof directory), directory, sizeof directory) == 0);
    assert(guest_system_directory(buffer, sizeof directory, 1) == sizeof directory - 1);
    for (size_t i = 0; i < sizeof directory; ++i)
        assert(guest_load(buffer + 2 * i, 2) == (unsigned char)directory[i]);
    return 0;
}

int main(void) {
    char *args[] = {"launcher", "-V", "two words", "a\"b", "tail\\", "", NULL};
    return console_entry(6, args);
}
