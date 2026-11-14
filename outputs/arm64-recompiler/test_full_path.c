#include <assert.h>
#define main console_entry
#include "console_runtime.c"
#undef main

const struct section guest_sections[1] = {{0}};
const uint64_t guest_section_count = 0;
const uint64_t guest_image_base = 0x140000000;
uint32_t lifted_console(void) { return 0; }

int main(void) {
    const uint64_t input = STACK_BASE;
    const uint64_t output = STACK_BASE + 256;
    const uint64_t file_part = STACK_BASE + 512;
    const char source[] = "C:/tmp/./parent/../sample.txt";
    const char expected[] = "C:\\tmp\\sample.txt";
    for (size_t i = 0; i < sizeof source; ++i)
        guest_store(input + 2 * i, source[i], 2);

    assert(subsys_GetFullPathNameW(input, 0, 0, 0) == sizeof expected);
    assert(subsys_GetFullPathNameW(input, sizeof expected - 1, output, file_part) == sizeof expected);
    assert(subsys_GetFullPathNameW(input, sizeof expected, output, file_part) == sizeof expected - 1);
    for (size_t i = 0; i < sizeof expected; ++i)
        assert(guest_load(output + 2 * i, 2) == (unsigned char)expected[i]);
    assert(guest_load(file_part, 8) == output + 2 * strlen("C:\\tmp\\"));

    char host[32];
    normalize_win_path_a(expected, host, sizeof host);
    assert(strcmp(host, "/tmp/sample.txt") == 0);

    FILE *file = tmpfile();
    assert(file);
    int fd = dup(fileno(file));
    assert(fd >= 0 && write(fd, "test data", 9) == 9 && lseek(fd, 0, SEEK_SET) == 0);
    uint64_t handle = alloc_handle(HANDLE_KIND_FILE);
    assert(handle);
    get_handle(handle)->fd = fd;
    assert(subsys_GetFileInformationByHandle(handle, output));
    assert(guest_load(output + 36, 4) == 9);
    assert(subsys_ReadFile(handle, output, 64, file_part, 0));
    assert(guest_load(file_part, 4) == 9 && guest_load(output, 1) == 't');
    assert(lseek(fd, 0, SEEK_SET) == 0);
    const uint64_t read_args = STACK_BASE + 640;
    guest_store(read_args, file_part, 8);
    guest_store(read_args + 8, output, 8);
    guest_store(read_args + 16, 64, 4);
    guest_store(read_args + 24, 0, 8);
    assert(guest_nt_read_file(handle, 0, 0, 0, read_args) == 0);
    assert(guest_load(file_part + 8, 8) == 9);
    assert(guest_nt_read_file(handle, 0, 0, 0, read_args) == 0xc0000011);
    assert(guest_load(file_part + 8, 8) == 0);
    assert(guest_close_handle(handle));
    fclose(file);
}
