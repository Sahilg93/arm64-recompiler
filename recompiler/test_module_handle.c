#include <assert.h>
#define main console_entry
#include "console_runtime.c"
#undef main

const struct section guest_sections[1] = {{0}};
const uint64_t guest_section_count = 0;
const uint64_t guest_image_base = 0x140000000;
uint32_t lifted_console(void) { return 0; }

int main(void) {
    uint64_t address = guest_heap_alloc(0x7fff2001, 8, 64);
    assert(address);
    assert(guest_module_handle(0, 1) == guest_image_base);
    const char kernel[] = "KeRnEl32.dll";
    for (size_t i = 0; i < sizeof kernel; ++i)
        guest_store(address + 2 * i, kernel[i], 2);
    assert(guest_module_handle(address, 1) == KERNEL_MODULE);
    unsigned references = kernel_references;
    uint64_t handle = guest_load_library(address, 0, 0);
    assert(handle == KERNEL_MODULE && kernel_references == references + 1);
    assert(guest_free_library(handle) && kernel_references == references);
    guest_store(address, 'X', 2);
    assert(!guest_module_handle(address, 1) && guest_get_last_error() == 126);
}
