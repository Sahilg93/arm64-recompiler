#include <assert.h>
#define main console_entry
#include "console_runtime.c"
#undef main

const struct section guest_sections[1] = {{0}};
const uint64_t guest_section_count = 0;
const uint64_t guest_image_base = 0;
uint32_t lifted_console(void) { return 0; }

int main(void) {
    const uint64_t heap = 0x7fff2001;
    uint64_t original = guest_heap_realloc(heap, 0, 0, 3);
    assert(original);
    guest_store(original, 0x44332211, 4);
    assert(!guest_heap_realloc(heap, 8, original, UINT64_MAX));
    assert(guest_load(original, 4) == 0x44332211);
    uint64_t grown = guest_heap_realloc(heap, 8, original, 8);
    assert(grown && !heap_span(original, 1));
    assert(guest_load(grown, 8) == 0x332211);
    uint64_t shrunk = guest_heap_realloc(heap, 0, grown, 2);
    assert(shrunk && !heap_span(grown, 1));
    assert(guest_load(shrunk, 2) == 0x2211);
    assert(guest_heap_free(heap, 0, shrunk));
}
