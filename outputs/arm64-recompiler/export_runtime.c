#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern const unsigned char guest_ro[];
extern const uint64_t guest_ro_start, guest_ro_size;
extern int32_t lifted_export(uint64_t, uint64_t);

enum { A = 0x10000000, B = 0x20000000 };
static _Thread_local const unsigned char *inputs[2];
static _Thread_local size_t lengths[2];
static _Thread_local uint64_t saved_frame;
static _Thread_local int frame_initialized;

static int fits(uint64_t address, uint64_t count, uint64_t base, uint64_t size) {
    return address >= base && count <= size && address - base <= size - count;
}

uint64_t guest_load(uint64_t address, uint32_t count) {
    if (!count || count > sizeof(uint64_t))
        abort();
    if (address == 0x30000ff0 && count == 8 && frame_initialized)
        return saved_frame;
    const unsigned char *source = NULL;
    if (fits(address, count, A, lengths[0]))
        source = inputs[0] + (address - A);
    else if (fits(address, count, B, lengths[1]))
        source = inputs[1] + (address - B);
    else if (fits(address, count, guest_ro_start, guest_ro_size))
        source = guest_ro + (address - guest_ro_start);
    if (!source)
        abort();
    uint64_t value = 0;
    memcpy(&value, source, count);
    return value;
}

void guest_store(uint64_t address, uint64_t value, uint32_t count) {
    if (address != 0x30000ff0 || count != 8)
        abort();
    saved_frame = value;
    frame_initialized = 1;
}

void check_export_stack(uint64_t rsp) {
    if (rsp != 0x30000ff8)
        abort();
}

int32_t compare_export(const unsigned char *a, size_t a_length,
                       const unsigned char *b, size_t b_length) {
    if ((!a && a_length) || (!b && b_length) || a_length > B - A || b_length > B - A)
        abort();
    frame_initialized = 0;
    inputs[0] = a;
    inputs[1] = b;
    lengths[0] = a_length;
    lengths[1] = b_length;
    return lifted_export(a ? A : 0, b ? B : 0);
}
