#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void lifted_writer(uint64_t, uint64_t);

enum { DEST = 0x10000000, INPUT = 0x20000000 };
static _Thread_local unsigned char *destination;
static _Thread_local size_t destination_size;
static _Thread_local const unsigned char *input;
static _Thread_local size_t input_size;

static int fits(uint64_t address, uint32_t size, uint64_t base, size_t length) {
    return size > 0 && size <= sizeof(uint64_t) && address >= base &&
           size <= length && address - base <= length - size;
}

uint64_t guest_load(uint64_t address, uint32_t size) {
    uint64_t value = 0;
    if (!fits(address, size, INPUT, input_size))
        abort();
    memcpy(&value, input + (address - INPUT), size);
    return value;
}

void guest_store(uint64_t address, uint64_t value, uint32_t size) {
    if (!fits(address, size, DEST, destination_size))
        abort();
    memcpy(destination + (address - DEST), &value, size);
}

void write_export(unsigned char *out, size_t out_size, uint64_t scalar,
                  const unsigned char *in, size_t in_size) {
    if (!out || out_size > INPUT - DEST || (!in && in_size) ||
        in_size > INPUT - DEST)
        abort();
    destination = out;
    destination_size = out_size;
    input = in;
    input_size = in_size;
    lifted_writer(DEST, in ? INPUT : scalar);
}
