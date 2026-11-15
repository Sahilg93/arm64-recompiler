#include <stdint.h>
#include <stdbool.h>
#include "console_modules.h"

uint64_t guest_indirect_dispatch(void *, uint64_t, uint64_t, uint32_t);
uint64_t guest_rtl_lookup_function_entry(uint64_t, uint64_t, uint64_t);
uint64_t guest_load(uint64_t, uint32_t);
uint64_t guest_rtl_virtual_unwind(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
void guest_store(uint64_t, uint64_t, uint32_t);

static const unsigned char machine_code[] = {
    0xe8, 0x0b, 0, 0, 0,             /* call 0x1010 */
    0xc3,                            /* ret */
    0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90,
    0xb8, 42, 0, 0, 0,              /* mov eax, 42 */
    0xc3,
    0xb8, 42, 0, 0, 0,              /* mov eax, 42 */
    0xc3,
    0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3, /* add rsp, 32; pop rbx; ret */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

};

static const unsigned char runtime_functions[] = {
    0x00, 0x10, 0, 0,  0x06, 0x10, 0, 0,  0x00, 0x30, 0, 0,
    0x10, 0x10, 0, 0,  0x16, 0x10, 0, 0,  0x0c, 0x30, 0, 0,
    0x16, 0x10, 0, 0,  0x22, 0x10, 0, 0,  0x00, 0x30, 0, 0,
    0x24, 0x10, 0, 0,  0x28, 0x10, 0, 0,  0x20, 0x30, 0, 0,
};
static const unsigned char unwind_info[] = {
    9, 4, 2, 0,          /* Version 1, exception handler, two unwind slots. */
    4, 0x32, 1, 0x30,    /* Allocate 32 bytes, then restore pushed RBX. */
    0x20, 0x10, 0, 0,    /* Handler RVA. */
    0x21, 4, 2, 0,       /* Chain record with an extra RSI save. */
    4, 0x64, 1, 0,       /* Save RSI at RSP + 8. */
    0, 0x10, 0, 0,       /* Primary begin RVA. */
    6, 0x10, 0, 0,       /* Primary end RVA. */
    0, 0x30, 0, 0,       /* Primary unwind RVA. */
    1, 1, 1, 0, 1, 0x1a, 0, 0, /* Machine frame with an error code. */
};
const struct section guest_sections[] = {
    {0x1000, sizeof machine_code, sizeof machine_code, machine_code, 0},
    {0x2000, sizeof runtime_functions, sizeof runtime_functions, runtime_functions, 0},
    {0x3000, sizeof unwind_info, sizeof unwind_info, unwind_info, 0},
};
const uint64_t guest_section_count = 3;
const uint64_t guest_exception_rva = 0x2000;
const uint64_t guest_exception_size = sizeof runtime_functions;
const uint64_t guest_image_base = 0x140000000;
const struct { uint64_t start, size; } guest_code_ranges[] = {{0x1000, sizeof machine_code}};
const uint64_t guest_code_range_count = 1;

static void compiled(void *context, uint64_t return_va) {
    (void)return_va;
    uint64_t *cpu = context;
    cpu[0] = 73;
    cpu[7] += 8;
}
uint64_t guest_add_vectored_exception_handler(uint32_t, uint64_t);
uint64_t guest_remove_vectored_exception_handler(uint64_t);
void guest_raise_exception(uint32_t, uint32_t, uint32_t, uint64_t, uint64_t, uint64_t);
void guest_set_cpu(void *);

static unsigned exception_calls;
static void on_exception(void *context, uint64_t return_va) {
    (void)return_va;
    uint64_t *cpu = context;
    bool language = cpu[2] == 0x20fff08;
    uint64_t record = language ? cpu[1] : guest_load(cpu[1], 8);
    if (guest_load(record, 4) == 0xe0001234 && guest_load(record + 32, 8) == 17)
        ++exception_calls;
    cpu[0] = language ? 0 : UINT32_MAX;
    cpu[7] += 8;
}

const struct guest_dispatch_entry guest_dispatch_table[] = {{0x1010, compiled}, {0x1020, on_exception}};
const uint64_t guest_dispatch_count = 2;

uint32_t lifted_console(void) {
    uint64_t output = 0x20ffe00;
    if (guest_rtl_lookup_function_entry(guest_image_base + 0x1011, output, 0) !=
            guest_image_base + 0x200c || guest_load(output, 8) != guest_image_base ||
        guest_rtl_lookup_function_entry(guest_image_base + 0x1022, 0, 0) != 0)
        return 4;
    uint64_t ctx = 0x20fe000, rsp = 0x20fff00;
    uint64_t frame = output + 8, data = output + 16;
    guest_store(ctx + 0x98, rsp, 8);
    guest_store(rsp + 32, 0x12345678, 8);
    guest_store(rsp + 40, guest_image_base + 0x1011, 8);
    if (guest_rtl_virtual_unwind(1, guest_image_base, guest_image_base + 0x1004,
                                guest_image_base + 0x2000, ctx, data, frame, 0) !=
            guest_image_base + 0x1020 ||
        guest_load(ctx + 0x90, 8) != 0x12345678 ||
        guest_load(ctx + 0x98, 8) != rsp + 48 ||
        guest_load(ctx + 0xf8, 8) != guest_image_base + 0x1011 ||
        guest_load(frame, 8) != rsp || guest_load(data, 8) != guest_image_base + 0x300c)
        return 5;
    guest_store(ctx + 0x98, rsp + 32, 8);
    if (guest_rtl_virtual_unwind(1, guest_image_base, guest_image_base + 0x1002,
                                guest_image_base + 0x2000, ctx, data, frame, 0) ||
        guest_load(ctx + 0x98, 8) != rsp + 48 || guest_load(data, 8))
        return 6;

    guest_store(ctx + 0x98, rsp, 8);
    guest_store(rsp + 8, 0x87654321, 8);
    if (guest_rtl_virtual_unwind(1, guest_image_base, guest_image_base + 0x1014,
                                guest_image_base + 0x200c, ctx, data, frame, 0) !=
            guest_image_base + 0x1020 ||
        guest_load(ctx + 0xa8, 8) != 0x87654321 ||
        guest_load(ctx + 0x90, 8) != 0x12345678 ||
        guest_load(ctx + 0x98, 8) != rsp + 48 ||
        guest_load(ctx + 0xf8, 8) != guest_image_base + 0x1011 ||
        guest_load(data, 8) != guest_image_base + 0x300c)
        return 7;

    guest_store(ctx + 0x98, rsp + 32, 8);
    if (guest_rtl_virtual_unwind(1, guest_image_base, guest_image_base + 0x1020,
                                guest_image_base + 0x2018, ctx, data, frame, 0) ||
        guest_load(ctx + 0x90, 8) != 0x12345678 ||
        guest_load(ctx + 0x98, 8) != rsp + 48 ||
        guest_load(ctx + 0xf8, 8) != guest_image_base + 0x1011 ||
        guest_load(data, 8))
        return 8;

    guest_store(ctx + 0x98, rsp, 8);
    guest_store(rsp + 8, guest_image_base + 0x1011, 8);
    guest_store(rsp + 16, 0x33, 8);
    guest_store(rsp + 24, 0x202, 8);
    guest_store(rsp + 32, rsp + 64, 8);
    guest_store(rsp + 40, 0x2b, 8);
    if (guest_rtl_virtual_unwind(0, guest_image_base, guest_image_base + 0x1025,
                                guest_image_base + 0x2024, ctx, data, frame, 0) ||
        guest_load(ctx + 0x98, 8) != rsp + 64 ||
        guest_load(ctx + 0xf8, 8) != guest_image_base + 0x1011 ||
        guest_load(ctx + 0x44, 4) != 0x202)
        return 11;

    uint64_t cpu[128] = {0};
    cpu[7] = 0x20fff00;
    guest_store(cpu[7], 0, 8);
    if (guest_indirect_dispatch(cpu, guest_image_base + 0x1000, 0, 0) != 73 ||
        cpu[7] != 0x20fff08)
        return 1;
    cpu[7] = 0x20fff00;
    guest_store(cpu[7], 0, 8);
    if (guest_indirect_dispatch(cpu, 0x1005, 0, 1) != 73 ||
        cpu[7] != 0x20fff08)
        return 2;
    cpu[7] = 0x20fff00;
    guest_store(cpu[7], 0, 8);
    if (guest_indirect_dispatch(cpu, 0x1016, 0, 0) != 42 ||
        cpu[7] != 0x20fff08)
        return 3;
    guest_set_cpu(cpu);
    uint64_t handler = guest_add_vectored_exception_handler(1, 0x1020);
    guest_store(output, 17, 8);
    guest_raise_exception(0xe0001234, 0, 1, output, guest_image_base + 0x1004, cpu[7]);
    if (exception_calls != 1 || !guest_remove_vectored_exception_handler(handler))
        return 9;
    guest_store(cpu[7] + 32, 0, 8);
    guest_store(cpu[7] + 40, 0, 8);
    guest_raise_exception(0xe0001234, 0, 1, output, guest_image_base + 0x1004, cpu[7]);
    if (exception_calls != 2)
        return 10;
    return 0;
}
