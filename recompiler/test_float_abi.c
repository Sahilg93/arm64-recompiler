#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// Mock guest memory functions for generated_shims.h and console_subsystems.h
void guest_store(uint64_t addr, uint64_t value, uint32_t width) { (void)addr; (void)value; (void)width; }
uint64_t guest_load(uint64_t addr, uint32_t width) { (void)addr; (void)width; return 0; }
void *guest_pointer(uint64_t addr, uint32_t width) { (void)addr; (void)width; return NULL; }
unsigned char *guest_writable_span(uint64_t addr, uint64_t size) { (void)addr; (void)size; return NULL; }
void guest_set_last_error(uint32_t error) { (void)error; }
uint64_t guest_get_last_error(void) { return 0; }
uint64_t guest_heap_alloc(uint64_t handle, uint32_t flags, uint64_t size) { (void)handle; (void)flags; (void)size; return 0; }
uint64_t guest_heap_free(uint64_t handle, uint32_t flags, uint64_t address) { (void)handle; (void)flags; (void)address; return 1; }
uint64_t guest_close_handle(uint64_t handle) { (void)handle; return 1; }

#include "console_subsystems.h"
#include "generated_shims.h"

int main(void) {
    union { double d; uint64_t u; } in0, in1, out;
    uint64_t res = 0;
    bool ok = false;

    // 1. Direct guest_sqrt test
    in0.d = 4.0;
    out.u = guest_sqrt(in0.u, 0, 0, 0);
    printf("guest_sqrt(4.0) = %f (expected 2.0)\n", out.d);
    assert(out.d == 2.0);

    // 2. Direct guest_pow test
    in0.d = 2.0;
    in1.d = 3.0;
    out.u = guest_pow(in0.u, in1.u, 0, 0);
    printf("guest_pow(2.0, 3.0) = %f (expected 8.0)\n", out.d);
    assert(out.d == 8.0);

    // 3. Dispatcher test for sqrt
    in0.d = 4.0;
    ok = guest_dispatch_generated_shim("sqrt", &res, in0.u, 0, 0, 0);
    assert(ok);
    out.u = res;
    printf("guest_dispatch_generated_shim('sqrt', 4.0) = %f\n", out.d);
    assert(out.d == 2.0);

    // 4. Dispatcher test for pow
    in0.d = 2.0;
    in1.d = 3.0;
    ok = guest_dispatch_generated_shim("pow", &res, in0.u, in1.u, 0, 0);
    assert(ok);
    out.u = res;
    printf("guest_dispatch_generated_shim('pow', 2.0, 3.0) = %f\n", out.d);
    assert(out.d == 8.0);

    // 5. Additional math float verification
    in0.d = 0.0;
    out.u = guest_sin(in0.u, 0, 0, 0);
    assert(out.d == 0.0);

    out.u = guest_cos(in0.u, 0, 0, 0);
    assert(out.d == 1.0);

    in0.d = -5.5;
    out.u = guest_fabs(in0.u, 0, 0, 0);
    assert(out.d == 5.5);

    printf("ALL Float ABI tests passed successfully on ARM64!\n");
    return 0;
}
