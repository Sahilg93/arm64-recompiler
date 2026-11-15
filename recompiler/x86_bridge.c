#include <stdint.h>

extern uint32_t __attribute__((ms_abi)) guest(uint32_t a, uint32_t b);

uint32_t lifted(uint32_t a, uint32_t b) {
    return guest(a, b);
}
