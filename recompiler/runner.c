#include <inttypes.h>
#include <stdio.h>

extern uint32_t lifted(uint32_t a, uint32_t b);

int main(void) {
    uint32_t a, b;
    int fields;
    while ((fields = scanf("%" SCNu32 " %" SCNu32, &a, &b)) == 2)
        printf("%" PRIu32 "\n", lifted(a, b));
    return fields == EOF && !ferror(stdin) && !ferror(stdout) ? 0 : 1;
}
