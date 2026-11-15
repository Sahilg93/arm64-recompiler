typedef unsigned int u32;

__attribute__((noinline))
u32 fixture(u32 a, u32 b) {
    u32 total = 0;
    while (a != 0) {
        if (a & 1)
            total += b;
        b += a;
        a >>= 1;
    }
    return total;
}
