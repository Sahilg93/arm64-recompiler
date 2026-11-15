typedef unsigned int u32;
u32 fixture(u32 a, u32 b) {
    switch (a) {
        case 0: return b + 17;
        case 1: return b ^ 199;
        case 2: return b - 54;
        case 3: return b & 127;
        case 4: return b | 254;
        case 5: return -b;
        default: return 42;
    }
}
