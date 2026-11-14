/* Baseline interpreter for executable ranges in the primary PE image. */
struct guest_code_range { uint64_t start, size; };
__attribute__((weak)) const struct guest_code_range guest_code_ranges[] = {{0, 0}};
__attribute__((weak)) const uint64_t guest_code_range_count = 0;

static bool guest_code_contains(uint64_t pc, uint64_t size) {
    for (uint64_t i = 0; i < guest_code_range_count; ++i)
        if (fits(pc, size, guest_code_ranges[i].start, guest_code_ranges[i].size))
            return true;
    return false;
}

static uint64_t x86_fetch(uint64_t *pc, unsigned width) {
    if (!guest_code_contains(*pc, width))
        guest_trap("interpreter fetched outside executable image");
    uint64_t bits = guest_load(*pc, width);
    *pc += width;
    return bits;
}

/* Windows register encoding mapped to the shared LLVM register layout. */
static const unsigned x86_register_slots[] = {
    0, 1, 2, 8, 7, 9, 10, 11, 3, 4, 5, 6, 12, 13, 14, 15
};

static void x86_write(uint64_t *cpu, unsigned slot, uint64_t value, bool wide) {
    cpu[slot] = wide ? value : (uint32_t)value;
    cpu[53 + slot] = 64;
}

static uint64_t x86_interpret(uint64_t *cpu, uint64_t pc, uint64_t return_va) {
    for (unsigned steps = 0; steps < 100000; ++steps) {
        uint64_t start = pc;
        unsigned op = (unsigned)x86_fetch(&pc, 1);
        unsigned rex = 0;
        if (op >= 0x40 && op <= 0x4f) {
            rex = op;
            op = (unsigned)x86_fetch(&pc, 1);
        }
        bool wide = (rex & 8) != 0;
        if (op == 0x90 && !rex)
            continue;
        if (op >= 0xb8 && op <= 0xbf) {
            unsigned slot = x86_register_slots[op - 0xb8 + ((rex & 1) ? 8 : 0)];
            x86_write(cpu, slot, x86_fetch(&pc, wide ? 8 : 4), wide);
            continue;
        }
        if (op == 0xc3 && !rex) {
            uint64_t next = guest_load(cpu[7], 8);
            cpu[7] += 8;
            if (next == return_va)
                return cpu[0];
            if (next < guest_image_base || !guest_code_contains(next - guest_image_base, 1))
                guest_trap("interpreter return outside executable image");
            pc = next - guest_image_base;
            continue;
        }
        if (op == 0xff) {
            unsigned modrm = (unsigned)x86_fetch(&pc, 1);
            unsigned operation = (modrm >> 3) & 7;
            if ((modrm & 0xc0) == 0xc0 && (operation == 2 || operation == 4)) {
                unsigned slot = x86_register_slots[(modrm & 7) + ((rex & 1) ? 8 : 0)];
                uint64_t target = cpu[slot];
                if (target >= guest_image_base && target - guest_image_base < 0x20000000)
                    target -= guest_image_base;
                void (*compiled)(void *, uint64_t) = guest_lookup_dispatch(target);
                if (compiled || guest_code_contains(target, 1)) {
                    if (operation == 2) {
                        uint64_t next = guest_image_base + pc;
                        cpu[7] -= 8;
                        guest_store(cpu[7], next, 8);
                        if (compiled) {
                            compiled(cpu, next);
                            continue;
                        }
                    } else if (compiled) {
                        uint64_t next = guest_load(cpu[7], 8);
                        compiled(cpu, next);
                        if (next == return_va)
                            return cpu[0];
                        target = next - guest_image_base;
                    }
                    pc = target;
                    continue;
                }
            }
        }
        if ((op == 0xe8 || op == 0xe9 || op == 0xeb) && !rex) {
            int64_t displacement = op == 0xeb ? (int8_t)x86_fetch(&pc, 1) :
                                                (int32_t)x86_fetch(&pc, 4);
            uint64_t target = pc + (uint64_t)displacement;
            if (!guest_code_contains(target, 1))
                guest_trap("interpreter branch outside executable image");
            void (*compiled)(void *, uint64_t) = guest_lookup_dispatch(target);
            if (op == 0xe8) {
                uint64_t next = guest_image_base + pc;
                cpu[7] -= 8;
                guest_store(cpu[7], next, 8);
                if (compiled) {
                    compiled(cpu, next);
                    continue;
                }
            } else if (compiled) {
                uint64_t next = guest_load(cpu[7], 8);
                compiled(cpu, next);
                if (next == return_va)
                    return cpu[0];
                pc = next - guest_image_base;
                continue;
            }
            pc = target;
            continue;
        }
        if (op == 0x89 || op == 0x8b) {
            unsigned modrm = (unsigned)x86_fetch(&pc, 1);
            if ((modrm & 0xc0) == 0xc0) {
                unsigned reg = x86_register_slots[((modrm >> 3) & 7) + ((rex & 4) ? 8 : 0)];
                unsigned rm = x86_register_slots[(modrm & 7) + ((rex & 1) ? 8 : 0)];
                x86_write(cpu, op == 0x89 ? rm : reg, cpu[op == 0x89 ? reg : rm], wide);
                continue;
            }
        }
        fprintf(stderr, "RVA 0x%llx: unsupported interpreter opcode 0x%02x\n",
                (unsigned long long)start, op);
        exit(125);
    }
    guest_trap("interpreter instruction limit reached");
    return 0;
}
