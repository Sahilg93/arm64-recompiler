/*
 * Fallback x86-64 interpreter.
 *
 * Runs guest code the lifter did not compile an entry for: a return into the
 * middle of a function after an exception handler redirected execution, and
 * runtime-generated code in VirtualAlloc regions committed PAGE_EXECUTE*.
 *
 * The program counter is always an absolute guest VA: image code is
 * guest_image_base + RVA, JIT code is the raw (zero-tag) host address that
 * VirtualAlloc returned. Registers, XMM lanes, and the zf/cf/signed_less/of/sf
 * flag slots use the lifter's CPU layout, so control can pass between
 * interpreted and compiled code at calls and returns. PF, AF, and DF are not
 * modeled (DF is taken as clear); instructions that need them trap.
 */
struct guest_code_range { uint64_t start, size; };
__attribute__((weak)) const struct guest_code_range guest_code_ranges[] = {{0, 0}};
__attribute__((weak)) const uint64_t guest_code_range_count = 0;

uint64_t guest_indirect_dispatch(void *, uint64_t, uint64_t, uint32_t);
bool subsys_vm_executable(uint64_t, uint64_t);

static bool guest_code_contains(uint64_t pc, uint64_t size) {
    for (uint64_t i = 0; i < guest_code_range_count; ++i)
        if (fits(pc, size, guest_code_ranges[i].start, guest_code_ranges[i].size))
            return true;
    return false;
}

static bool x86_image_va(uint64_t va) {
    return guest_image_base && va >= guest_image_base && va - guest_image_base < 0x20000000;
}

/* Whether the interpreter may fetch from va: image code or an executable VirtualAlloc page. */
static bool x86_executable(uint64_t va, uint64_t size) {
    if (x86_image_va(va))
        return guest_code_contains(va - guest_image_base, size);
    return subsys_vm_executable(va, size);
}

enum {
    X86_XMM = 16, X86_ZF = 48, X86_CF, X86_SIGNED_LESS, X86_OF, X86_SF, X86_WIDTH = 53
};

/* Windows register encoding mapped to the shared LLVM register layout. */
static const unsigned x86_register_slots[] = {
    0, 1, 2, 8, 7, 9, 10, 11, 3, 4, 5, 6, 12, 13, 14, 15
};

static __attribute__((noreturn)) void x86_unsupported(uint64_t va, const char *what, unsigned op) {
    uint64_t shown = x86_image_va(va) ? va - guest_image_base : va;
    fprintf(stderr, "%s 0x%llx: unsupported interpreter %s 0x%02x\n",
            x86_image_va(va) ? "RVA" : "VA", (unsigned long long)shown, what, op);
    exit(125);
}

static uint64_t x86_fetch(uint64_t *pc, unsigned width) {
    if (!x86_executable(*pc, width))
        guest_trap("interpreter fetched outside executable code");
    uint64_t bits = guest_load(*pc, width);
    *pc += width;
    return bits;
}

static int64_t x86_fetch_signed(uint64_t *pc, unsigned width) {
    uint64_t bits = x86_fetch(pc, width);
    switch (width) {
    case 1: return (int8_t)bits;
    case 2: return (int16_t)bits;
    case 4: return (int32_t)bits;
    default: return (int64_t)bits;
    }
}

static uint64_t x86_mask(unsigned size) {
    return size >= 8 ? UINT64_MAX : (UINT64_C(1) << (size * 8)) - 1;
}

static uint64_t x86_sign_bit(unsigned size) {
    return UINT64_C(1) << (size * 8 - 1);
}

static int64_t x86_signed(uint64_t value, unsigned size) {
    unsigned shift = 64 - size * 8;
    return (int64_t)(value << shift) >> shift;
}

/* Register n is the x86 encoding (0-15). Byte registers 4-7 without REX are AH..BH. */
static uint64_t x86_get(const uint64_t *cpu, unsigned n, unsigned size, bool rex) {
    if (size == 1 && !rex && n >= 4 && n < 8)
        return (cpu[x86_register_slots[n - 4]] >> 8) & 0xff;
    return cpu[x86_register_slots[n]] & x86_mask(size);
}

static void x86_set(uint64_t *cpu, unsigned n, unsigned size, bool rex, uint64_t value) {
    unsigned slot;
    if (size == 1 && !rex && n >= 4 && n < 8) {
        slot = x86_register_slots[n - 4];
        cpu[slot] = (cpu[slot] & ~UINT64_C(0xff00)) | ((value & 0xff) << 8);
    } else {
        slot = x86_register_slots[n];
        if (size >= 4)
            cpu[slot] = size == 8 ? value : (uint32_t)value;
        else
            cpu[slot] = (cpu[slot] & ~x86_mask(size)) | (value & x86_mask(size));
    }
    cpu[X86_WIDTH + slot] = 64;
}

static void x86_flags(uint64_t *cpu, uint64_t result, unsigned size, bool carry, bool overflow) {
    result &= x86_mask(size);
    bool sign = (result & x86_sign_bit(size)) != 0;
    cpu[X86_ZF] = result == 0;
    cpu[X86_CF] = carry;
    cpu[X86_SF] = sign;
    cpu[X86_OF] = overflow;
    cpu[X86_SIGNED_LESS] = sign != overflow;
}

/* Condition codes 0-15 as in Jcc/SETcc/CMOVcc. */
static bool x86_condition(uint64_t va, const uint64_t *cpu, unsigned code) {
    bool zf = cpu[X86_ZF] & 1, cf = cpu[X86_CF] & 1, sf = cpu[X86_SF] & 1, of = cpu[X86_OF] & 1;
    bool less = cpu[X86_SIGNED_LESS] & 1;
    bool result;
    switch (code >> 1) {
    case 0: result = of; break;
    case 1: result = cf; break;
    case 2: result = zf; break;
    case 3: result = cf || zf; break;
    case 4: result = sf; break;
    case 5: x86_unsupported(va, "parity condition", code);
    case 6: result = less; break;
    default: result = zf || less; break;
    }
    return (code & 1) ? !result : result;
}

/* add, or, adc, sbb, and, sub, xor, cmp: returns the result and sets flags. */
static uint64_t x86_alu(uint64_t *cpu, unsigned kind, uint64_t a, uint64_t b, unsigned size) {
    uint64_t mask = x86_mask(size), sign = x86_sign_bit(size);
    a &= mask;
    b &= mask;
    uint64_t carry_in = (kind == 2 || kind == 3) ? (cpu[X86_CF] & 1) : 0;
    uint64_t result;
    switch (kind) {
    case 0: case 2: {
        unsigned __int128 sum = (unsigned __int128)a + b + carry_in;
        result = (uint64_t)sum & mask;
        bool carry = size == 8 ? (sum >> 64) != 0 : ((uint64_t)sum & ~mask) != 0;
        x86_flags(cpu, result, size, carry, ((a ^ result) & (b ^ result) & sign) != 0);
        return result;
    }
    case 3: case 5: case 7: {
        result = (a - b - carry_in) & mask;
        bool borrow = (unsigned __int128)a < (unsigned __int128)b + carry_in;
        x86_flags(cpu, result, size, borrow, ((a ^ b) & (a ^ result) & sign) != 0);
        return result;
    }
    case 1: result = a | b; break;
    case 4: result = a & b; break;
    default: result = a ^ b; break;
    }
    x86_flags(cpu, result, size, false, false);
    return result;
}

/* rol, ror, rcl, rcr, shl, shr, sal, sar. */
static uint64_t x86_shift(uint64_t va, uint64_t *cpu, unsigned kind, uint64_t value,
                          unsigned count, unsigned size) {
    unsigned bits = size * 8;
    count &= size == 8 ? 63 : 31;
    value &= x86_mask(size);
    if (!count)
        return value;
    uint64_t result;
    bool carry, overflow;
    switch (kind) {
    case 0: case 1: {
        unsigned rotate = count % bits;
        result = rotate ? (kind == 0 ? (value << rotate) | (value >> (bits - rotate))
                                     : (value >> rotate) | (value << (bits - rotate)))
                        : value;
        result &= x86_mask(size);
        bool msb = (result & x86_sign_bit(size)) != 0;
        carry = kind == 0 ? (result & 1) : msb;
        overflow = kind == 0 ? (msb != carry)
                             : (msb != ((result >> (bits - 2)) & 1));
        /* Rotates leave ZF and SF alone. */
        cpu[X86_CF] = carry;
        cpu[X86_OF] = overflow;
        cpu[X86_SIGNED_LESS] = (cpu[X86_SF] & 1) != overflow;
        return result;
    }
    case 4: case 6:
        if (count > bits) {
            result = 0;
            carry = false;
        } else {
            result = count == 64 ? 0 : (value << count) & x86_mask(size);
            carry = (value >> (bits - count)) & 1;
        }
        overflow = ((result & x86_sign_bit(size)) != 0) != carry;
        break;
    case 5:
        result = count >= bits ? 0 : value >> count;
        carry = count > bits ? false : (value >> (count - 1)) & 1;
        overflow = (value & x86_sign_bit(size)) != 0;
        break;
    case 7: {
        int64_t extended = x86_signed(value, size);
        unsigned clamped = count >= bits ? bits - 1 : count;
        result = (uint64_t)(extended >> clamped) & x86_mask(size);
        carry = (extended >> (count >= bits ? bits - 1 : count - 1)) & 1;
        overflow = false;
        break;
    }
    default:
        x86_unsupported(va, "rotate-through-carry", kind);
    }
    x86_flags(cpu, result, size, carry, overflow);
    return result;
}

/* A decoded ModRM operand: a register or a memory address computed after the immediate. */
struct x86_operand {
    bool is_register, rip, gs;
    unsigned reg;
    int base, index;
    unsigned scale;
    int64_t disp;
};

static unsigned x86_decode_modrm(uint64_t *pc, unsigned rex, bool gs, struct x86_operand *rm) {
    unsigned modrm = (unsigned)x86_fetch(pc, 1);
    unsigned mod = modrm >> 6, low = modrm & 7;
    *rm = (struct x86_operand){.gs = gs, .base = -1, .index = -1, .scale = 1};
    if (mod == 3) {
        rm->is_register = true;
        rm->reg = low + ((rex & 1) ? 8 : 0);
        return modrm;
    }
    if (low == 4) {
        unsigned sib = (unsigned)x86_fetch(pc, 1);
        unsigned index = ((sib >> 3) & 7) + ((rex & 2) ? 8 : 0);
        rm->scale = 1u << (sib >> 6);
        if (index != 4)
            rm->index = (int)index;
        if ((sib & 7) == 5 && mod == 0)
            rm->disp = x86_fetch_signed(pc, 4);
        else
            rm->base = (int)((sib & 7) + ((rex & 1) ? 8 : 0));
    } else if (low == 5 && mod == 0) {
        rm->rip = true;
        rm->disp = x86_fetch_signed(pc, 4);
    } else {
        rm->base = (int)(low + ((rex & 1) ? 8 : 0));
    }
    if (mod == 1)
        rm->disp += x86_fetch_signed(pc, 1);
    else if (mod == 2)
        rm->disp += x86_fetch_signed(pc, 4);
    return modrm;
}

/* end is the VA after the whole instruction, the base of RIP-relative operands. */
static uint64_t x86_address(const uint64_t *cpu, const struct x86_operand *rm, uint64_t end) {
    uint64_t address = (uint64_t)rm->disp;
    if (rm->rip)
        address += end;
    if (rm->base >= 0)
        address += cpu[x86_register_slots[rm->base]];
    if (rm->index >= 0)
        address += cpu[x86_register_slots[rm->index]] * rm->scale;
    if (rm->gs)
        address += 0x2101000;
    return address;
}

static uint64_t x86_read(const uint64_t *cpu, const struct x86_operand *rm, unsigned size,
                         bool rex, uint64_t end) {
    if (rm->is_register)
        return x86_get(cpu, rm->reg, size, rex);
    return guest_load(x86_address(cpu, rm, end), size);
}

static void x86_store(uint64_t *cpu, const struct x86_operand *rm, unsigned size, bool rex,
                      uint64_t end, uint64_t value) {
    if (rm->is_register)
        x86_set(cpu, rm->reg, size, rex, value);
    else
        guest_store(x86_address(cpu, rm, end), value & x86_mask(size), size);
}

static void x86_xmm_read(const uint64_t *cpu, const struct x86_operand *rm, uint64_t end,
                         unsigned size, uint64_t lanes[2]) {
    if (rm->is_register) {
        lanes[0] = cpu[X86_XMM + rm->reg * 2];
        lanes[1] = size == 16 ? cpu[X86_XMM + rm->reg * 2 + 1] : 0;
        if (size < 8)
            lanes[0] &= x86_mask(size);
        return;
    }
    uint64_t address = x86_address(cpu, rm, end);
    lanes[0] = guest_load(address, size < 8 ? size : 8);
    lanes[1] = size == 16 ? guest_load(address + 8, 8) : 0;
}

static void x86_xmm_set(uint64_t *cpu, unsigned reg, uint64_t low, uint64_t high) {
    cpu[X86_XMM + reg * 2] = low;
    cpu[X86_XMM + reg * 2 + 1] = high;
    cpu[X86_WIDTH + X86_XMM + reg * 2] = 128;
}

static void x86_push(uint64_t *cpu, uint64_t value) {
    cpu[7] -= 8;
    guest_store(cpu[7], value, 8);
}

static uint64_t x86_pop(uint64_t *cpu) {
    uint64_t value = guest_load(cpu[7], 8);
    cpu[7] += 8;
    return value;
}

/*
 * Leave the interpreter for a call target it does not run itself: a compiled
 * guest function, an import (IAT value or service token), or host code. The
 * return address next is already on the guest stack; the callee pops it.
 */
static void x86_call_out(uint64_t *cpu, uint64_t target, uint64_t next) {
    guest_indirect_dispatch(cpu, target, next, 0);
    current_cpu = cpu;
}

static uint64_t x86_interpret(uint64_t *cpu, uint64_t pc, uint64_t return_va) {
    if (!x86_image_va(pc) && guest_code_contains(pc, 1))
        pc += guest_image_base;
    bool mark_faults = guest_fault_pc != 0;
    for (;;) {
        uint64_t start = pc;
        if (mark_faults)
            guest_mark_fault_pc(start);
        unsigned op, rex = 0;
        bool operand16 = false, rep = false, repne = false, gs = false;
        for (;;) {
            op = (unsigned)x86_fetch(&pc, 1);
            if (op == 0x66) operand16 = true;
            else if (op == 0xf3) rep = true;
            else if (op == 0xf2) repne = true;
            else if (op == 0x65) gs = true;
            else if (op == 0xf0 || op == 0x2e || op == 0x3e || op == 0x26 || op == 0x36) continue;
            else if (op == 0x64 || op == 0x67) x86_unsupported(start, "prefix", op);
            else break;
        }
        if (op >= 0x40 && op <= 0x4f) {
            rex = op;
            op = (unsigned)x86_fetch(&pc, 1);
        }
        if (op == 0x0f) {
            op = 0x100 | (unsigned)x86_fetch(&pc, 1);
            if (op == 0x138 || op == 0x13a)
                x86_unsupported(start, "opcode 0x0f", op & 0xff);
        }
        bool has_rex = rex != 0;
        unsigned size = (rex & 8) ? 8 : operand16 ? 2 : 4;
        unsigned reg_ext = (rex & 4) ? 8 : 0;
        struct x86_operand rm;
        unsigned modrm, reg;

        /* Classic ALU forms 00-3d: op r/m,r / r,r/m / AL|eAX,imm. */
        if (op < 0x40 && (op & 7) < 6) {
            unsigned kind = op >> 3, form = op & 7;
            unsigned width = (form & 1) ? size : 1;
            if (form < 4) {
                modrm = x86_decode_modrm(&pc, rex, gs, &rm);
                reg = ((modrm >> 3) & 7) + reg_ext;
                uint64_t r = x86_get(cpu, reg, width, has_rex);
                uint64_t m = x86_read(cpu, &rm, width, has_rex, pc);
                if (form < 2) {
                    uint64_t result = x86_alu(cpu, kind, m, r, width);
                    if (kind != 7)
                        x86_store(cpu, &rm, width, has_rex, pc, result);
                } else {
                    uint64_t result = x86_alu(cpu, kind, r, m, width);
                    if (kind != 7)
                        x86_set(cpu, reg, width, has_rex, result);
                }
            } else {
                uint64_t imm = (uint64_t)x86_fetch_signed(&pc, width == 8 ? 4 : width);
                uint64_t result = x86_alu(cpu, kind, x86_get(cpu, 0, width, has_rex), imm, width);
                if (kind != 7)
                    x86_set(cpu, 0, width, has_rex, result);
            }
            continue;
        }

        switch (op) {
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
            x86_push(cpu, x86_get(cpu, (op & 7) + ((rex & 1) ? 8 : 0), 8, true));
            continue;
        case 0x58: case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
            x86_set(cpu, (op & 7) + ((rex & 1) ? 8 : 0), 8, true, x86_pop(cpu));
            continue;
        case 0x63: /* movsxd */
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            x86_set(cpu, reg, size, has_rex,
                    (uint64_t)(int64_t)(int32_t)x86_read(cpu, &rm, 4, has_rex, pc));
            continue;
        case 0x68: case 0x6a:
            x86_push(cpu, (uint64_t)x86_fetch_signed(&pc, op == 0x6a ? 1 : 4));
            continue;
        case 0x69: case 0x6b: case 0x1af: { /* imul r, r/m(, imm) */
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            int64_t b = op == 0x1af ? x86_signed(x86_get(cpu, reg, size, has_rex), size)
                                    : x86_fetch_signed(&pc, op == 0x6b ? 1 : (size == 2 ? 2 : 4));
            int64_t a = x86_signed(x86_read(cpu, &rm, size, has_rex, pc), size);
            __int128 product = (__int128)a * b;
            uint64_t result = (uint64_t)product & x86_mask(size);
            bool overflow = product != (__int128)x86_signed(result, size);
            x86_flags(cpu, result, size, overflow, overflow);
            x86_set(cpu, reg, size, has_rex, result);
            continue;
        }
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
        case 0x180: case 0x181: case 0x182: case 0x183: case 0x184: case 0x185: case 0x186: case 0x187:
        case 0x188: case 0x189: case 0x18a: case 0x18b: case 0x18c: case 0x18d: case 0x18e: case 0x18f: {
            int64_t displacement = x86_fetch_signed(&pc, op < 0x100 ? 1 : 4);
            if (x86_condition(start, cpu, op & 0xf)) {
                pc += (uint64_t)displacement;
                if (!x86_executable(pc, 1))
                    guest_trap("interpreter branch outside executable code");
            }
            continue;
        }
        case 0x80: case 0x81: case 0x83: { /* ALU r/m, imm */
            unsigned width = op == 0x80 ? 1 : size;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            unsigned imm_size = op == 0x81 ? (width == 2 ? 2 : 4) : 1;
            uint64_t imm = (uint64_t)x86_fetch_signed(&pc, imm_size);
            unsigned kind = (modrm >> 3) & 7;
            uint64_t result = x86_alu(cpu, kind, x86_read(cpu, &rm, width, has_rex, pc), imm, width);
            if (kind != 7)
                x86_store(cpu, &rm, width, has_rex, pc, result);
            continue;
        }
        case 0x84: case 0x85: { /* test r/m, r */
            unsigned width = op == 0x84 ? 1 : size;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            x86_alu(cpu, 4, x86_read(cpu, &rm, width, has_rex, pc), x86_get(cpu, reg, width, has_rex), width);
            continue;
        }
        case 0x86: case 0x87: { /* xchg r/m, r */
            unsigned width = op == 0x86 ? 1 : size;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            uint64_t memory = x86_read(cpu, &rm, width, has_rex, pc);
            x86_store(cpu, &rm, width, has_rex, pc, x86_get(cpu, reg, width, has_rex));
            x86_set(cpu, reg, width, has_rex, memory);
            continue;
        }
        case 0x88: case 0x89: case 0x8a: case 0x8b: { /* mov */
            unsigned width = (op & 1) ? size : 1;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            if (op < 0x8a)
                x86_store(cpu, &rm, width, has_rex, pc, x86_get(cpu, reg, width, has_rex));
            else
                x86_set(cpu, reg, width, has_rex, x86_read(cpu, &rm, width, has_rex, pc));
            continue;
        }
        case 0x8d: /* lea */
            modrm = x86_decode_modrm(&pc, rex, false, &rm);
            if (rm.is_register)
                x86_unsupported(start, "lea operand", modrm);
            x86_set(cpu, ((modrm >> 3) & 7) + reg_ext, size, has_rex, x86_address(cpu, &rm, pc));
            continue;
        case 0x8f: /* pop r/m */
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            {
                uint64_t value = x86_pop(cpu);
                x86_store(cpu, &rm, 8, true, pc, value);
            }
            continue;
        case 0x90:
            if (!(rex & 1))
                continue; /* nop and pause */
            /* fallthrough: xchg r8, rax */
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: {
            unsigned other = (op & 7) + ((rex & 1) ? 8 : 0);
            uint64_t value = x86_get(cpu, other, size, true);
            x86_set(cpu, other, size, true, x86_get(cpu, 0, size, true));
            x86_set(cpu, 0, size, true, value);
            continue;
        }
        case 0x98: /* cbw, cwde, cdqe */
            x86_set(cpu, 0, size, true, (uint64_t)x86_signed(x86_get(cpu, 0, size / 2, true), size / 2));
            continue;
        case 0x99: /* cwd, cdq, cqo */
            x86_set(cpu, 2, size, true,
                    x86_signed(x86_get(cpu, 0, size, true), size) < 0 ? UINT64_MAX : 0);
            continue;
        case 0xa4: case 0xa5: case 0xaa: case 0xab: { /* movs, stos */
            if (repne)
                x86_unsupported(start, "repne string opcode", op);
            unsigned width = (op & 1) ? size : 1;
            uint64_t count = rep ? cpu[1] : 1;
            for (; count; --count) {
                if (op <= 0xa5) {
                    guest_store(cpu[11], guest_load(cpu[10], width), width);
                    cpu[10] += width;
                } else {
                    guest_store(cpu[11], cpu[0] & x86_mask(width), width);
                }
                cpu[11] += width;
            }
            if (rep)
                cpu[1] = 0;
            continue;
        }
        case 0xa8: case 0xa9: { /* test AL|eAX, imm */
            unsigned width = op == 0xa8 ? 1 : size;
            uint64_t imm = (uint64_t)x86_fetch_signed(&pc, width == 8 ? 4 : width);
            x86_alu(cpu, 4, x86_get(cpu, 0, width, true), imm, width);
            continue;
        }
        case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
            x86_set(cpu, (op & 7) + ((rex & 1) ? 8 : 0), 1, has_rex, x86_fetch(&pc, 1));
            continue;
        case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
            x86_set(cpu, (op & 7) + ((rex & 1) ? 8 : 0), size, true, x86_fetch(&pc, size));
            continue;
        case 0xc0: case 0xc1: case 0xd0: case 0xd1: case 0xd2: case 0xd3: { /* shift group */
            unsigned width = (op & 1) ? size : 1;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            unsigned count = op <= 0xc1 ? (unsigned)x86_fetch(&pc, 1) : op <= 0xd1 ? 1 : (unsigned)cpu[1] & 0xff;
            uint64_t value = x86_read(cpu, &rm, width, has_rex, pc);
            x86_store(cpu, &rm, width, has_rex, pc,
                      x86_shift(start, cpu, (modrm >> 3) & 7, value, count, width));
            continue;
        }
        case 0xc2: case 0xc3: { /* ret */
            uint64_t release = op == 0xc2 ? x86_fetch(&pc, 2) : 0;
            uint64_t next = x86_pop(cpu);
            cpu[7] += release;
            if (next == return_va)
                return cpu[0];
            if (!x86_executable(next, 1))
                guest_trap("interpreter return outside executable code");
            pc = next;
            continue;
        }
        case 0xc6: case 0xc7: { /* mov r/m, imm */
            unsigned width = op == 0xc6 ? 1 : size;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            if ((modrm >> 3) & 7)
                x86_unsupported(start, "opcode extension", op);
            uint64_t imm = (uint64_t)x86_fetch_signed(&pc, width == 8 ? 4 : width);
            x86_store(cpu, &rm, width, has_rex, pc, imm);
            continue;
        }
        case 0xc9: /* leave */
            cpu[7] = cpu[9];
            x86_set(cpu, 5, 8, true, x86_pop(cpu));
            continue;
        case 0xe8: case 0xe9: case 0xeb: { /* call, jmp rel */
            int64_t displacement = x86_fetch_signed(&pc, op == 0xeb ? 1 : 4);
            uint64_t target = pc + (uint64_t)displacement;
            void (*compiled)(void *, uint64_t) = guest_lookup_dispatch(target);
            if (!compiled && !x86_executable(target, 1))
                guest_trap("interpreter branch outside executable code");
            if (op == 0xe8) {
                x86_push(cpu, pc);
                if (compiled) {
                    compiled(cpu, pc);
                    current_cpu = cpu;
                    continue;
                }
                pc = target;
                continue;
            }
            if (compiled) {
                /* A tail call into a compiled function returns to our caller's address. */
                uint64_t next = guest_load(cpu[7], 8);
                compiled(cpu, next);
                current_cpu = cpu;
                if (next == return_va)
                    return cpu[0];
                pc = next;
                continue;
            }
            pc = target;
            continue;
        }
        case 0xf6: case 0xf7: { /* test/not/neg/mul/imul/div/idiv */
            unsigned width = op == 0xf6 ? 1 : size;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            unsigned kind = (modrm >> 3) & 7;
            if (kind < 2) {
                uint64_t imm = (uint64_t)x86_fetch_signed(&pc, width == 8 ? 4 : width);
                x86_alu(cpu, 4, x86_read(cpu, &rm, width, has_rex, pc), imm, width);
                continue;
            }
            uint64_t value = x86_read(cpu, &rm, width, has_rex, pc);
            if (kind == 2) {
                x86_store(cpu, &rm, width, has_rex, pc, ~value);
                continue;
            }
            if (kind == 3) {
                uint64_t result = x86_alu(cpu, 5, 0, value, width);
                cpu[X86_CF] = (value & x86_mask(width)) != 0;
                x86_store(cpu, &rm, width, has_rex, pc, result);
                continue;
            }
            if (width < 4)
                x86_unsupported(start, "narrow multiply/divide", op);
            uint64_t mask = x86_mask(width);
            unsigned bits = width * 8;
            if (kind == 4 || kind == 5) {
                uint64_t low, high;
                bool overflow;
                if (kind == 4) {
                    unsigned __int128 product = (unsigned __int128)(cpu[0] & mask) * (value & mask);
                    low = (uint64_t)product & mask;
                    high = (uint64_t)(product >> bits) & mask;
                    overflow = high != 0;
                } else {
                    __int128 product = (__int128)x86_signed(cpu[0], width) * x86_signed(value, width);
                    low = (uint64_t)product & mask;
                    high = (uint64_t)(product >> bits) & mask;
                    overflow = product != (__int128)x86_signed(low, width);
                }
                x86_set(cpu, 0, width, true, low);
                x86_set(cpu, 2, width, true, high);
                x86_flags(cpu, low, width, overflow, overflow);
                continue;
            }
            if (!(value & mask))
                guest_trap("integer divide by zero in interpreter");
            if (kind == 6) {
                unsigned __int128 dividend = ((unsigned __int128)(cpu[2] & mask) << bits) | (cpu[0] & mask);
                unsigned __int128 quotient = dividend / (value & mask);
                if (quotient >> bits)
                    guest_trap("integer divide overflow in interpreter");
                x86_set(cpu, 0, width, true, (uint64_t)quotient);
                x86_set(cpu, 2, width, true, (uint64_t)(dividend % (value & mask)));
            } else {
                __int128 dividend = (__int128)(((unsigned __int128)(cpu[2] & mask) << bits) | (cpu[0] & mask));
                if (width == 4)
                    dividend = (int64_t)(uint64_t)dividend;
                __int128 divisor = x86_signed(value, width);
                __int128 quotient = dividend / divisor;
                if (quotient != (__int128)x86_signed((uint64_t)quotient & mask, width))
                    guest_trap("integer divide overflow in interpreter");
                x86_set(cpu, 0, width, true, (uint64_t)quotient);
                x86_set(cpu, 2, width, true, (uint64_t)(dividend % divisor));
            }
            continue;
        }
        case 0xfe: case 0xff: {
            unsigned width = op == 0xfe ? 1 : size;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            unsigned kind = (modrm >> 3) & 7;
            if (kind < 2) { /* inc, dec keep CF */
                uint64_t carry = cpu[X86_CF];
                uint64_t result = x86_alu(cpu, kind ? 5 : 0, x86_read(cpu, &rm, width, has_rex, pc), 1, width);
                cpu[X86_CF] = carry;
                x86_store(cpu, &rm, width, has_rex, pc, result);
                continue;
            }
            if (op == 0xff && kind == 6) {
                x86_push(cpu, x86_read(cpu, &rm, 8, true, pc));
                continue;
            }
            if (op == 0xff && (kind == 2 || kind == 4)) {
                uint64_t target = x86_read(cpu, &rm, 8, true, pc);
                if (kind == 2) {
                    x86_push(cpu, pc);
                    if (!guest_lookup_dispatch(target) && x86_executable(target, 1)) {
                        pc = target;
                        continue;
                    }
                    x86_call_out(cpu, target, pc);
                    continue;
                }
                if (!guest_lookup_dispatch(target) && x86_executable(target, 1)) {
                    pc = target;
                    continue;
                }
                /* Tail jump out: the callee returns to the address on top of the stack. */
                uint64_t next = guest_load(cpu[7], 8);
                guest_indirect_dispatch(cpu, target, next, 1);
                current_cpu = cpu;
                if (next == return_va)
                    return cpu[0];
                if (!x86_executable(next, 1))
                    guest_trap("interpreter return outside executable code");
                pc = next;
                continue;
            }
            x86_unsupported(start, "opcode extension", op);
        }
        case 0x10b:
            guest_trap("ud2 in interpreted guest code");
            continue;
        case 0x11f: /* multi-byte nop */
            x86_decode_modrm(&pc, rex, gs, &rm);
            continue;
        case 0x140: case 0x141: case 0x142: case 0x143: case 0x144: case 0x145: case 0x146: case 0x147:
        case 0x148: case 0x149: case 0x14a: case 0x14b: case 0x14c: case 0x14d: case 0x14e: case 0x14f: {
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            uint64_t value = x86_read(cpu, &rm, size, has_rex, pc);
            /* A 32-bit cmov writes (zero-extends) its destination even when false. */
            x86_set(cpu, reg, size, has_rex,
                    x86_condition(start, cpu, op & 0xf) ? value : x86_get(cpu, reg, size, has_rex));
            continue;
        }
        case 0x190: case 0x191: case 0x192: case 0x193: case 0x194: case 0x195: case 0x196: case 0x197:
        case 0x198: case 0x199: case 0x19a: case 0x19b: case 0x19c: case 0x19d: case 0x19e: case 0x19f:
            x86_decode_modrm(&pc, rex, gs, &rm);
            x86_store(cpu, &rm, 1, has_rex, pc, x86_condition(start, cpu, op & 0xf));
            continue;
        case 0x1b6: case 0x1b7: case 0x1be: case 0x1bf: { /* movzx, movsx */
            unsigned source = (op & 1) ? 2 : 1;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            uint64_t value = x86_read(cpu, &rm, source, has_rex, pc);
            if (op >= 0x1be)
                value = (uint64_t)x86_signed(value, source);
            x86_set(cpu, reg, size, has_rex, value);
            continue;
        }
        /* SSE moves and zeroing idioms used by compiled C for copies and spills. */
        case 0x110: case 0x111: case 0x128: case 0x129: case 0x16f: case 0x17f: {
            bool scalar = (op == 0x110 || op == 0x111) && (rep || repne);
            if ((op == 0x16f || op == 0x17f) && !operand16 && !rep)
                x86_unsupported(start, "MMX opcode 0x0f", op & 0xff);
            unsigned width = scalar ? (rep ? 4 : 8) : 16;
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            bool load = op == 0x110 || op == 0x128 || op == 0x16f;
            uint64_t lanes[2];
            if (load) {
                x86_xmm_read(cpu, &rm, pc, width, lanes);
                if (scalar && rm.is_register) { /* movss/movsd reg, reg merge */
                    uint64_t keep = width == 4 ? cpu[X86_XMM + reg * 2] & ~UINT64_C(0xffffffff) : 0;
                    x86_xmm_set(cpu, reg, keep | lanes[0], cpu[X86_XMM + reg * 2 + 1]);
                } else {
                    x86_xmm_set(cpu, reg, lanes[0], lanes[1]);
                }
            } else {
                lanes[0] = cpu[X86_XMM + reg * 2];
                lanes[1] = cpu[X86_XMM + reg * 2 + 1];
                if (rm.is_register) {
                    if (scalar) {
                        uint64_t keep = width == 4 ? cpu[X86_XMM + rm.reg * 2] & ~UINT64_C(0xffffffff) : 0;
                        x86_xmm_set(cpu, rm.reg, keep | (lanes[0] & x86_mask(width)), cpu[X86_XMM + rm.reg * 2 + 1]);
                    } else {
                        x86_xmm_set(cpu, rm.reg, lanes[0], lanes[1]);
                    }
                } else {
                    uint64_t address = x86_address(cpu, &rm, pc);
                    guest_store(address, lanes[0] & x86_mask(width < 8 ? width : 8), width < 8 ? width : 8);
                    if (width == 16)
                        guest_store(address + 8, lanes[1], 8);
                }
            }
            continue;
        }
        case 0x157: case 0x1ef: { /* xorps, xorpd, pxor */
            if (op == 0x1ef && !operand16)
                x86_unsupported(start, "MMX opcode 0x0f", op & 0xff);
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            uint64_t lanes[2];
            x86_xmm_read(cpu, &rm, pc, 16, lanes);
            x86_xmm_set(cpu, reg, cpu[X86_XMM + reg * 2] ^ lanes[0], cpu[X86_XMM + reg * 2 + 1] ^ lanes[1]);
            continue;
        }
        case 0x16e: case 0x17e: case 0x1d6: { /* movd/movq */
            modrm = x86_decode_modrm(&pc, rex, gs, &rm);
            reg = ((modrm >> 3) & 7) + reg_ext;
            unsigned width = (rex & 8) ? 8 : 4;
            if (op == 0x16e && operand16) { /* xmm <- r/m */
                x86_xmm_set(cpu, reg, x86_read(cpu, &rm, width, has_rex, pc), 0);
            } else if (op == 0x17e && operand16) { /* r/m <- xmm */
                x86_store(cpu, &rm, width, has_rex, pc, cpu[X86_XMM + reg * 2]);
            } else if (op == 0x17e && rep) { /* movq xmm <- xmm/m64 */
                uint64_t lanes[2];
                x86_xmm_read(cpu, &rm, pc, 8, lanes);
                x86_xmm_set(cpu, reg, lanes[0], 0);
            } else if (op == 0x1d6 && operand16) { /* movq xmm/m64 <- xmm */
                if (rm.is_register)
                    x86_xmm_set(cpu, rm.reg, cpu[X86_XMM + reg * 2], 0);
                else
                    guest_store(x86_address(cpu, &rm, pc), cpu[X86_XMM + reg * 2], 8);
            } else {
                x86_unsupported(start, "MMX opcode 0x0f", op & 0xff);
            }
            continue;
        }
        default:
            break;
        }
        if (op >= 0x100)
            x86_unsupported(start, "opcode 0x0f", op & 0xff);
        x86_unsupported(start, "opcode", op);
    }
}
