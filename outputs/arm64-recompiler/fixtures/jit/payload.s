# Position-independent x86-64 code copied into a VirtualAlloc buffer and run
# from there. Win64 ABI:
#   void jit_ops(uint64_t *out /* rcx */, uint64_t (*callback)(uint64_t) /* rdx */)
# Each step stores one result in out[i]; main.c holds the expected values.
# The steps cover the opcodes the fallback interpreter must handle: the
# 0x80/0x81/0x83 immediate ALU group and the short AL/eAX forms, movsx/movzx,
# shifts and rotates, cmovcc, setcc, mul/imul/div/idiv, string stores, simple
# SSE moves, a counted loop, and a call back into compiled guest code.
.text
.globl jit_ops
jit_ops:
    pushq %rbx
    pushq %r12
    pushq %rdi
    subq $32, %rsp
    movq %rcx, %rbx
    movq %rdx, %r12

    # 0: add r32, imm8 (sign-extended)
    movl $0x1234, %eax
    addl $-1, %eax
    movq %rax, 0(%rbx)
    # 1: and r64, imm32
    movq $-1, %rax
    andq $0x7ff0, %rax
    movq %rax, 8(%rbx)
    # 2: or r/m8, imm8
    movl $0x100, %eax
    orb $0x80, %al
    movq %rax, 16(%rbx)
    # 3: adc r32, imm8 with CF from cmp
    movl $1, %eax
    movl $10, %ecx
    cmpl $2, %eax
    adcl $5, %ecx
    movq %rcx, 24(%rbx)
    # 4: sbb r64, imm8 with CF from cmp
    movl $1, %eax
    movq $10, %rdx
    cmpl $2, %eax
    sbbq $3, %rdx
    movq %rdx, 32(%rbx)
    # 5: xor eAX, imm32 (short form) clears the upper half
    movq $-1, %rax
    xorl $0x0f0f0f0f, %eax
    movq %rax, 40(%rbx)
    # 6: sub/xor r32, imm32
    movl $1000, %ecx
    subl $300, %ecx
    xorl $0x100, %ecx
    movq %rcx, 48(%rbx)
    # 7: movsx r64, r/m8
    movl $0x1280, %eax
    movsbq %al, %rcx
    movq %rcx, 56(%rbx)
    # 8: movzx r32, AH
    movzbl %ah, %ecx
    movq %rcx, 64(%rbx)
    # 9: movsx r32, r/m16 zero-extends to 64 bits
    movq $-1, %rcx
    movl $0x8001, %eax
    movswl %ax, %ecx
    movq %rcx, 72(%rbx)
    # 10: movsxd
    movl $0x80000000, %eax
    movslq %eax, %rcx
    movq %rcx, 80(%rbx)
    # 11: mov m16, imm16 then movzx r32, m16
    movq $-1, 88(%rbx)
    movw $0xbeef, 88(%rbx)
    movzwl 88(%rbx), %ecx
    movq %rcx, 88(%rbx)
    # 12: sar by immediate and by one
    movq $-16, %rax
    sarq $2, %rax
    sarq %rax
    movq %rax, 96(%rbx)
    # 13: shr by CL, shl by one
    movl $0x80000000, %eax
    movb $4, %cl
    shrl %cl, %eax
    shll %eax
    movq %rax, 104(%rbx)
    # 14: rol and ror by immediate
    movl $0x80000001, %eax
    roll $4, %eax
    rorl $8, %eax
    movq %rax, 112(%rbx)
    # 15, 16: cmovl taken; 32-bit cmovg not taken still zero-extends
    movl $5, %eax
    movl $9, %ecx
    movq $-1, %rdx
    cmpl %ecx, %eax
    cmovll %ecx, %eax
    cmovgl %ecx, %edx
    movq %rax, 120(%rbx)
    movq %rdx, 128(%rbx)
    # 17: cmove r64 after xor sets ZF
    movq $7, %rax
    xorl %ecx, %ecx
    cmoveq %rax, %rcx
    movq %rcx, 136(%rbx)
    # 18: setcc into memory after a signed/unsigned split compare (-5 vs 3)
    movq $0, 144(%rbx)
    movl $-5, %eax
    cmpl $3, %eax
    setl 144(%rbx)
    setb 145(%rbx)
    seta 146(%rbx)
    setg 147(%rbx)
    setne 148(%rbx)
    sets 149(%rbx)
    seto 150(%rbx)
    setle 151(%rbx)
    # 19: setcc after signed overflow (0x7fffffff + 1)
    movq $0, 152(%rbx)
    movl $0x7fffffff, %eax
    addl $1, %eax
    seto 152(%rbx)
    setno 153(%rbx)
    setl 154(%rbx)
    setge 155(%rbx)
    setb 156(%rbx)
    setae 157(%rbx)
    sete 158(%rbx)
    setne 159(%rbx)
    # 20: imul r32, r/m32, imm8
    movl $-7, %eax
    imull $6, %eax, %ecx
    movq %rcx, 160(%rbx)
    # 21: mul r64 (low half; high half in 22)
    movabsq $0x100000001, %rax
    movq $0x100000000, %rcx
    mulq %rcx
    movq %rax, 168(%rbx)
    movq %rdx, 176(%rbx)
    # 23: idiv r64 quotient, 24: remainder
    movq $100, %rax
    cqto
    movq $-7, %rcx
    idivq %rcx
    movq %rax, 184(%rbx)
    movq %rdx, 192(%rbx)
    # 25: neg and not
    movq $5, %rax
    negq %rax
    notq %rax
    movq %rax, 200(%rbx)
    # 26: counted loop with dec/jnz
    xorl %eax, %eax
    movl $10, %ecx
1:  addl %ecx, %eax
    decl %ecx
    jnz 1b
    movq %rax, 208(%rbx)
    # 27: call compiled guest code through a register
    movl $41, %ecx
    callq *%r12
    movq %rax, 216(%rbx)
    # 28: lea with an index and no base
    movl $3, %ecx
    leaq 0x10(,%rcx,8), %rax
    movq %rax, 224(%rbx)
    # 29: ALU and shift on memory operands
    movq $100, 232(%rbx)
    addl $0x11, 232(%rbx)
    shlq $1, 232(%rbx)
    # 30: 16-bit add wraps without touching bits above AX
    movl $0x1ffff, %eax
    addw $1, %ax
    movq %rax, 240(%rbx)
    # 31: rep stosb
    leaq 248(%rbx), %rdi
    movb $0xab, %al
    movl $8, %ecx
    rep stosb
    # 32: movq between a GPR, an XMM register, and memory
    movabsq $0x1122334455667788, %rax
    movq %rax, %xmm1
    movq %xmm1, 256(%rbx)
    # 33: test/jcc and push/pop
    movl $0x40, %eax
    testb $0x40, %al
    jz 2f
    pushq $0x77
    popq %rax
2:  movq %rax, 264(%rbx)
    # 34..49: SSE2 shifts by an immediate, two results (low, high) per step:
    # psrldq, pslldq, psrlq+psllq, psrld+pslld, psrlw+psllw, psraw, psrad past
    # the element width (fills with the sign), psrlq by 64 (clears).
    movabsq $0x8877665544332211, %rax
    movq %rax, 272(%rbx)
    movabsq $0xffeeddccbbaa9900, %rax
    movq %rax, 280(%rbx)
    movdqu 272(%rbx), %xmm2
    movdqa %xmm2, %xmm1
    psrldq $5, %xmm1
    movdqu %xmm1, 272(%rbx)
    movdqa %xmm2, %xmm9
    pslldq $3, %xmm9
    movdqu %xmm9, 288(%rbx)
    movdqa %xmm2, %xmm1
    psrlq $4, %xmm1
    psllq $8, %xmm1
    movdqu %xmm1, 304(%rbx)
    movdqa %xmm2, %xmm1
    psrld $4, %xmm1
    pslld $12, %xmm1
    movdqu %xmm1, 320(%rbx)
    movdqa %xmm2, %xmm9
    psrlw $4, %xmm9
    psllw $1, %xmm9
    movdqu %xmm9, 336(%rbx)
    movdqa %xmm2, %xmm1
    psraw $3, %xmm1
    movdqu %xmm1, 352(%rbx)
    movdqa %xmm2, %xmm1
    psrad $36, %xmm1
    movdqu %xmm1, 368(%rbx)
    movdqa %xmm2, %xmm1
    psrlq $64, %xmm1
    movdqu %xmm1, 384(%rbx)

    addq $32, %rsp
    popq %rdi
    popq %r12
    popq %rbx
    retq
