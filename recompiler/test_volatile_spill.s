.text
.globl entry
entry:
    subq $40, %rsp
    callq *__imp_GetLastError(%rip)
    callq probe
    movl $42, %ecx
    callq *__imp_ExitProcess(%rip)
probe:
    subq $16, %rsp
    movq %r10, (%rsp)
    movq %r11, 8(%rsp)
    movq (%rsp), %r10
    movq 8(%rsp), %r11
    addq $16, %rsp
    retq
