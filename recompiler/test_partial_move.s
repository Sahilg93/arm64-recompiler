.text
.globl entry
entry:
    subq $40, %rsp
    movb $42, %dl
    movl %edx, %r14d
    movzbl %r14b, %ecx
    callq *__imp_ExitProcess(%rip)
