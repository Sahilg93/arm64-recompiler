.text
.globl fault_read
.seh_proc fault_read
fault_read:
    .seh_endprologue
    xorl %eax, %eax
    movl (%rax), %eax
    retq
.seh_endproc
