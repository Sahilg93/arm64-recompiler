.text
.globl raise_in_frame
.seh_proc raise_in_frame
raise_in_frame:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    .seh_handler language_handler, @except
    movl $0xe0001235, %ecx
    xorl %edx, %edx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    callq *__imp_RaiseException(%rip)
    nop
    addq $40, %rsp
    retq
    .seh_handlerdata
    .long 0
.text
.seh_endproc
