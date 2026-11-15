.text
.globl begin_consolidation
.seh_proc begin_consolidation
begin_consolidation:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq %rsp, %rcx
    callq unwind_child
    int3
.seh_endproc

.seh_proc unwind_child
unwind_child:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    .seh_handler cleanup_handler, @unwind
    movq %rdx, 32(%rsp)
    movq $0, 40(%rsp)
    movq %r8, %rax
    movq %r9, %r8
    movq %rax, %rdx
    movl $73, %r9d
    callq *__imp_RtlUnwindEx(%rip)
    nop
    addq $56, %rsp
    retq
    .seh_handlerdata
    .long 0
.text
.seh_endproc
