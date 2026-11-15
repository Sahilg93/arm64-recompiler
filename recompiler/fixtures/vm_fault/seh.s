# int seh_read(volatile int *address): loads *address inside a frame whose
# unwind data names seh_handler, so a fault here is found only by walking
# .pdata/.xdata (table-driven SEH), not through a vectored handler. The handler
# pops this frame and resumes at seh_resume, which returns 0x73 to the caller.
.text
.globl seh_read
.seh_proc seh_read
seh_read:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    .seh_handler seh_handler, @except
    movl (%rcx), %eax
    nop
    addq $40, %rsp
    retq
    .seh_handlerdata
    .long 0
.text
.seh_endproc

.globl seh_resume
.seh_proc seh_resume
seh_resume:
    .seh_endprologue
    movl $0x73, %eax
    retq
.seh_endproc
