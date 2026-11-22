# STATIC AUDIT TEST FIXTURE — Standalone assembly anti-patterns
.section .text
.global raw_helper
raw_helper:
    mov $60, %rax
    syscall
    ret

# Marks stack executable (disables NX/DEP)
.section .note.GNU-stack,"x",@progbits

