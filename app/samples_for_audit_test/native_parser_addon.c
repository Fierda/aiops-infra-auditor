/* STATIC AUDIT TEST FIXTURE — C/C++ native extension & inline ASM memory-safety anti-patterns */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_native_header(const char *user_header, size_t count, size_t elem_size) {
    char fixed_buf[64];
    /* Unbounded buffer copy (CWE-120) */
    strcpy(fixed_buf, user_header);

    /* Format string vulnerability (CWE-134) */
    printf(user_header);

    /* Unchecked integer multiplication in heap allocation (CWE-190) */
    char *heap_buf = (char *)malloc(count * elem_size);
    if (!heap_buf) {
        return;
    }

    free(heap_buf);
    /* Potential Use-After-Free without nullifying pointer (CWE-416) */
    heap_buf[0] = 'A';

    /* Inline assembly block bypassing compiler memory safety (CWE-676) */
    __asm__ volatile("nop");
}

