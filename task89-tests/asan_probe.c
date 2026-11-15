/*
 * Negative control for the AddressSanitizer layer of read-window restriction.
 *
 * Allocates an exact-sized heap window and deliberately reads one byte past it (still inside the
 * same page, so no MMU fault occurs). ASan's heap red zones must turn this into an abort.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    const size_t n = 16;
    unsigned char* p = (unsigned char*)malloc(n);
    if (!p)
    {
        return 2;
    }
    for (size_t i = 0; i < n; ++i)
    {
        p[i] = (unsigned char)i;
    }

    /* In-bounds access: fine. */
    volatile unsigned char ok = p[n - 1];
    (void)ok;

    /* One byte past the allocation: ASan heap-buffer-overflow, expected to abort. */
    volatile unsigned char bad = p[n];
    (void)bad;

    printf("ASAN BROKEN: heap over-read was not detected\n");
    free(p);
    return 1;
}
