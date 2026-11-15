/*
 * Negative control for the guarded-window mechanism used by segtrunc_test.
 *
 * Deliberately reads one byte past a declared window that ends directly in front of a PROT_NONE
 * page. A correct guard setup must kill the process with SIGSEGV (proving a decoder over-read of
 * the same kind would be caught). The probe installs a SIGSEGV handler that reports success and
 * exits 0; if the over-read does NOT fault, it exits 1 (guard mechanism broken).
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

static volatile sig_atomic_t g_faulted = 0;

static void handler(int sig)
{
    (void)sig;
    g_faulted = 1;
    /* The faulting instruction cannot be resumed; exit from the handler directly. */
    const char msg[] = "GUARD OK: over-read past window raised SIGSEGV\n";
    if (write(STDOUT_FILENO, msg, sizeof(msg) - 1) < 0) { /* ignore */ }
    _exit(0);
}

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    unsigned char* map = (unsigned char*)mmap(NULL, (size_t)ps * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
    {
        perror("mmap");
        return 2;
    }
    if (mprotect(map + ps, (size_t)ps, PROT_NONE) != 0)
    {
        perror("mprotect");
        return 2;
    }

    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* A 5-byte window placed at the very end of the accessible page. */
    unsigned char* window = map + ps - 5;
    window[0] = 0x90;

    /* In-bounds read: must succeed. */
    volatile unsigned char ok = window[4];
    (void)ok;

    /* Out-of-bounds read one byte past the window (into the PROT_NONE page): must fault. */
    volatile unsigned char bad = window[5];
    (void)bad;

    printf("GUARD BROKEN: over-read past window did NOT fault\n");
    return 1;
}
