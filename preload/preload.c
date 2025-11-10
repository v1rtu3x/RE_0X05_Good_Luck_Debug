// /preload/preload.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


long ptrace(int request, pid_t pid, void *addr, void *data) {
    static long (*real_ptrace)(int, pid_t, void*, void*) = NULL;
    if (!real_ptrace) real_ptrace = dlsym(RTLD_NEXT, "ptrace");
    (void)request; (void)pid; (void)addr; (void)data;
    return 0;
}

pid_t getppid(void) {
    static pid_t (*real_getppid)(void) = NULL;
    if (!real_getppid) real_getppid = dlsym(RTLD_NEXT, "getppid");
    pid_t orig = real_getppid ? real_getppid() : 1;
    (void)orig;
    return orig;
}

FILE *fopen(const char *pathname, const char *mode) {
    static FILE *(*real_fopen)(const char*, const char*) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

    if (pathname && strstr(pathname, "/proc/self/status") != NULL) {
        const char *fake = "Name:\tanti_debug_challenge\nState:\tR (running)\nTracerPid:\t0\n";
#ifdef __linux__
        return fmemopen((void*)strdup(fake), strlen(fake), "r");
#else
        char tmpname[] = "/tmp/fakestatusXXXXXX";
        int fd = mkstemp(tmpname);
        if (fd == -1) return NULL;
        write(fd, fake, strlen(fake));
        lseek(fd, 0, SEEK_SET);
        FILE *f = fdopen(fd, "r");
        unlink(tmpname);
        return f;
#endif
    }
    return real_fopen ? real_fopen(pathname, mode) : NULL;
}
