// /src/good_luck_debug.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

static const char *correct_key = "OpenSesame123!"; 
static inline unsigned long long rdtsc(void) {
    unsigned int hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}

int check_ptrace_detected(void) {
    errno = 0;
    long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (r == -1 && errno == EPERM) {
        return 1;
    }
    return 0;
}

int check_proc_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0; 
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer = atoi(line + 10);
            fclose(f);
            if (tracer != 0) return 1;
            return 0;
        }
    }
    fclose(f);
    return 0;
}

int check_timing_rdtsc(void) {
    const unsigned long long sleep_ns = 10 * 1000 * 1000ULL; 
    unsigned long long start = rdtsc();
    struct timespec ts = {0};
    ts.tv_sec = 0;
    ts.tv_nsec = sleep_ns;
    nanosleep(&ts, NULL);
    unsigned long long end = rdtsc();
    unsigned long long diff = end - start;

    const unsigned long long threshold = 100000000ULL;
    if (diff > threshold) {
        return 1;
    }
    return 0;
}

int any_anti_debug_detected(void) {
    if (check_ptrace_detected()) return 1;
    if (check_proc_tracerpid()) return 1;
    if (check_timing_rdtsc()) return 1;
    return 0;
}

int main(void) {
    puts("Enter the secret key:");

    char buf[256];
    if (!fgets(buf, sizeof(buf), stdin)) {
        puts("Failed to read input.");
        return 1;
    }

    buf[strcspn(buf, "\n")] = '\0';

    int detected = any_anti_debug_detected();
    if (detected) {
        puts("[!] Debugger / tracer detected. The program refuses to accept the real key.");

        if (strcmp(buf, "debugger_override_key") == 0) {
            puts("[+] You found the override key for debug mode. (Try bypassing anti-debug to get the real flag.)");
        } else {
            puts("Wrong key.");
        }
        return 2;
    } else {

        if (strcmp(buf, correct_key) == 0) {
            puts("Correct! Here is your reward: DMI{4nt1_debug_byp4553d}");
            return 0;
        } else {
            puts("Wrong key.");
            return 3;
        }
    }
}
