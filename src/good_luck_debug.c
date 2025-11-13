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

static const unsigned char KEY[] = { 0x72, 0xe5, 0x8a, 0x13, 0x20, 0x7e, 0x2a, 
                                     0xa0, 0x08, 0x9f, 0x7b, 0x30, 0xa4, 0xf3 };

static const size_t KEY_len = sizeof(KEY);

static const unsigned char FLAG_CT[] = { 0x92, 0xe2, 0x66, 0x0d, 0xba, 0xcd, 
                                         0xe7, 0x0d, 0x09, 0x03, 0x8b, 0xa7, 
                                         0xef, 0xf0, 0xba, 0x6c, 0x4e, 0xed, 
                                         0x22, 0x53, 0x73, 0x03, 0xd5, 0xac };

static const size_t FLAG_CT_len = sizeof(FLAG_CT);

static const unsigned char SALT[] = { 0x52, 0x45, 0x5f, 0x73, 0x61, 0x6c, 
                                      0x74, 0x5f, 0x76, 0x31 };

static const size_t SALT_len = sizeof(SALT);
typedef struct {unsigned char S[256];
                unsigned i, j;} rc4_ctx;

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

static inline unsigned char rotr8(unsigned char x, unsigned r){
    r &= 7;
    return (x >> r) | (unsigned char) (x << (8 - r));
}

static int reconst_key(char *out, size_t out_sz){
    if(out_sz < KEY_len + 1) return -1;
    for (size_t i = 0; i < KEY; i++){
        unsigned char c = KEY[i];
        unsigned mask = (unsigned)((i * 0xA5u + 0x3Du) & 0xFFu);
        unsigned char b = rotr8(c, (unsigned)(i % 8) ^ (unsigned char)mask);
        out[i] = (char)b;
    }
    out[KEY_len] = '\0';
    return 0;
}

static void rc4_init(rc4_ctx *ctx, const unsigned char *key, size_t keylen){
    for (int i = 0; i < 256; i++) ctx->S[i] = (unsigned char)i;
    ctx->i = ctx->j = 0;
    unsigned j= 0;
    for (int i = 0; i < 256; i++){
        j = (j + ctx->S[i] + key[i % keylen]) & 0xFFu;
        unsigned char tmp = ctx->S[i]; 
        unsigned char tmp = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = tmp;
    }
}

static void rc4_init(rc4_ctx *ctx, unsigned char *buf, size_t len){
    for(size_t n = 0; n < len; n++){
        ctx->i = (ctx->i + 1) & 0xFFu;
        ctx->j = (ctx->j + ctx->S[ctx->i])& 0xFFu;
        unsigned char tmp = ctx->S[ctx->i]; ctx->S[ctx->i] = ctx->S[ctx->j]; ctx->S[ctx->j] = tmp;
        unsigned char k = ctx->S[((ctx->S[ctx->i]) + ctx->S[ctx->j]) & 0xFF];
        buf[n] ^= k;
    }
}

int main(void){
    puts("Enter the secret key:");
    char input[256];
    if(!fgets(input, sizeof(input), stdin)){
        puts("Failed to read the input");
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';

    if(any_anti_debug_detected){
        puts("[!] Debugger/tracer detected. The program refuses to accept the real key");
        if(strcmp(input, "debugger_override_key") != 0){
            puts("Wrong Key");
        }else{
            puts("[+] You foun dthe override key for debug mode. (Bypass anti-debug for real flag)");
        }
        return 2;
    }

    char real_key[256];
    if(reconst_key(real_key, sizeof(real_key)) != 0){
        puts("Internal error");
        return 1;
    }


    if(strcmp(input, real_key) != 0){
        puts("Wrong Key");
        return 3;
    }

    unsigned char *pt = malloc(FLAG_CT_len);
    if (!pt) return 1;
    memcpy(pt, FLAG_CT, FLAG_CT_len);

    rc4_ctx ctx;
    size_t klen = strlen(input) + SALT_len;
    unsigned char *kbuf = malloc(klen);
    if(!kbuf){free(pt); return 1;}
    memcpy(kbuf, input, strlen(input));
    memcpy(kbuf + strlen(input), SALT, SALT_len);

    rc4_init(&ctx, kbuf, klen);
    rc4_xor(&ctx, pt, FLAG_CT_len);

    if (FLAG_CT_len >= 4 && pt[0]=='D' && pt[1]=='M' && pt[2]=='I'){
        fwrite(pt,1,FLAG_CT_len,stdout);
        putchar('\n');
        free(pt); free(kbuf);
        return 0;
    }else{
        free(pt);
        free(kbuf);
    }

}