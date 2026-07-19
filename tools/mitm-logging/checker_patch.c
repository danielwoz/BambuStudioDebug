// checker_patch.c — LD_PRELOAD neutralizer for the genuine Bambu network plugin's
// periodic code-integrity monitor, so the cloud-MQTT pin NOP (pin_patch.c) can
// stay resident INDEFINITELY without the plugin self-destructing, and WITHOUT
// parking any thread (so device networking keeps running). No ptrace; the patch
// is written via /proc/self/mem after the plugin unpacks.
//
// Structure of the checker (static RE of the unpacked r-xp region, rebased):
// ---------------------------------------------------------------------------
// libbambu_networking.so runs a DEDICATED std::thread whose entire callable is a
// plain-x86 monitor loop at plugin+0x250ec0 (thread-invoke trampoline return
// addr +0x5584f5; the loop's `call exit` return addr +0x250f50 is what appears in
// the death backtrace). The loop sleeps ~100 ms/iteration and every 300 iters runs
// two VMProtect-VIRTUALIZED helpers and decides in PLAIN x86:
//
//     +0x250f32  mov  edi, 1
//     +0x250f37  call funcA            ; 0x351990 -> virtualized (0x..19dc3c)
//     +0x250f3c  test al, al
//     +0x250f3e  jne  +0x250f49        ; funcA != 0  -> EXIT path
//     +0x250f40  call funcB            ; 0x3528d0 -> virtualized (0x..bc7e9c): the
//                                      ;   code-region hash/integrity check
//     +0x250f45  test al, al
//     +0x250f47  jne  +0x250efd        ; funcB != 0  -> PASS, continue loop
//     +0x250f49  xor  edi, edi
//     +0x250f4b  call exit             ; 0x351d70 -> exit(0)  (init one-shot); the
//                                      ;   periodic path's atexit handler +0x2f2980
//                                      ;   then routes through std::terminate
//     +0x250f50  mov  rax, [rbp+0x138] ; (return addr captured in backtrace)
//
// funcA/funcB are virtualized and cannot be cheaply read, BUT they only RETURN a
// boolean; the exit/terminate DECISION is the two plain-x86 branches above. So the
// hash is neutralized WITHOUT reversing it — and without caring whether it hashes
// its own bytes — by hardcoding the decision to "always pass":
//
//     +0x250f3e  75 09  jne +0x250f49  ->  90 90  nop; nop     (ignore funcA)
//     +0x250f47  75 b4  jne +0x250efd  ->  eb b4  jmp +0x250efd (ignore funcB,
//                                                                always continue)
//
// After both edits the `call exit` at +0x250f4b is unreachable: even if funcB
// hashes the (now-patched) loop and returns "tampered", the loop can no longer
// reach exit/terminate. funcA/funcB are still CALLED (side effects preserved).
// There is exactly ONE such monitor loop in the image (the imul-magic 0x1b4e81b5
// and this masked signature each occur once), i.e. a single root checker.
//
// Build: gcc -O2 -fPIC -shared -Wall -o checker_patch.so checker_patch.c -lpthread
// Use:   LD_PRELOAD=checker_patch.so:pin_patch.so:mitm_redirect.so ... <studio>
//        CHECKER_PATCH_LOG=/tmp/checker_patch.log  (optional)
//        CHECKER_PATCH_DRYRUN=1                     (locate only, do not modify)

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define PLUGIN_NAME "libbambu_networking.so"

// Masked signature starting at +0x250f32 (call rel32 displacements wildcarded).
// bf 01 00 00 00 | e8 ?? ?? ?? ?? | 84 c0 75 09 | e8 ?? ?? ?? ?? | 84 c0 75 b4 | 31 ff e8
static const unsigned char SIG[] = {
    0xbf,0x01,0x00,0x00,0x00,  0xe8,0,0,0,0,  0x84,0xc0,0x75,0x09,
    0xe8,0,0,0,0,  0x84,0xc0,0x75,0xb4,  0x31,0xff,0xe8
};
static const unsigned char MSK[] = {
    1,1,1,1,1, 1,0,0,0,0, 1,1,1,1,
    1,0,0,0,0, 1,1,1,1, 1,1,1
};
#define SIG_LEN (sizeof SIG)
#define OFF_JNE_A 12   // 75 09  -> 90 90
#define OFF_JNE_B 21   // 75 b4  -> eb b4 (byte at +21 only: 0x75 -> 0xeb)

static const char *logpath(void){ const char*p=getenv("CHECKER_PATCH_LOG"); return (p&&*p)?p:"/tmp/checker_patch.log"; }
static void plog(const char *fmt, ...){
    FILE*f=fopen(logpath(),"a"); if(!f) return;
    struct timespec tv; clock_gettime(CLOCK_REALTIME,&tv); time_t t=tv.tv_sec; char ts[32];
    strftime(ts,sizeof ts,"%H:%M:%S",localtime(&t));
    fprintf(f,"[%s.%03ld] ",ts,tv.tv_nsec/1000000);
    va_list ap; va_start(ap,fmt); vfprintf(f,fmt,ap); va_end(ap); fputc('\n',f); fclose(f);
}

static int masked_eq(const unsigned char *p){
    for(size_t k=0;k<SIG_LEN;k++) if(MSK[k] && p[k]!=SIG[k]) return 0;
    return 1;
}

static int write_procmem(unsigned char *dst,const unsigned char *src,size_t n){
    int fd=open("/proc/self/mem",O_RDWR); if(fd<0) return 0;
    ssize_t w=pwrite(fd,src,n,(off_t)(uintptr_t)dst); close(fd);
    if(w!=(ssize_t)n) return 0;
    __builtin___clear_cache((char*)dst,(char*)dst+n);
    return 1;
}

static int plugin_span(uintptr_t *lo_out,uintptr_t *hi_out){
    FILE*m=fopen("/proc/self/maps","r"); if(!m) return 0;
    char line[512]; uintptr_t lo=(uintptr_t)-1,hi=0;
    while(fgets(line,sizeof line,m)){
        if(!strstr(line,PLUGIN_NAME)) continue;
        uintptr_t a,b; if(sscanf(line,"%lx-%lx",&a,&b)!=2) continue;
        if(a<lo) lo=a; if(b>hi) hi=b;
    }
    fclose(m); if(hi==0) return 0; *lo_out=lo; *hi_out=hi; return 1;
}

// Locate the monitor loop's decision site in the plugin's unpacked r-x span and
// apply the two edits. Returns 1 if (already) neutralized, 0 if not found yet.
static int scan_and_patch(void){
    uintptr_t plo,phi; if(!plugin_span(&plo,&phi)) return 0;
    FILE*m=fopen("/proc/self/maps","r"); if(!m) return 0;
    char line[512]; int done=0;
    while(fgets(line,sizeof line,m)){
        uintptr_t lo,hi; char perms[8];
        if(sscanf(line,"%lx-%lx %7s",&lo,&hi,perms)!=3) continue;
        if(perms[0]!='r'||perms[2]!='x') continue;
        if(lo<plo||hi>phi) continue;
        size_t sz=hi-lo; if(sz>(64u<<20)) continue;
        unsigned char *base=(unsigned char*)lo;
        for(size_t i=0;i+SIG_LEN<=sz;i++){
            if(base[i]!=SIG[0]) continue;
            if(!masked_eq(base+i)) continue;
            unsigned char *jneA=base+i+OFF_JNE_A;   // expect 75 09
            unsigned char *jneB=base+i+OFF_JNE_B;   // expect 75 b4
            int a_done = (jneA[0]==0x90 && jneA[1]==0x90);
            int b_done = (jneB[0]==0xeb);
            if(a_done && b_done){ done=1; continue; }
            if(getenv("CHECKER_PATCH_DRYRUN")){
                plog("DRYRUN: monitor loop at %p (jneA=%02x %02x jneB=%02x)",
                     (void*)(base+i),jneA[0],jneA[1],jneB[0]);
                done=1; continue;
            }
            unsigned char nop2[2]={0x90,0x90};
            unsigned char jmp1[1]={0xeb};
            int ok = write_procmem(jneA,nop2,2) && write_procmem(jneB,jmp1,1);
            if(ok){
                plog("NEUTRALIZED checker at %p (+span %p-%p): funcA-jne->nop nop, funcB-jne->jmp; exit unreachable",
                     (void*)(base+i),(void*)plo,(void*)phi);
                done=1;
            } else {
                plog("write failed at %p",(void*)(base+i));
            }
        }
    }
    fclose(m);
    return done;
}

static void *worker(void *arg){
    (void)arg;
    plog("checker_patch loaded (pid %d); scanning for integrity monitor loop",(int)getpid());
    int announced=0;
    for(int i=0;i<6000;i++){                 // ~10 min; re-apply if ever reverted
        int done=scan_and_patch();
        if(done && !announced){ plog("checker neutralized; pin NOP can stay resident indefinitely"); announced=1; }
        struct timespec ts={0,100*1000*1000}; nanosleep(&ts,NULL);
    }
    plog("watch loop done");
    return NULL;
}

__attribute__((constructor))
static void init(void){
    pthread_t t;
    if(pthread_create(&t,NULL,worker,NULL)==0) pthread_detach(t);
}
