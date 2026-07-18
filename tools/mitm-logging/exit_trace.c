// exit_trace.c — LD_PRELOAD probe for the network plugin's ONE-SHOT init-time
// integrity check. That check fires at the first cloud TLS use (~10.7s) and, if
// the pin bytes are already patched, kills the process WITHOUT a signal or
// std::terminate (death_trace sees nothing) — so it likely routes through an
// exit-family libc call. Confirmed: the checker calls plain exit(0) from
// libbambu_networking.so+0x250f50 (thread entry +0x5584f5) — the SAME routine the
// periodic std::terminate (+0x2f2980) also routes through. This shim interposes
// exit/_exit/_Exit/quick_exit/abort (plus kill/tgkill/raise), logs plugin-frame
// callers, and — when EXIT_BLOCK_PLUGIN is set — neutralizes the plugin's exit:
//   EXIT_BLOCK_PLUGIN=1  RETURN to the caller (checker continues; but a plugin
//                        second-stage std::thread-dtor std::terminate then fires).
//   EXIT_BLOCK_PLUGIN=2  PARK the calling thread (process survives indefinitely
//                        with NO secondary SIGSEGV, unlike tamper_park — but the
//                        parked worker also drives the device-connect leg, which
//                        then stalls). See docs/MITM_TAMPER_VERDICT.md.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *PLUGIN = "libbambu_networking.so";
static const char *outpath(void){ const char*o=getenv("EXIT_TRACE_OUT"); return (o&&*o)?o:"/tmp/exit_trace.log"; }

static int caller_in_plugin(void **bt,int n){
  for(int i=0;i<n;i++){ Dl_info d; if(dladdr(bt[i],&d)&&d.dli_fname&&strstr(d.dli_fname,PLUGIN)) return 1; }
  return 0;
}
static void logbt(const char*fn,int code){
  void*bt[64]; int n=backtrace(bt,64); int plugin=caller_in_plugin(bt,n);
  if(!plugin) return;                 // ignore benign sh/libc exits; only the plugin matters
  struct timespec tp; clock_gettime(CLOCK_REALTIME,&tp); time_t t=tp.tv_sec; struct tm tm; localtime_r(&t,&tm);
  char ts[32]; int k=strftime(ts,sizeof ts,"%H:%M:%S",&tm); snprintf(ts+k,sizeof ts-k,".%03ld",tp.tv_nsec/1000000);
  FILE*f=fopen(outpath(),"a"); if(!f) return;
  fprintf(f,"\n=== [%s] %s(%d) tid=%ld plugin_frame=1 ===\n",ts,fn,code,(long)gettid());
  for(int i=0;i<n&&i<20;i++){ Dl_info d;
    if(dladdr(bt[i],&d)&&d.dli_fbase) fprintf(f,"  #%02d %s+0x%lx\n",i,d.dli_fname?d.dli_fname:"?",(unsigned long)bt[i]-(unsigned long)d.dli_fbase);
    else fprintf(f,"  #%02d %p\n",i,bt[i]); }
  const char *mode = getenv("EXIT_BLOCK_PLUGIN");
  int block = mode && *mode;
  int park  = mode && mode[0]=='2';            // =2 parks the thread; =1 returns to caller
  fprintf(f, !block ? "  -> passing through\n" :
             park   ? "  -> PARKING thread\n" : "  -> RETURNING to caller (check neutralized)\n");
  fclose(f);
  if(block){ if(park){ for(;;) pause(); } return; }  // =1: return so the checker continues its normal path
}
// exit/_exit are noreturn in libc's view; our interceptors below consult logbt,
// which for a plugin-frame caller under EXIT_BLOCK_PLUGIN=1 RETURNS here, so we
// fall through and return to the caller instead of terminating.
#include <sys/syscall.h>
int kill(pid_t p,int s){ static int(*real)(pid_t,int)=0; if(!real) real=dlsym(RTLD_NEXT,"kill"); logbt("kill",s); return real(p,s); }
int tgkill(int tg,int t,int s){ static int(*real)(int,int,int)=0; if(!real) real=dlsym(RTLD_NEXT,"tgkill"); logbt("tgkill",s); return real(tg,t,s); }
int raise(int s){ static int(*real)(int)=0; if(!real) real=dlsym(RTLD_NEXT,"raise"); logbt("raise",s); return real(s); }

#define HOOK(name,ret,proto,call,code) \
  ret name proto { static ret(*real)proto=0; if(!real) real=dlsym(RTLD_NEXT,#name); logbt(#name,code); return real call; }

void exit(int s){ static void(*real)(int)=0; if(!real) real=dlsym(RTLD_NEXT,"exit"); logbt("exit",s); real(s); __builtin_unreachable(); }
void _exit(int s){ static void(*real)(int)=0; if(!real) real=dlsym(RTLD_NEXT,"_exit"); logbt("_exit",s); real(s); __builtin_unreachable(); }
void _Exit(int s){ static void(*real)(int)=0; if(!real) real=dlsym(RTLD_NEXT,"_Exit"); logbt("_Exit",s); real(s); __builtin_unreachable(); }
void quick_exit(int s){ static void(*real)(int)=0; if(!real) real=dlsym(RTLD_NEXT,"quick_exit"); logbt("quick_exit",s); real(s); __builtin_unreachable(); }
void abort(void){ static void(*real)(void)=0; if(!real) real=dlsym(RTLD_NEXT,"abort"); logbt("abort",0); real(); __builtin_unreachable(); }
