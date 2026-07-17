// tamper_park.c — LD_PRELOAD countermeasure to the network plugin's delayed
// tamper self-destruct. Controls A/B established that after the cloud-MQTT pin
// patch is written, a plugin worker thread runs a content re-scan of its own
// code, detects the modified byte(s), and calls std::terminate (no active
// exception). std::terminate routes through the process-wide terminate handler
// pointer, so overriding it lets us intercept the self-destruct.
//
// This handler inspects the backtrace: if the frame that entered terminate lies
// inside libbambu_networking.so (the tamper checker), it parks THAT thread
// forever instead of aborting, so the rest of the process keeps running and the
// established cloud session stays up. A terminate that originates outside the
// plugin (a genuine app fault) is passed through to the normal abort path so we
// do not mask real bugs.
//
// Build: g++ -O2 -fPIC -shared -rdynamic -o tamper_park.so tamper_park.c -ldl -lpthread
// Use:   LD_PRELOAD=tamper_park.so:pin_patch.so:mitm_redirect.so ...

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <execinfo.h>
#include <exception>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *outpath(void)
{
    const char *o = getenv("TAMPER_PARK_OUT");
    return (o && *o) ? o : "/tmp/tamper_park.log";
}

static void tstamp(char *b, size_t n)
{
    struct timespec tp; clock_gettime(CLOCK_REALTIME, &tp);
    time_t t = tp.tv_sec; struct tm tm; localtime_r(&t, &tm);
    int k = (int)strftime(b, n, "%H:%M:%S", &tm);
    snprintf(b + k, n - k, ".%03ld", tp.tv_nsec / 1000000);
}

static const char *PLUGIN = "libbambu_networking.so";

// Does any frame in the captured backtrace belong to the network plugin?
static int caller_in_plugin(void **bt, int cnt)
{
    for (int i = 0; i < cnt; i++) {
        Dl_info di;
        if (dladdr(bt[i], &di) && di.dli_fname && strstr(di.dli_fname, PLUGIN))
            return 1;
    }
    return 0;
}

// Optional: also backtrace a fatal signal (a second-stage tamper may fault
// deliberately after its terminate is parked). Enabled with TAMPER_PARK_SIGBT=1.
static struct sigaction old_segv, old_abrt, old_ill, old_bus;

extern "C" void tp_sig(int sig, siginfo_t *si, void *u)
{
    (void)u;
    void *bt[64]; int cnt = backtrace(bt, 64);
    int plugin = caller_in_plugin(bt, cnt);
    char tb[32]; tstamp(tb, sizeof tb);
    FILE *f = fopen(outpath(), "a");
    if (f) {
        fprintf(f, "\n=== [%s] FATAL SIGNAL %d (%s) tid=%ld addr=%p plugin_frame=%d ===\n",
                tb, sig, strsignal(sig), (long)gettid(), si ? si->si_addr : 0, plugin);
        for (int i = 0; i < cnt && i < 16; i++) {
            Dl_info di;
            if (dladdr(bt[i], &di) && di.dli_fbase)
                fprintf(f, "  #%02d %s+0x%lx\n", i, di.dli_fname ? di.dli_fname : "?",
                        (unsigned long)bt[i] - (unsigned long)di.dli_fbase);
            else
                fprintf(f, "  #%02d %p <anon>\n", i, bt[i]);
        }
        fclose(f);
    }
    struct sigaction *old = sig == SIGSEGV ? &old_segv : sig == SIGABRT ? &old_abrt :
                            sig == SIGILL ? &old_ill : &old_bus;
    sigaction(sig, old, NULL);
    raise(sig);
}

static std::terminate_handler g_prev = nullptr;

static void handler(void)
{
    void *bt[64];
    int cnt = backtrace(bt, 64);
    int plugin = caller_in_plugin(bt, cnt);

    char tb[32]; tstamp(tb, sizeof tb);
    FILE *f = fopen(outpath(), "a");
    if (f) {
        fprintf(f, "\n=== [%s] std::terminate intercepted (tid=%ld) plugin_caller=%d ===\n",
                tb, (long)gettid(), plugin);
        char **sym = backtrace_symbols(bt, cnt);
        for (int i = 0; i < cnt && i < 12; i++) {
            Dl_info di;
            if (dladdr(bt[i], &di) && di.dli_fbase)
                fprintf(f, "  #%02d %s+0x%lx\n", i,
                        di.dli_fname ? di.dli_fname : "?",
                        (unsigned long)bt[i] - (unsigned long)di.dli_fbase);
            else
                fprintf(f, "  #%02d %p %s\n", i, bt[i], sym ? sym[i] : "");
        }
        free(sym);
        if (plugin)
            fprintf(f, "  -> PARKING this thread (tamper self-destruct neutralized)\n");
        else
            fprintf(f, "  -> passing through to abort (non-plugin terminate)\n");
        fclose(f);
    }

    if (plugin) {
        // Neutralize: never return (returning would trigger abort), never abort.
        // Park this one thread; the process and its other threads live on.
        for (;;) pause();
    }
    if (g_prev) g_prev();
    abort();
}

__attribute__((constructor))
static void init(void)
{
    char tb[32]; tstamp(tb, sizeof tb);
    FILE *f = fopen(outpath(), "a");
    if (f) { fprintf(f, "\n### [%s] tamper_park armed pid=%d ###\n", tb, getpid()); fclose(f); }
    g_prev = std::set_terminate(handler);

    if (getenv("TAMPER_PARK_SIGBT")) {
        struct sigaction sa; memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = tp_sig; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, &old_segv);
        sigaction(SIGABRT, &sa, &old_abrt);
        sigaction(SIGILL,  &sa, &old_ill);
        sigaction(SIGBUS,  &sa, &old_bus);
    }
}
