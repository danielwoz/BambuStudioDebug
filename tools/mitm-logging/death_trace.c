// death_trace.c — LD_PRELOAD diagnostic that catches the *moment of death* of a
// process and attributes the terminating frame to a module + offset. Its purpose
// is to decide whether a crash originates INSIDE the VMProtect-unpacked network
// plugin (a tamper self-destruct) or in wx / GTK / glib / libstdc++ / the C
// runtime (an environmental fault).
//
// It installs two catchers:
//   1. std::set_terminate — fires for "terminate called ..." deaths (uncaught
//      C++ exception, std::thread destroyed while joinable, pure-virtual call,
//      noexcept violation). Captures a backtrace at the point std::terminate was
//      entered, so the frame that *called* terminate is visible.
//   2. SIGABRT / SIGSEGV / SIGILL / SIGBUS / SIGTRAP handlers — fire for raw
//      abort()/faults, including a tamper routine that aborts or jumps to a bad
//      address. Captures a backtrace from the faulting context.
//
// Every frame is resolved with dladdr to <module>+<hex-offset>. For the network
// plugin the interesting frames land inside its own reserved vaddr span (the
// anonymous unpacked exec region maps within it) — that is the tamper signal.
// A first-death /proc/self/maps snapshot lets those anonymous frames be located
// offline. After logging, the original disposition is restored and re-raised so
// the process still dies exactly as it would have.
//
// Build: g++ -O2 -fPIC -shared -rdynamic -o death_trace.so death_trace.c -ldl -lpthread
// Use:   LD_PRELOAD=death_trace.so:...  DEATH_TRACE_OUT=/tmp/death_bt.log <studio>

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
    const char *o = getenv("DEATH_TRACE_OUT");
    return (o && *o) ? o : "/tmp/death_bt.log";
}

static void ts(char *buf, size_t n)
{
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    time_t t = tp.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    int k = (int)strftime(buf, n, "%H:%M:%S", &tm);
    snprintf(buf + k, n - k, ".%03ld", tp.tv_nsec / 1000000);
}

static void dump_maps_once(void)
{
    static int done = 0;
    if (done) return;
    done = 1;
    char dst[512];
    snprintf(dst, sizeof dst, "%s.maps", outpath());
    FILE *in = fopen("/proc/self/maps", "r");
    FILE *out = fopen(dst, "w");
    if (in && out) {
        char line[1024];
        while (fgets(line, sizeof line, in)) fputs(line, out);
    }
    if (in) fclose(in);
    if (out) fclose(out);
}

// Resolve and print a captured backtrace with module+offset attribution.
static void write_bt(FILE *f, void **bt, int cnt)
{
    char **sym = backtrace_symbols(bt, cnt);
    for (int i = 0; i < cnt; i++) {
        Dl_info di;
        if (dladdr(bt[i], &di) && di.dli_fbase) {
            unsigned long off = (unsigned long)bt[i] - (unsigned long)di.dli_fbase;
            fprintf(f, "  #%02d %p  %s+0x%lx",
                    i, bt[i], di.dli_fname ? di.dli_fname : "?", off);
            if (di.dli_sname)
                fprintf(f, "  <%s+0x%lx>", di.dli_sname,
                        (unsigned long)bt[i] - (unsigned long)di.dli_saddr);
            fputc('\n', f);
        } else {
            // No owning object: an anonymous exec region (e.g. the plugin's
            // unpacked VMProtect code). Print the raw address; the .maps
            // snapshot attributes it offline.
            fprintf(f, "  #%02d %p  <anon/unresolved>%s\n",
                    i, bt[i], sym ? sym[i] : "");
        }
    }
    free(sym);
}

extern "C" {

static struct sigaction old_abrt, old_segv, old_ill, old_bus, old_trap;

static void sig_handler(int sig, siginfo_t *si, void *uctx)
{
    (void)uctx;
    char tbuf[32]; ts(tbuf, sizeof tbuf);
    FILE *f = fopen(outpath(), "a");
    if (f) {
        fprintf(f, "\n=== [%s] FATAL SIGNAL %d (%s) pid=%d tid=%ld addr=%p ===\n",
                tbuf, sig, strsignal(sig), getpid(), (long)gettid(),
                si ? si->si_addr : 0);
        void *bt[64];
        int cnt = backtrace(bt, 64);
        write_bt(f, bt, cnt);
        fclose(f);
    }
    dump_maps_once();
    // Restore default disposition and re-raise so death proceeds unchanged.
    struct sigaction *old =
        sig == SIGABRT ? &old_abrt : sig == SIGSEGV ? &old_segv :
        sig == SIGILL  ? &old_ill  : sig == SIGBUS  ? &old_bus  : &old_trap;
    sigaction(sig, old, NULL);
    raise(sig);
}

} // extern "C"

static std::terminate_handler g_prev_terminate = nullptr;

static void terminate_handler(void)
{
    char tbuf[32]; ts(tbuf, sizeof tbuf);
    FILE *f = fopen(outpath(), "a");
    if (f) {
        fprintf(f, "\n=== [%s] std::terminate ENTERED pid=%d tid=%ld ===\n",
                tbuf, getpid(), (long)gettid());
        // If a C++ exception is in flight, name it.
        std::exception_ptr ep = std::current_exception();
        if (ep) {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) {
                fprintf(f, "  active exception: std::exception: %s\n", e.what());
            }
            catch (...) { fprintf(f, "  active exception: (non-std type)\n"); }
        } else {
            fprintf(f, "  no active exception (direct std::terminate: "
                       "joinable std::thread dtor / pure-virtual / noexcept)\n");
        }
        void *bt[64];
        int cnt = backtrace(bt, 64);
        write_bt(f, bt, cnt);
        fclose(f);
    }
    dump_maps_once();
    if (g_prev_terminate) g_prev_terminate();
    abort();
}

__attribute__((constructor))
static void init(void)
{
    char tbuf[32]; ts(tbuf, sizeof tbuf);
    FILE *f = fopen(outpath(), "a");
    if (f) {
        fprintf(f, "\n### [%s] death_trace armed in pid=%d ###\n", tbuf, getpid());
        fclose(f);
    }
    g_prev_terminate = std::set_terminate(terminate_handler);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, &old_abrt);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGILL,  &sa, &old_ill);
    sigaction(SIGBUS,  &sa, &old_bus);
    sigaction(SIGTRAP, &sa, &old_trap);
}
