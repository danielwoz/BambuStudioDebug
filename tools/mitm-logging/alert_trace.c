// alert_trace.c — LD_PRELOAD diagnostic that localizes the code inside the
// VMProtect-unpacked network plugin that EMITS a TLS fatal alert (specifically
// unknown_ca, desc 0x30) on the cloud-MQTT leg. No ptrace.
//
// A rejected server certificate is refused by OpenSSL sending a *plaintext*
// handshake-phase alert record on the socket: 15 03 03 00 02 LL DD where
// LL=level (02=fatal) and DD=description (0x30 = unknown_ca = 48). Because the
// plugin's bundled OpenSSL writes that record through the libc socket layer
// (write/send), interposing those libc calls lets us catch the exact byte
// pattern and capture a backtrace() at the emission site. Each frame resolves
// via dladdr to <module>+<offset>; the plugin frames give the runtime offset of
// the alert-send path, a few frames below the certificate-verify branch.
//
// On the first fatal-alert match it also snapshots /proc/self/maps so the
// plugin's anonymous unpacked exec region (and its base) can be recovered for
// offline disassembly.
//
// Build: gcc -O2 -fPIC -shared -rdynamic -o alert_trace.so alert_trace.c -ldl
// Use:   LD_PRELOAD=alert_trace.so:mitm_redirect.so ... ALERT_TRACE_OUT=/tmp/alert_bt.log

#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);

static const char *outpath(void)
{
    const char *o = getenv("ALERT_TRACE_OUT");
    return (o && *o) ? o : "/tmp/alert_trace.log";
}

/* Is this buffer a TLS handshake-phase alert record?  15 03 0x 00 02 LL DD */
static int is_tls_alert(const unsigned char *b, size_t n, int *level, int *desc)
{
    if (n < 7) return 0;
    if (b[0] != 0x15) return 0;             /* content type = alert */
    if (b[1] != 0x03) return 0;             /* TLS major */
    if (b[3] != 0x00 || b[4] != 0x02) return 0; /* record length = 2 */
    *level = b[5];
    *desc  = b[6];
    return 1;
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

static void report_alert(int fd, const unsigned char *b, size_t n)
{
    int level = 0, desc = 0;
    if (!is_tls_alert(b, n, &level, &desc)) return;
    /* level 2 = fatal; desc 0x30 = unknown_ca, 0x2a = bad_certificate,
     * 0x2b = unsupported_cert, 0x2f = illegal_parameter. Log every fatal. */
    if (level != 2) return;

    FILE *f = fopen(outpath(), "a");
    if (!f) return;
    fprintf(f, "=== TLS FATAL ALERT fd=%d level=%d desc=0x%02x (%s) ===\n",
            fd, level, desc,
            desc == 0x30 ? "unknown_ca" :
            desc == 0x2a ? "bad_certificate" :
            desc == 0x2b ? "unsupported_certificate" :
            desc == 0x2f ? "illegal_parameter" :
            desc == 0x28 ? "handshake_failure" : "other");

    void *bt[48];
    int cnt = backtrace(bt, 48);
    char **sym = backtrace_symbols(bt, cnt);
    for (int i = 0; i < cnt; i++) {
        Dl_info di;
        if (dladdr(bt[i], &di) && di.dli_fbase) {
            unsigned long off = (unsigned long)bt[i] - (unsigned long)di.dli_fbase;
            fprintf(f, "  #%02d %p  %s+0x%lx  (%s)\n", i, bt[i],
                    di.dli_fname ? di.dli_fname : "?", off,
                    sym ? sym[i] : "?");
        } else {
            fprintf(f, "  #%02d %p  %s\n", i, bt[i], sym ? sym[i] : "?");
        }
    }
    free(sym);
    fclose(f);
    dump_maps_once();
}

ssize_t write(int fd, const void *buf, size_t n)
{
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    report_alert(fd, (const unsigned char *)buf, n);
    return real_write(fd, buf, n);
}

ssize_t send(int fd, const void *buf, size_t n, int flags)
{
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");
    report_alert(fd, (const unsigned char *)buf, n);
    return real_send(fd, buf, n, flags);
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags,
               const struct sockaddr *to, socklen_t tolen)
{
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    report_alert(fd, (const unsigned char *)buf, n);
    return real_sendto(fd, buf, n, flags, to, tolen);
}
