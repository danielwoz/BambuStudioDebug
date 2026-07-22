// LD_PRELOAD socket tracer.
//
// Interposes the BSD socket calls a process makes and appends a line per call
// to $SOCKLOG_OUT: timestamp, thread id, fd, peer address, byte count, and a
// hex preview of the payload. It captures raw UDP/TCP the way the process sends
// it, which is what the REST-level MITM cannot see: the genuine Bambu network
// plugin self-resolves DNS and runs its TUTK camera transport as raw UDP.
//
// It only wraps syscalls (no ptrace, no memory patching), so it does not trip
// the plugin's tamper detection.
//
// Environment:
//   SOCKLOG_OUT   output file path            (default /tmp/socklog.txt, appended)
//   SOCKLOG_MAX   payload bytes logged as hex (default 2048; 0 = header only)
//
// Build: ./build_socklog.sh   (gcc -shared -fPIC -ldl -lpthread)
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>

static int             g_fd  = -1;
static size_t          g_cap = 2048;                 // payload hex cap in bytes
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t  g_once = PTHREAD_ONCE_INIT;

static void init_once(void) {
    const char* out = getenv("SOCKLOG_OUT");
    g_fd = open(out ? out : "/tmp/socklog.txt",
                O_CREAT | O_WRONLY | O_APPEND, 0644);
    const char* cap = getenv("SOCKLOG_MAX");
    if (cap && *cap) {
        long v = strtol(cap, NULL, 10);
        if (v >= 0) g_cap = (size_t)v;
    }
}

// Emit "<sec>.<usec> T<tid> <text>\n". The payload preview is passed already
// formatted so the total length is bounded by the caller's buffer.
static void logline(const char* text) {
    pthread_once(&g_once, init_once);
    if (g_fd < 0) return;
    char hdr[64];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int hn = snprintf(hdr, sizeof hdr, "%ld.%06ld T%ld ",
                      ts.tv_sec, ts.tv_nsec / 1000,
                      (long)pthread_self() % 100000);
    size_t tn = strlen(text);
    pthread_mutex_lock(&g_mu);
    ssize_t w;
    w = write(g_fd, hdr, hn);
    w = write(g_fd, text, tn);
    w = write(g_fd, "\n", 1);
    (void)w;
    pthread_mutex_unlock(&g_mu);
}

static void addrstr(const struct sockaddr* a, socklen_t l, char* out, size_t olen) {
    if (!a || l == 0) { snprintf(out, olen, "(null)"); return; }
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in* s = (const void*)a;
        char ip[64]; inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
        snprintf(out, olen, "%s:%d", ip, ntohs(s->sin_port));
    } else if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6* s = (const void*)a;
        char ip[128]; inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof ip);
        snprintf(out, olen, "[%s]:%d", ip, ntohs(s->sin6_port));
    } else snprintf(out, olen, "fam=%d", a->sa_family);
}

// Hex-encode up to g_cap bytes into a freshly allocated string (caller frees).
static char* hexdup(const void* buf, size_t n) {
    size_t m = (n < g_cap) ? n : g_cap;
    char* out = malloc(m * 2 + 1);
    if (!out) return NULL;
    static const char hx[] = "0123456789abcdef";
    const unsigned char* p = buf;
    size_t o = 0;
    for (size_t i = 0; i < m; i++) { out[o++] = hx[p[i] >> 4]; out[o++] = hx[p[i] & 15]; }
    out[o] = 0;
    return out;
}

// Emit an event whose text is "<prefix> data=<hex>". Splits the malloc so the
// hex string can be arbitrarily large without a fixed stack buffer.
static void logdata(const char* prefix, const void* buf, size_t n) {
    char* hex = (g_cap && n) ? hexdup(buf, n) : NULL;
    size_t need = strlen(prefix) + 7 + (hex ? strlen(hex) : 0) + 1;
    char* line = malloc(need);
    if (line) {
        snprintf(line, need, "%s data=%s", prefix, hex ? hex : "");
        logline(line);
        free(line);
    }
    free(hex);
}

#define REAL(name) static typeof(name)* real_##name; \
    if (!real_##name) real_##name = dlsym(RTLD_NEXT, #name);

int socket(int d, int t, int p) {
    REAL(socket); int fd = real_socket(d, t, p);
    char b[96]; snprintf(b, sizeof b, "socket domain=%d type=%d proto=%d -> fd=%d", d, t, p, fd);
    logline(b); return fd;
}
int bind(int fd, const struct sockaddr* a, socklen_t l) {
    REAL(bind); char as[160]; addrstr(a, l, as, sizeof as);
    int r = real_bind(fd, a, l);
    char b[256]; snprintf(b, sizeof b, "bind fd=%d %s -> %d", fd, as, r);
    logline(b); return r;
}
int connect(int fd, const struct sockaddr* a, socklen_t l) {
    REAL(connect); char as[160]; addrstr(a, l, as, sizeof as);
    int r = real_connect(fd, a, l);
    char b[256]; snprintf(b, sizeof b, "connect fd=%d %s -> %d", fd, as, r);
    logline(b); return r;
}
int setsockopt(int fd, int lvl, int opt, const void* v, socklen_t l) {
    REAL(setsockopt);
    int r = real_setsockopt(fd, lvl, opt, v, l);
    char pfx[128]; snprintf(pfx, sizeof pfx, "setsockopt fd=%d lvl=%d opt=%d len=%d -> %d", fd, lvl, opt, (int)l, r);
    logdata(pfx, v, l); return r;
}
ssize_t sendto(int fd, const void* b, size_t n, int f, const struct sockaddr* a, socklen_t l) {
    REAL(sendto); char as[160]; addrstr(a, l, as, sizeof as);
    ssize_t r = real_sendto(fd, b, n, f, a, l);
    char pfx[256]; snprintf(pfx, sizeof pfx, "sendto fd=%d to=%s len=%zu -> %zd", fd, as, n, r);
    logdata(pfx, b, n); return r;
}
ssize_t send(int fd, const void* b, size_t n, int f) {
    REAL(send);
    ssize_t r = real_send(fd, b, n, f);
    char pfx[128]; snprintf(pfx, sizeof pfx, "send fd=%d len=%zu -> %zd", fd, n, r);
    logdata(pfx, b, n); return r;
}
ssize_t recvfrom(int fd, void* b, size_t n, int f, struct sockaddr* a, socklen_t* l) {
    REAL(recvfrom); ssize_t r = real_recvfrom(fd, b, n, f, a, l);
    char as[160]; addrstr(a, l ? *l : 0, as, sizeof as);
    char pfx[256]; snprintf(pfx, sizeof pfx, "recvfrom fd=%d from=%s -> %zd", fd, as, r);
    logdata(pfx, b, r > 0 ? (size_t)r : 0); return r;
}
ssize_t sendmsg(int fd, const struct msghdr* m, int f) {
    REAL(sendmsg); char as[160]; addrstr(m ? m->msg_name : 0, m ? m->msg_namelen : 0, as, sizeof as);
    ssize_t r = real_sendmsg(fd, m, f);
    char pfx[256]; snprintf(pfx, sizeof pfx, "sendmsg fd=%d to=%s -> %zd", fd, as, r);
    if (m && m->msg_iovlen > 0) logdata(pfx, m->msg_iov[0].iov_base, m->msg_iov[0].iov_len);
    else logline(pfx);
    return r;
}
ssize_t recvmsg(int fd, struct msghdr* m, int f) {
    REAL(recvmsg); ssize_t r = real_recvmsg(fd, m, f);
    char as[160]; addrstr(m ? m->msg_name : 0, m ? m->msg_namelen : 0, as, sizeof as);
    char pfx[256]; snprintf(pfx, sizeof pfx, "recvmsg fd=%d from=%s -> %zd", fd, as, r);
    if (r > 0 && m && m->msg_iovlen > 0) logdata(pfx, m->msg_iov[0].iov_base, m->msg_iov[0].iov_len);
    else logline(pfx);
    return r;
}
