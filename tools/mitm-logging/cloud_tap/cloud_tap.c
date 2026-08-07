// cloud_tap — LD_PRELOAD in-process capture of the genuine plugin's HTTPS plaintext.
//
// Where the REST MITM (mitm_redirect.so) can't see traffic — the genuine Bambu
// network plugin statically links OpenSSL and pins the cloud CA, so a proxy (which
// would need the pinned verify overridden) never completes TLS — the decrypted
// HTTP request (request line + X-BBL-* headers + Bearer token) and response (JSON,
// PEM cert/key/crl) still live briefly in the plugin's PRIVATE heap while a
// request is in flight. This shim runs a background thread (started from a shared-
// object constructor, so it runs inside the same process as the dlopen'd genuine
// plugin) that scans anonymous readable heap regions via /proc/self/maps +
// /proc/self/mem for HTTP-plaintext markers and dumps each distinct block to
// $CLOUD_TAP_OUT. It captures exactly what a TLS MITM would see, read from the
// plugin's own buffers instead of the (encrypted) socket.
//
// It is passive (no ptrace, no code patches), so it does not trip tamper checks.
//
// Environment:
//   CLOUD_TAP_OUT   output file path       (default /tmp/cloud_tap.log, appended)
//   CLOUD_TAP_WIN   capture window bytes  (default 8192)
//
// Build: ./build_cloudtap.sh   (gcc -shared -fPIC -ldl -lpthread)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>

static FILE*           g_log = NULL;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile int    g_run = 0;
static size_t          g_win = 8192;
static pthread_t       g_thr;

static const char* const kMarkers[] = {
    "Authorization: Bearer","X-BBL-Client","X-BBL-Executable","X-BBL-Agent",
    "GET /v1/","POST /v1/","PUT /v1/","Host: api.bambulab","iot-service/api",
    "/applications/","\"aes256\"","app_key","cert_id","reinstall_app_key","\"crl\"",
    "-----BEGIN CERTIFICATE-----","-----BEGIN RSA PRIVATE","-----BEGIN PRIVATE KEY-----",
    "get_app_cert","device-security-sign","bambulab.com",
};
static const int NM = (int)(sizeof(kMarkers)/sizeof(kMarkers[0]));
static size_t g_mlen[64]; static int g_first[256]; static int g_tables_ready=0;

static void build_tables(void) {
    if (g_tables_ready) return;
    for (int i = 0; i < 256; ++i) g_first[i] = 0;
    for (int i = 0; i < NM; ++i) { g_mlen[i] = strlen(kMarkers[i]); g_first[(unsigned char)kMarkers[i][0]] = 1; }
    g_tables_ready = 1;
}

static uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static size_t grab_window(const uint8_t* base, size_t rsz, const uint8_t* at,
                         uint8_t* dst, size_t dstcap) {
    const uint8_t* start = at;
    size_t back = (size_t)(at - base);
    size_t lim = back < 3072 ? back : 3072;
    for (size_t k = 1; k <= lim; ++k) {
        const uint8_t* p = at - k;
        if (p+8 <= base+rsz && (memcmp(p,"GET /",5)==0||memcmp(p,"POST /",6)==0||memcmp(p,"PUT /",5)==0||memcmp(p,"DELETE ",7)==0||memcmp(p,"HTTP/1.",7)==0)) start=p;
    }
    size_t avail = (size_t)(base+rsz-start); size_t wn = avail<g_win?avail:g_win;
    memcpy(dst,start,wn); return wn;
}

static void emit(const char* marker, const uint8_t* va, const uint8_t* buf, size_t wn) {
    while (wn>0 && buf[wn-1]==0) --wn;
    if (wn<8) return;
    uint64_t h = fnv1a(buf, wn<256?wn:256);
    (void)h;
    pthread_mutex_lock(&g_mu);
    if (g_log) {
        fprintf(g_log, "\n==== [cloud_tap] marker='%s' va=%p len=%zu ====\n", marker, (const void*)va, wn);
        fwrite(buf,1,wn,g_log);
        fprintf(g_log, "\n==== [cloud_tap] end ====\n");
        fflush(g_log);
    }
    pthread_mutex_unlock(&g_mu);
}

static void scan_once(void) {
    build_tables();
    FILE* m = fopen("/proc/self/maps","r");
    if (!m) return;
    char line[512];
    while (fgets(line, sizeof line, m)) {
        uintptr_t s=0,e=0; char perm[8]={0}; unsigned long long off=0,mmaj=0,mmin=0,ino=0; int n=0;
        if (sscanf(line,"%" SCNxPTR "-%" SCNxPTR " %7s %llx %llx:%llx %llu %n",
                  &s,&e,perm,&off,&mmaj,&mmin,&ino,&n) < 7) continue;
        const char* path = line + n;
        while (*path==' '||*path=='\t') path++;
        size_t plen = strlen(path); if (plen && path[plen-1]=='\n') --plen;
        int anon = (plen==0) || (plen==6 && memcmp(path,"[heap]",6)==0) || (strncmp(path,"[anon",5)==0);
        int readable = (perm[0]=='r'||perm[0]=='R');
        if (!anon || !readable) continue;
        size_t rsz = (size_t)(e - s); if (rsz==0 || rsz >= (512ull<<20)) continue;
        int mfd = open("/proc/self/mem", O_RDONLY);
        if (mfd < 0) continue;
        uint8_t* buf = malloc(rsz);
        if (!buf) continue;
        ssize_t got = pread(mfd, buf, rsz, (off_t)s);
        close(mfd);
        if (got <= 0) { free(buf); continue; }
        size_t gotn = (size_t)got;
        uint8_t* win = malloc(g_win);
        for (size_t i = 0; i < gotn; ++i) {
            unsigned char c = buf[i];
            if (!g_first[c]) continue;
            for (int mi = 0; mi < NM; ++mi) {
                size_t ml = g_mlen[mi];
                if (c == (unsigned char)kMarkers[mi][0] && i+ml <= gotn && memcmp(buf+i, kMarkers[mi], ml)==0) {
                    size_t wn = grab_window(buf, gotn, buf+i, win, g_win);
                    if (wn >= 8) emit(kMarkers[mi], buf+i, win, wn);
                    i += ml-1; break;
                }
            }
        }
        free(buf); free(win);
    }
    fclose(m);
}

static void* scan_loop(void* arg) {
    (void)arg;
    const char* w = getenv("CLOUD_TAP_WIN");
    if (w && *w) { long v = strtol(w,NULL,10); if (v>=512 && v<=(1<<20)) g_win=(size_t)v; }
    while (g_run) { scan_once(); usleep(150000); }
    return NULL;
}

__attribute__((constructor)) static void cloud_tap_ctor(void) {
    if (g_run) return;
    const char* out = getenv("CLOUD_TAP_OUT");
    g_log = fopen(out ? out : "/tmp/cloud_tap.log", "a");
    if (g_log) setbuf(g_log, NULL);
    g_run = 1;
    pthread_create(&g_thr, NULL, scan_loop, NULL);
}

