// pin_patch.c — LD_PRELOAD runtime x86 patcher that defeats the genuine Bambu
// network plugin's cloud-MQTT certificate pin, in-process, with no ptrace and
// no on-disk modification of the plugin.
//
// Background
// ----------
// libbambu_networking.so is VMProtect-packed at rest and statically bundles its
// own OpenSSL 3.1.x; the cloud-MQTT TLS + the certificate pin live entirely
// inside it (no interposable dynamic symbol, so an LD_PRELOAD symbol override
// cannot reach them). At runtime the OpenSSL code is unpacked as plain,
// non-virtualized x86 into an anonymous executable region.
//
// Localization (see alert_trace.c + docs) put the pin in OpenSSL's
// tls_process_server_certificate: after `i = ssl_verify_cert_chain(s, sk)` it
// does `if (verify_mode != NONE && i <= 0) SSLfatal(ssl_x509err2alert(
// s->verify_result), CERTIFICATE_VERIFY_FAILED)` which emits the fatal
// unknown_ca alert (record 15 03 03 00 02 02 30) that the relay observes.
//
// The gate is the single conditional branch:
//     mov  %eax,%r13d                 ; i = ssl_verify_cert_chain(...)
//     mov  0x560(%r12),%eax           ; s->verify_mode
//     test %eax,%eax ; je  +9         ; VERIFY_NONE -> skip
//     test %r13d,%r13d
//     jle  <fail: unknown_ca>         ; i <= 0  <== the pin
// NOP-ing that jle lets the verify (and its app pin callback) run fully but
// removes the abort, so the handshake completes and the real cloud MQTT session
// flows through the relay. The verify itself is untouched (all side effects and
// s->verify_result remain), only the fatal-on-failure branch is skipped.
//
// The patch is located by an ASLR-independent signature scan (the 18-byte lead
// sequence is unique in the image), so no fixed offset is baked in. The page is
// briefly made writable via mprotect, the 6-byte jle is overwritten with a
// 6-byte NOP, and permissions are restored. A watch loop re-applies the patch
// if a VMProtect integrity pass were to revert it, and logs any reversion.
//
// A delayed patch (PIN_PATCH_DELAY_MS) clears the plugin's one-shot init-time
// content check, but a SECOND, periodic code-integrity re-scan then detects the
// resident NOP and self-destructs via std::terminate (~13s after the patch; see
// docs/MITM_TAMPER_VERDICT.md). PIN_PATCH_RESTORE_MS restores the original bytes
// that many ms after patching so the re-scan finds pristine code and the process
// survives; the already-established cloud session persists.
//
// Build: gcc -O2 -fPIC -shared -o pin_patch.so pin_patch.c -lpthread
// Use:   LD_PRELOAD=pin_patch.so:mitm_redirect.so REDIRECT_MQTT8883=... <studio>
//        PIN_PATCH_LOG=/tmp/pin_patch.log     (optional)
//        PIN_PATCH_DELAY_MS=60000             (arm after init check)
//        PIN_PATCH_PROCMEM=1                  (write via /proc/self/mem, no mprotect)
//        PIN_PATCH_RESTORE_MS=5000            (restore original bytes -> evade re-scan)
//        PIN_PATCH_RESTORE_ON=<sentinel path> (event-driven restore: put the
//                                              original bytes back as soon as the
//                                              relay signals the cloud session is
//                                              established, i.e. AFTER the TLS
//                                              handshake completed through it)
//        PIN_PATCH_RESTORE_MAX_MS=8000        (hard fallback: restore no later than
//                                              this many ms after patching, so the
//                                              restore always beats the ~13s scan)
//        PIN_PATCH_RESTORE_SETTLE_MS=0         (dwell this long AFTER the sentinel
//                                              before restoring -- lets the session
//                                              settle / a GUI command be driven while
//                                              the pin is still down; capped by MAX_MS)

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>

// 18-byte lead signature ending at `test %r13d,%r13d`, immediately followed by
// the target `jle rel32` (0f 8e ..). Uniquely identifies the pin branch.
static const unsigned char SIG[] = {
    0x41, 0x89, 0xc5,                         // mov  %eax,%r13d
    0x41, 0x8b, 0x84, 0x24, 0x60, 0x05, 0x00, 0x00, // mov 0x560(%r12),%eax
    0x85, 0xc0,                               // test %eax,%eax
    0x74, 0x09,                               // je   +9
    0x45, 0x85, 0xed                          // test %r13d,%r13d
};
#define SIG_LEN (sizeof SIG)
#define JLE_OFF SIG_LEN            // jle starts right after the signature
static const unsigned char NOP6[6] = {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00};

// Arming gate for delayed patching (see PIN_PATCH_DELAY_MS). 1 = patch on sight.
static volatile int g_armed = 1;

// Restore-after-window state (see PIN_PATCH_RESTORE_MS). The cloud-MQTT pin only
// needs to be down DURING the TLS handshake; once the session is established the
// original bytes can be put back so the plugin's periodic code-integrity re-scan
// (which otherwise self-destructs, see docs/MITM_TAMPER_VERDICT.md) finds pristine
// code and the process survives. Set to defeat the second-stage tamper check.
static unsigned char g_orig[6];
static volatile int g_have_orig = 0;
static unsigned char *g_patched_jle = NULL;
static volatile int g_restored = 0;

// Write 6 bytes through /proc/self/mem (no mprotect / no permission change).
static int write6_procmem(unsigned char *dst, const unsigned char *src)
{
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return 0;
    ssize_t w = pwrite(fd, src, 6, (off_t)(uintptr_t)dst);
    close(fd);
    if (w != 6) return 0;
    __builtin___clear_cache((char *)dst, (char *)dst + 6);
    return 1;
}

static const char *logpath(void)
{
    const char *p = getenv("PIN_PATCH_LOG");
    return (p && *p) ? p : "/tmp/pin_patch.log";
}

// Wall-clock milliseconds (monotonic). The restore deadline must be measured in
// real time, not loop iterations: each scan pass memmem's the plugin's ~30 MB
// unpacked span, so a 100 ms nanosleep budget actually elapses much more wall
// time, and iteration-counted timers drift past the ~13 s self-destruct scan.
static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void plog(const char *fmt, ...)
{
    FILE *f = fopen(logpath(), "a");
    if (!f) return;
    time_t t = time(NULL);
    char ts[32];
    strftime(ts, sizeof ts, "%H:%M:%S", localtime(&t));
    fprintf(f, "[%s] ", ts);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// memmem over [buf,buf+n)
static unsigned char *find(unsigned char *buf, size_t n,
                           const unsigned char *pat, size_t pl)
{
    if (n < pl) return NULL;
    for (size_t i = 0; i + pl <= n; i++)
        if (buf[i] == pat[0] && memcmp(buf + i, pat, pl) == 0)
            return buf + i;
    return NULL;
}

static int apply_at(unsigned char *jle)
{
    // Only patch a real `jle rel32` (0f 8e) at the expected spot.
    if (!(jle[0] == 0x0f && jle[1] == 0x8e))
        return 0;
    if (!g_armed)                              // delayed-arm: located, not yet due
        return 0;
    if (getenv("PIN_PATCH_DRYRUN")) {          // locate only, do not modify
        plog("DRYRUN: would patch jle at %p", (void *)jle);
        return 0;
    }
    // Method PROCMEM: write through /proc/self/mem, which bypasses the page's
    // read-only protection WITHOUT an mprotect, so the region's perms are never
    // changed (evades a permission-watch tamper check). No effect on a content
    // hash check.
    if (g_restored)                            // restored window elapsed: leave pristine
        return 0;
    if (!g_have_orig) {                         // remember original bytes for restore
        memcpy(g_orig, jle, 6);
        g_have_orig = 1;
    }
    if (getenv("PIN_PATCH_PROCMEM")) {
        if (!write6_procmem(jle, NOP6)) { plog("procmem pwrite failed"); return 0; }
        g_patched_jle = jle;
        return 1;
    }
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)jle & ~(uintptr_t)(pg - 1);
    uintptr_t end   = ((uintptr_t)jle + 6 + pg - 1) & ~(uintptr_t)(pg - 1);
    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        plog("mprotect RWX failed at %p", jle);
        return 0;
    }
    memcpy(jle, NOP6, 6);
    __builtin___clear_cache((char *)jle, (char *)jle + 6);
    mprotect((void *)start, end - start, PROT_READ | PROT_EXEC);
    g_patched_jle = jle;
    return 1;
}

#define PLUGIN_NAME "libbambu_networking.so"

// Compute the plugin's mapped address span. The identical OpenSSL verify branch
// exists in BOTH Studio's own OpenSSL and the plugin's bundled copy; only the
// plugin's copy must be patched. VMProtect maps the plugin's unpacked (anonymous)
// executable code WITHIN the plugin ELF's own reserved vaddr span, so bounding
// the scan to [lo,hi] of all PLUGIN_NAME mappings isolates the plugin and never
// touches Studio's OpenSSL (mapped elsewhere).
static int plugin_span(uintptr_t *lo_out, uintptr_t *hi_out)
{
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    uintptr_t lo = (uintptr_t)-1, hi = 0;
    while (fgets(line, sizeof line, m)) {
        if (!strstr(line, PLUGIN_NAME)) continue;
        uintptr_t a, b;
        if (sscanf(line, "%lx-%lx", &a, &b) != 2) continue;
        if (a < lo) lo = a;
        if (b > hi) hi = b;
    }
    fclose(m);
    if (hi == 0) return 0;
    *lo_out = lo; *hi_out = hi;
    return 1;
}

// Scan the plugin's executable regions for EVERY occurrence of the pin branch
// and patch each un-patched one.
//   *newly_patched += number of jles patched this pass
//   returns total matches currently present in the plugin span.
static int scan_and_patch(int *newly_patched)
{
    uintptr_t plo, phi;
    if (!plugin_span(&plo, &phi)) return -1;   // plugin not loaded yet

    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    int total = 0;
    while (fgets(line, sizeof line, m)) {
        uintptr_t lo, hi;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3) continue;
        if (perms[2] != 'x' || perms[0] != 'r') continue;   // need r-x
        if (lo < plo || hi > phi) continue;                 // plugin span only
        size_t sz = hi - lo;
        if (sz > (64u << 20)) continue;
        unsigned char *base = (unsigned char *)lo;
        size_t off = 0;
        for (;;) {
            unsigned char *sig = find(base + off, sz - off, SIG, SIG_LEN);
            if (!sig) break;
            unsigned char *jle = sig + JLE_OFF;
            off = (size_t)(sig - base) + 1;
            if (jle + 6 > (unsigned char *)hi) continue;
            if (memcmp(jle, NOP6, 6) == 0) { total++; continue; } // already patched
            if (jle[0] == 0x0f && jle[1] == 0x8e) {
                total++;
                if (apply_at(jle)) {
                    if (newly_patched) (*newly_patched)++;
                    plog("patched plugin pin branch at %p (span %p-%p)",
                         (void *)jle, (void *)plo, (void *)phi);
                }
            }
        }
    }
    fclose(m);
    return total;
}

// When PIN_PATCH_DELAY_MS is set, the branch is located but NOT patched until
// the delay elapses (measured from first-located), so the plugin's one-time
// startup integrity pass can complete before the code is modified. Gated by
// g_armed so scan_and_patch only writes once armed.
static void *worker(void *arg)
{
    (void)arg;
    plog("pin_patch loaded (pid %d); scanning for pin branches", (int)getpid());
    long delay_ms = 0;
    const char *d = getenv("PIN_PATCH_DELAY_MS");
    if (d && *d) { delay_ms = atol(d); g_armed = 0; }
    int located_logged = 0;
    int last_total = -1, total_patched = 0;
    // Continuously patch every occurrence. Studio's own OpenSSL copy is patched
    // immediately; the plugin's bundled copy is patched once it unpacks (later),
    // when a new match appears. The loop also re-applies after any integrity
    // reversion. Runs for the whole session-relevant window (~10 min).
    long restore_ms = 0;
    const char *r = getenv("PIN_PATCH_RESTORE_MS");
    if (r && *r) restore_ms = atol(r);
    // Event-driven restore: put pristine bytes back the moment the relay reports
    // the cloud session is established (sentinel file appears), with a hard
    // upper bound so the restore always precedes the ~13s integrity re-scan.
    const char *restore_on = getenv("PIN_PATCH_RESTORE_ON");
    long restore_max_ms = 8000;
    const char *rmax = getenv("PIN_PATCH_RESTORE_MAX_MS");
    if (rmax && *rmax) restore_max_ms = atol(rmax);
    // Optional dwell AFTER the sentinel appears before restoring, so the freshly
    // established session can fully settle (and, when capturing an interactive
    // command, so the GUI has a moment to act while the pin is still down). Still
    // bounded by restore_max_ms so it never crosses the self-destruct scan.
    long restore_settle_ms = 0;
    const char *rset = getenv("PIN_PATCH_RESTORE_SETTLE_MS");
    if (rset && *rset) restore_settle_ms = atol(rset);
    long patched_at_ms = -1;    // wall time the pin was first applied
    long sentinel_at_ms = -1;   // wall time the sentinel first appeared
    long located_at = -1;
    for (int i = 0; i < 6000; i++) {
        int np = 0;
        int total = scan_and_patch(&np);
        total_patched += np;
        // Restore the original bytes once the post-patch window elapses, so the
        // plugin's periodic integrity re-scan finds pristine code and does not
        // self-destruct. After restoring, patching is disabled (g_restored).
        if ((restore_ms > 0 || (restore_on && *restore_on)) &&
            !g_restored && g_have_orig && g_patched_jle) {
            if (patched_at_ms < 0) patched_at_ms = now_ms();
            long elapsed_ms = now_ms() - patched_at_ms;
            int do_restore = 0;
            const char *why = NULL;
            if (restore_on && *restore_on) {
                // Keep the pin DOWN through any pre-establishment retry (the plugin
                // may have already failed once with unknown_ca and will retry); only
                // restore once the handshake actually completed (sentinel present),
                // then dwell restore_settle_ms so the session settles -- but never
                // past the hard max, which is guaranteed to precede the ~13s scan.
                if (sentinel_at_ms < 0 && access(restore_on, F_OK) == 0)
                    sentinel_at_ms = now_ms();
                if (sentinel_at_ms >= 0 && now_ms() - sentinel_at_ms >= restore_settle_ms) {
                    do_restore = 1; why = "sentinel";
                } else if (elapsed_ms >= restore_max_ms) {
                    do_restore = 1; why = "max-wait";
                }
            } else if (elapsed_ms >= restore_ms) {
                do_restore = 1; why = "timer";
            }
            if (do_restore) {
                if (write6_procmem(g_patched_jle, g_orig)) {
                    g_restored = 1;
                    plog("RESTORED original bytes at %p after %ld ms (trigger=%s, tamper-scan evasion)",
                         (void *)g_patched_jle, elapsed_ms, why);
                } else {
                    plog("RESTORE failed at %p", (void *)g_patched_jle);
                }
            }
        }
        if (!g_armed) {
            if (total >= 1 && located_at < 0) {
                located_at = i;
                if (!located_logged) {
                    plog("branch located; arming in %ld ms", delay_ms);
                    located_logged = 1;
                }
            }
            if (located_at >= 0 && (long)(i - located_at) * 100 >= delay_ms) {
                g_armed = 1;
                plog("ARMED after delay; patching now");
            }
        }
        if (total != last_total) {
            plog("matches=%d newly_patched_this_pass=%d cumulative=%d",
                 total, np, total_patched);
            last_total = total;
        } else if (np) {
            plog("RE-PATCHED %d after reversion (cumulative=%d)", np, total_patched);
        }
        struct timespec ts = {0, 100 * 1000 * 1000}; // 100ms
        nanosleep(&ts, NULL);
    }
    plog("watch loop done (cumulative_patched=%d)", total_patched);
    return NULL;
}

__attribute__((constructor))
static void init(void)
{
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) == 0)
        pthread_detach(t);
}
