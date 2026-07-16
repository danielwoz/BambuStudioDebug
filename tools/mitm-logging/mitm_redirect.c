/* Transport-level MITM redirect for the GENUINE Bambu network plugin.
 *
 * LD_PRELOAD this into BambuStudio so the closed-source network plugin's TLS
 * connections to api.bambulab.com are transparently steered through a local
 * mitmdump, while every other host still reaches the real internet. This is the
 * capture core of BambuStudioDebug: it records what the GENUINE plugin puts on
 * the wire, which is the golden trace the open-bamboo-networking harness
 * reproduces.
 *
 * Mechanism (hostname-scoped so login/webview TLS is untouched):
 *   1. getaddrinfo() rewrites ONLY api.bambulab.com to a loopback sentinel
 *      (127.0.0.2). bambulab.com / makerworld.com (the sign-in webview, which
 *      shares Cloudflare IPs with the API) resolve normally and reach the real
 *      server with a real certificate, so the login webview's TLS succeeds.
 *   2. connect() sends the sentinel's :443 to 127.0.0.1:$REDIRECT_443, where a
 *      mitmdump reverse-proxy for https://api.bambulab.com is listening.
 *   3. SSL_CTX_set_verify / SSL_set_verify are forced to VERIFY_NONE so the
 *      plugin's libcurl/OpenSSL leg accepts mitmproxy's interception cert.
 *      (Alternatively the mitmproxy CA can be added to the plugin's CA bundle;
 *      disabling verification on the redirected leg only is simpler and equally
 *      scoped. The GnuTLS webview is unaffected -- it talks to the real server.)
 *
 * IPv6 for the API is black-holed to ::1 so the client falls back to the v4
 * sentinel rather than reaching the real API over v6 and bypassing capture.
 *
 * Cloud MQTT (long-lived device session): when REDIRECT_MQTT8883 is set, the
 * region cloud broker (any host ending mqtt.bambulab.com, e.g.
 * us.mqtt.bambulab.com) is rewritten at getaddrinfo to a second loopback
 * sentinel (127.0.0.3); connect() then steers that sentinel's :8883 to the
 * local cloud MQTT relay (tools/mitm-logging/mqtt_cloud_relay.py), which
 * TLS-terminates, logs commands + status reports both directions, and forwards
 * the raw session to the real broker so the live device link keeps working.
 * The LAN :8883 rule (REDIRECT_8883, printer IP) is unchanged and separate.
 *
 * The plugin's MQTT TLS uses a statically-linked OpenSSL that verifies against
 * its compiled-in CApath/CAINFO (the build tree's ".../usr/local/certs/" dirs +
 * the /etc/ssl/certs bundle), ignoring SSL_CERT_DIR/FILE and the system trust
 * store, so the SSL_set_verify override cannot make it accept the relay cert.
 * Instead, when MITM_CA_DIR is set, reads of CA-store files (hashed <hash>.N
 * certs / ca-certificates.crt) under any ".../certs/" or /etc/ssl/certs dir are
 * redirected to that user-owned CA directory (system roots + the relay's MITM
 * CA); see the ca_rewrite hooks below. No system trust store or root needed.
 *
 * Build: tools/mitm-logging/build_redirect.sh
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dlfcn.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define SENTINEL       0x7f000002u  /* 127.0.0.2 -- api.bambulab.com (REST) */
#define CLOUD_MQTT_SENT 0x7f000003u  /* 127.0.0.3 -- *.mqtt.bambulab.com (cloud broker) */

static int (*rc)(int, const struct sockaddr *, socklen_t);

/* True for the region cloud-MQTT broker hosts, e.g. us.mqtt.bambulab.com /
 * cn.mqtt.bambulab.com. Matched by the "mqtt.bambulab.com" suffix (the region
 * host is whatever the login/profile response carries) so a new region is
 * covered without a code change. Gated on REDIRECT_MQTT8883 so the sentinel
 * rewrite only happens when a cloud MQTT relay is actually listening. */
static int is_cloud_mqtt_host(const char *node) {
  if (!node) return 0;
  const char *rd = getenv("REDIRECT_MQTT8883");
  if (!rd || !rd[0]) return 0;
  size_t nl = strlen(node);
  const char *suf = "mqtt.bambulab.com";
  size_t sl = strlen(suf);
  if (nl < sl) return 0;
  return strcasecmp(node + (nl - sl), suf) == 0;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  static int (*rg)(const char *, const char *, const struct addrinfo *,
                   struct addrinfo **);
  if (!rg)
    rg = (int (*)(const char *, const char *, const struct addrinfo *,
                  struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
  int r = rg(node, service, hints, res);
  if (r != 0 || !node || !res || !*res)
    return r;
  unsigned int rewrite = 0;
  if (strcasecmp(node, "api.bambulab.com") == 0)
    rewrite = SENTINEL;
  else if (is_cloud_mqtt_host(node))
    rewrite = CLOUD_MQTT_SENT;
  if (rewrite) {
    for (struct addrinfo *p = *res; p; p = p->ai_next) {
      if (p->ai_family == AF_INET && p->ai_addr)
        ((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr = htonl(rewrite);
      else if (p->ai_family == AF_INET6 && p->ai_addr) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)p->ai_addr;
        memset(&s6->sin6_addr, 0, sizeof s6->sin6_addr);
        s6->sin6_addr.s6_addr[15] = 1;
      }
    }
  }
  return r;
}

/* Steer a matched destination port to 127.0.0.1:<relay> if the paired env var
 * is set. :443 (cloud REST) is gated on the api.bambulab.com sentinel; the LAN
 * transports (:8883 MQTT, :990 FTPS, :6000 native CTRL) go to a printer IP, so
 * they are steered whenever their relay env is set (target one printer at a
 * time -- the relay is configured with that printer's IP as its upstream). */
static int redirect_port(unsigned short p, unsigned int h) {
  const char *rd;
  if (p == 443) {
    rd = getenv("REDIRECT_443");
    return (rd && rd[0] && h == SENTINEL) ? atoi(rd) : 0;
  }
  if (p == 8883) {
    /* Cloud broker leg (sentinel-scoped) takes priority over the LAN :8883
     * rule so both env vars may be set without the LAN relay swallowing a
     * cloud connection. */
    if (h == CLOUD_MQTT_SENT) {
      rd = getenv("REDIRECT_MQTT8883");
      return (rd && rd[0]) ? atoi(rd) : 0;
    }
    rd = getenv("REDIRECT_8883");
    return (rd && rd[0]) ? atoi(rd) : 0;
  }
  if (p == 990)  { rd = getenv("REDIRECT_990");  return (rd && rd[0]) ? atoi(rd) : 0; }
  if (p == 6000) { rd = getenv("REDIRECT_6000"); return (rd && rd[0]) ? atoi(rd) : 0; }
  return 0;
}

int connect(int fd, const struct sockaddr *a, socklen_t l) {
  if (!rc)
    rc = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT,
                                                                 "connect");
  if (a && a->sa_family == AF_INET) {
    const struct sockaddr_in *s = (const struct sockaddr_in *)a;
    unsigned int h = ntohl(s->sin_addr.s_addr);
    unsigned short p = ntohs(s->sin_port);
    int relay = redirect_port(p, h);
    if (relay) {
      struct sockaddr_in b;
      memcpy(&b, s, sizeof b);
      b.sin_addr.s_addr = htonl(0x7f000001u); /* 127.0.0.1 */
      b.sin_port = htons((unsigned short)relay);
      return rc(fd, (const struct sockaddr *)&b, l);
    }
  }
  return rc(fd, a, l);
}

void SSL_CTX_set_verify(SSL_CTX *c, int m, SSL_verify_cb cb) {
  typedef void (*f)(SSL_CTX *, int, SSL_verify_cb);
  f r = (f)dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
  if (r) r(c, SSL_VERIFY_NONE, NULL);
}
void SSL_set_verify(SSL *s, int m, SSL_verify_cb cb) {
  typedef void (*f)(SSL *, int, SSL_verify_cb);
  f r = (f)dlsym(RTLD_NEXT, "SSL_set_verify");
  if (r) r(s, SSL_VERIFY_NONE, NULL);
}

/* CA-path redirect for the cloud MQTT relay leg.
 *
 * The genuine plugin's MQTT/cloud TLS uses a statically-linked OpenSSL that
 * verifies the broker cert against its *compiled-in* CApath and CAINFO bundle,
 * ignoring SSL_CERT_DIR/SSL_CERT_FILE and the system trust store. On the
 * capture host those baked paths are the plugin's and Studio's OpenSSL build
 * trees, e.g. "/home/<builder>/.../usr/local/certs/" and
 * ".../deps/build/destdir/usr/local/certs/", plus the "/etc/ssl/certs/" bundle;
 * OpenSSL does hashed <subject-hash>.N lookups inside those dirs. The
 * SSL_set_verify override above cannot reach the static copy, so the relay cert
 * would be rejected (TLSV1_ALERT_UNKNOWN_CA). Rather than touch the system
 * trust store (root), we transparently redirect the plugin's CA-file reads to a
 * user-owned dir that also holds the relay's MITM CA: when MITM_CA_DIR is set,
 * a read of a CA store entry (a "<8hex>.N" hashed cert, or "ca-certificates.crt")
 * under any ".../certs/" or "/etc/ssl/certs/" directory is remapped to
 * "$MITM_CA_DIR/<basename>". That dir is a superset of the system roots plus the
 * relay CA, so real-host verification is unchanged and the relay leg newly
 * validates. Scoped to CA-store files only (openssl.cnf etc. pass through).
 *
 * NOTE: this makes Studio's own OpenSSL trust the relay CA, but does NOT defeat
 * the genuine Bambu plugin's CLOUD MQTT leg: that channel is certificate-pinned
 * (BambuSource carries an embedded CA, no plaintext cert in the binary) and
 * never consults any on-disk CA store, so it rejects the relay leaf regardless
 * (see docs/MITM_LOGGING.md). The redirect remains useful for static-OpenSSL
 * plugins whose CA store is an on-disk file rather than pinned. */

static void ca_debug(const char *fn, const char *path) {
  const char *dbg = getenv("MITM_CA_DEBUG");
  if (!dbg || !dbg[0] || !path) return;
  if (!strstr(path, "ssl") && !strstr(path, "cert") &&
      !strstr(path, ".pem") && !strstr(path, ".crt") && !strstr(path, "CA"))
    return;
  FILE *(*rf)(const char *, const char *) =
      (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");
  FILE *f = rf(dbg, "a");
  if (f) { fprintf(f, "%s\t%s\n", fn, path); fclose(f); }
}

/* basename is an OpenSSL CA-store entry: a "<8+ hex>.<digits>" hashed cert
 * (CApath), the ca-certificates bundle, or the default CAINFO bundle
 * "cert.pem" (OPENSSLDIR/cert.pem, what the plugin's OpenSSL loads whole). */
static int is_ca_store_file(const char *base) {
  if (strcmp(base, "ca-certificates.crt") == 0) return 1;
  if (strcmp(base, "cert.pem") == 0) return 1;
  const char *dot = strrchr(base, '.');
  if (!dot || dot == base) return 0;
  for (const char *p = base; p < dot; p++)
    if (!( (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
           (*p >= 'A' && *p <= 'F') )) return 0;
  if ((dot - base) < 4) return 0;           /* require a real hash, not "x.0" */
  for (const char *p = dot + 1; *p; p++)
    if (*p < '0' || *p > '9') return 0;      /* suffix is all digits */
  return dot[1] != '\0';
}

/* True if the file sits in an OpenSSL CApath / bundle location: the system
 * /etc/ssl tree, any ".../certs/" hashed dir, or an OpenSSLDIR ("/usr/local"
 * or ".../ssl/") holding the cert.pem/ca bundle. */
static int in_ca_dir(const char *path, const char *base) {
  size_t plen = (size_t)(base - path);       /* dir part incl. trailing '/' */
  if (strncmp(path, "/etc/ssl/", 9) == 0) return 1;
  if (plen >= 7 && strncmp(base - 7, "/certs/", 7) == 0) return 1;
  if (plen >= 5 && strncmp(base - 5, "/ssl/", 5) == 0) return 1;
  if (strstr(path, "/usr/local/")) return 1;
  return 0;
}

/* Redirect a CApath *directory* open (opendir enumeration) to MITM_CA_DIR. */
static const char *ca_dir_rewrite(const char *path, char *buf, size_t bufsz) {
  if (!path) return path;
  const char *dir = getenv("MITM_CA_DIR");
  if (!dir || !dir[0]) return path;
  size_t n = strlen(path);
  int is_certs = (n >= 6 && strcmp(path + n - 6, "/certs") == 0) ||
                 (n >= 7 && strcmp(path + n - 7, "/certs/") == 0) ||
                 strcmp(path, "/etc/ssl/certs") == 0;
  if (!is_certs) return path;
  ca_debug("REMAPDIR", dir);
  return dir;
}

static const char *ca_rewrite(const char *path, char *buf, size_t bufsz) {
  if (!path) return path;
  ca_debug("open", path);
  const char *dir = getenv("MITM_CA_DIR");
  if (!dir || !dir[0]) return path;
  const char *base = strrchr(path, '/');
  if (!base) return path;
  base += 1;
  if (!in_ca_dir(path, base) || !is_ca_store_file(base)) return path;
  int n = snprintf(buf, bufsz, "%s/%s", dir, base);
  if (n <= 0 || (size_t)n >= bufsz) return path;
  ca_debug("REMAP", buf);
  return buf;
}

FILE *fopen(const char *path, const char *mode) {
  static FILE *(*r)(const char *, const char *);
  if (!r) r = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");
  char buf[4096];
  return r(ca_rewrite(path, buf, sizeof buf), mode);
}
FILE *fopen64(const char *path, const char *mode) {
  static FILE *(*r)(const char *, const char *);
  if (!r) r = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen64");
  if (!r) return fopen(path, mode);
  char buf[4096];
  return r(ca_rewrite(path, buf, sizeof buf), mode);
}
int open(const char *path, int flags, ...) {
  static int (*r)(const char *, int, ...);
  if (!r) r = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
  }
  char buf[4096];
  return r(ca_rewrite(path, buf, sizeof buf), flags, mode);
}
int open64(const char *path, int flags, ...) {
  static int (*r)(const char *, int, ...);
  if (!r) r = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
  }
  char buf[4096];
  if (!r) return open(path, flags, mode);
  return r(ca_rewrite(path, buf, sizeof buf), flags, mode);
}
int openat(int dirfd, const char *path, int flags, ...) {
  static int (*r)(int, const char *, int, ...);
  if (!r) r = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
  }
  char buf[4096];
  return r(dirfd, ca_rewrite(path, buf, sizeof buf), flags, mode);
}

/* OpenSSL's by_dir CApath lookup stat()s each candidate <hash>.N before
 * loading it, so the stat family must follow the same redirect or the hashed
 * lookup finds nothing. Both the modern direct symbols and the older glibc
 * __xstat ABI (what the plugin's toolchain emitted) are covered. */
#define CA_STAT_BODY(SYM, TYPE)                                               \
  static int (*r)(const char *, TYPE *);                                      \
  if (!r) r = (int (*)(const char *, TYPE *))dlsym(RTLD_NEXT, SYM);           \
  char buf[4096];                                                            \
  return r(ca_rewrite(path, buf, sizeof buf), st);

int stat(const char *path, struct stat *st)   { CA_STAT_BODY("stat", struct stat) }
int lstat(const char *path, struct stat *st)  { CA_STAT_BODY("lstat", struct stat) }
int stat64(const char *path, struct stat64 *st)  { CA_STAT_BODY("stat64", struct stat64) }
int lstat64(const char *path, struct stat64 *st) { CA_STAT_BODY("lstat64", struct stat64) }

int __xstat(int ver, const char *path, struct stat *st) {
  static int (*r)(int, const char *, struct stat *);
  if (!r) r = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__xstat");
  char buf[4096];
  return r(ver, ca_rewrite(path, buf, sizeof buf), st);
}
int __lxstat(int ver, const char *path, struct stat *st) {
  static int (*r)(int, const char *, struct stat *);
  if (!r) r = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__lxstat");
  char buf[4096];
  return r(ver, ca_rewrite(path, buf, sizeof buf), st);
}
int __xstat64(int ver, const char *path, struct stat64 *st) {
  static int (*r)(int, const char *, struct stat64 *);
  if (!r) r = (int (*)(int, const char *, struct stat64 *))dlsym(RTLD_NEXT, "__xstat64");
  char buf[4096];
  return r(ver, ca_rewrite(path, buf, sizeof buf), st);
}
int __lxstat64(int ver, const char *path, struct stat64 *st) {
  static int (*r)(int, const char *, struct stat64 *);
  if (!r) r = (int (*)(int, const char *, struct stat64 *))dlsym(RTLD_NEXT, "__lxstat64");
  char buf[4096];
  return r(ver, ca_rewrite(path, buf, sizeof buf), st);
}
int access(const char *path, int amode) {
  static int (*r)(const char *, int);
  if (!r) r = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
  char buf[4096];
  return r(ca_rewrite(path, buf, sizeof buf), amode);
}

/* OpenSSL's by_dir CApath may enumerate the directory; redirect the whole
 * CApath dir to MITM_CA_DIR so the relay CA is among the entries. */
DIR *opendir(const char *path) {
  static DIR *(*r)(const char *);
  if (!r) r = (DIR *(*)(const char *))dlsym(RTLD_NEXT, "opendir");
  char buf[4096];
  return r(ca_dir_rewrite(path, buf, sizeof buf));
}
