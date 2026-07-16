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
 * the hardcoded CApath /etc/ssl/certs/ and ignores SSL_CERT_DIR/FILE, so the
 * SSL_set_verify override cannot make it accept the relay cert. Instead, when
 * MITM_CA_DIR is set, file opens under /etc/ssl/certs/ are redirected to that
 * user-owned CA directory (system roots + the relay's MITM CA); see the
 * ca_rewrite hooks below. No system trust store or root access is needed.
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
 * verifies the broker cert against the hardcoded CApath "/etc/ssl/certs/",
 * ignoring SSL_CERT_DIR/SSL_CERT_FILE. The LD_PRELOAD SSL_set_verify override
 * above cannot reach that static copy, so the relay's own cert would be
 * rejected (TLSV1_ALERT_UNKNOWN_CA). Rather than modify the system trust store
 * (root), we transparently redirect reads of the CA directory to a
 * user-owned copy that also holds the relay's MITM CA: when MITM_CA_DIR is set,
 * any path under "/etc/ssl/certs/" is rewritten to "$MITM_CA_DIR/". That dir is
 * a superset of the system roots (built from /etc/ssl/certs) plus the relay CA,
 * so real-host verification is unchanged and only the relay's leg newly
 * validates. Scoped to file opens of that one directory; nothing else moves. */
#define CA_PREFIX "/etc/ssl/certs/"

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

static const char *ca_rewrite(const char *path, char *buf, size_t bufsz) {
  if (!path) return path;
  ca_debug("open", path);
  const char *dir = getenv("MITM_CA_DIR");
  if (!dir || !dir[0]) return path;
  size_t pl = strlen(CA_PREFIX);
  if (strncmp(path, CA_PREFIX, pl) != 0) return path;
  int n = snprintf(buf, bufsz, "%s/%s", dir, path + pl);
  if (n <= 0 || (size_t)n >= bufsz) return path;
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
