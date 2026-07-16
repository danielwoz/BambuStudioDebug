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
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define SENTINEL 0x7f000002u  /* 127.0.0.2 */

static int (*rc)(int, const struct sockaddr *, socklen_t);

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  static int (*rg)(const char *, const char *, const struct addrinfo *,
                   struct addrinfo **);
  if (!rg)
    rg = (int (*)(const char *, const char *, const struct addrinfo *,
                  struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
  int r = rg(node, service, hints, res);
  if (r == 0 && node && strcasecmp(node, "api.bambulab.com") == 0 && res && *res) {
    for (struct addrinfo *p = *res; p; p = p->ai_next) {
      if (p->ai_family == AF_INET && p->ai_addr)
        ((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr = htonl(SENTINEL);
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
  if (p == 8883) { rd = getenv("REDIRECT_8883"); return (rd && rd[0]) ? atoi(rd) : 0; }
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
