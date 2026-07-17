// conn_origin_trace.c — LD_PRELOAD diagnostic that identifies WHICH loaded
// module initiates a given outbound TCP connection, by capturing an execution
// backtrace inside the connect() call. No ptrace: it interposes libc connect()
// and walks the caller frames with backtrace()/backtrace_symbols(), so each
// frame resolves (via dladdr) to the .so that made the call.
//
// Used to determine which library owns the cloud MQTT (:8883) TLS session. The
// backtrace on the connect() to the cloud-broker sentinel resolves entirely to
// libbambu_networking.so — proving the cloud MQTT client (and therefore its
// certificate-pinning TLS) lives in the network plugin's own bundled OpenSSL,
// not in libBambuSource.so.
//
// Build:  gcc -O2 -fPIC -shared -rdynamic -o conn_origin_trace.so conn_origin_trace.c -ldl
// Use:    LD_PRELOAD=conn_origin_trace.so:...  CONN_TRACE_PORTS=8883,9883  CONN_TRACE_OUT=/tmp/conn_bt.log  <program>
//         (defaults: ports 8883,9883; out /tmp/conn_origin_trace.log)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t);

static int port_matches(int port)
{
    const char *list = getenv("CONN_TRACE_PORTS");
    if (!list || !*list)
        return port == 8883 || port == 9883;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", list);
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ","))
        if (atoi(tok) == port)
            return 1;
    return 0;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        int port = ntohs(in->sin_port);
        if (port_matches(port)) {
            const char *out = getenv("CONN_TRACE_OUT");
            FILE *f = fopen(out && *out ? out : "/tmp/conn_origin_trace.log", "a");
            if (f) {
                char ip[64];
                inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
                fprintf(f, "=== connect fd=%d %s:%d ===\n", fd, ip, port);
                void *bt[32];
                int n = backtrace(bt, 32);
                char **sym = backtrace_symbols(bt, n);
                for (int i = 0; i < n; i++)
                    fprintf(f, "  %s\n", sym ? sym[i] : "?");
                free(sym);
                fclose(f);
            }
        }
    }
    return real_connect(fd, addr, len);
}
