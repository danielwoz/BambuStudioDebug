// Headless validation probe: drive the GENUINE plugin through the ABI tap and
// capture a real bambu_network_* boundary WITHOUT BambuStudio.
//
// It replicates the minimum of Studio's init the genuine plugin needs
// (callbacks + cert file + SSDP discovery so it snapshots the printer cert),
// connects to a LAN printer, and sends ONE command -- default a READ-ONLY
// pushall (status request), which is safe. The tap logs the genuine
// send_message_to_printer call; import_flow.py --flow device_command turns it
// into an abi-captured fixture.
//
// SAFETY: only pass a non-print command. Do NOT use this to send print.* to a
// real printer -- that starts a job. Keep the obn_send_command stop kill-switch
// armed (see abi_tap/README.md).
//
// Build/run: tools/mitm-logging/abi_tap/probe_genuine.sh
#include <dlfcn.h>
#include <string>
#include <functional>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

using OnLocalConnectedFn = std::function<void(int, std::string, std::string)>;
using OnMessageFn        = std::function<void(std::string, std::string)>;
using OnPrinterConnFn    = std::function<void(std::string)>;
using QueueOnMainFn      = std::function<void(std::function<void()>)>;
using OnMsgArrivedFn     = std::function<void(std::string)>;

static void* R(void* h, const char* n) { void* p = dlsym(h, n);
    if (!p) std::fprintf(stderr, "  (missing %s)\n", n); return p; }

int main(int argc, char** argv) {
    if (argc < 6) {
        std::fprintf(stderr, "usage: %s <genuine.so> <config_dir> <dev_id> <ip> <access_code> "
                             "[command_json]\n", argv[0]);
        return 2;
    }
    const char* so = argv[1]; const char* cfg = argv[2]; const char* dev = argv[3];
    const char* ip = argv[4]; const char* code = argv[5];
    std::string cmd = argc > 6 ? argv[6]
                     : "{\"pushing\":{\"sequence_id\":\"0\",\"command\":\"pushall\"}}";

    void* h = dlopen(so, RTLD_NOW | RTLD_LOCAL);
    if (!h) { std::fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    auto gv  = (std::string(*)())R(h, "bambu_network_get_version");
    auto ca  = (void*(*)(std::string))R(h, "bambu_network_create_agent");
    auto scd = (int(*)(void*, std::string))R(h, "bambu_network_set_config_dir");
    auto il  = (int(*)(void*))R(h, "bambu_network_init_log");
    auto st  = (int(*)(void*))R(h, "bambu_network_start");
    auto scf = (int(*)(void*, std::string, std::string))R(h, "bambu_network_set_cert_file");
    auto sdisc = (bool(*)(void*, bool, bool))R(h, "bambu_network_start_discovery");
    auto ssdpfn= (int(*)(void*, OnMsgArrivedFn))R(h, "bambu_network_set_on_ssdp_msg_fn");
    auto qom = (int(*)(void*, QueueOnMainFn))R(h, "bambu_network_set_queue_on_main_fn");
    auto solc= (int(*)(void*, OnLocalConnectedFn))R(h, "bambu_network_set_on_local_connect_fn");
    auto solm= (int(*)(void*, OnMessageFn))R(h, "bambu_network_set_on_local_message_fn");
    auto sopc= (int(*)(void*, OnPrinterConnFn))R(h, "bambu_network_set_on_printer_connected_fn");
    auto som = (int(*)(void*, OnMessageFn))R(h, "bambu_network_set_on_message_fn");
    auto cp  = (int(*)(void*, std::string, std::string, std::string, std::string, bool))
               R(h, "bambu_network_connect_printer");
    auto smp = (int(*)(void*, std::string, std::string, int, int))
               R(h, "bambu_network_send_message_to_printer");
    auto dp  = (int(*)(void*))R(h, "bambu_network_disconnect_printer");
    if (!gv || !ca || !scd || !cp || !smp) { std::fprintf(stderr, "missing core symbols\n"); return 2; }

    std::fprintf(stderr, "get_version=%s\n", gv().c_str());
    void* a = ca(std::string("/tmp"));
    scd(a, std::string(cfg));
    if (il) il(a);
    if (qom) qom(a, [](std::function<void()> f){ if (f) f(); });
    if (solc) solc(a, [](int, std::string, std::string){});
    if (solm) solm(a, [](std::string, std::string){});
    if (sopc) sopc(a, [](std::string){});
    if (som)  som(a, [](std::string, std::string){});
    if (scf)  scf(a, std::string("/etc/ssl/certs"), std::string("ca-certificates.crt"));
    if (ssdpfn) ssdpfn(a, [](std::string){});
    if (st) st(a);
    if (sdisc) { sdisc(a, true, false); for (int i = 0; i < 70; ++i) usleep(100000); }

    int rc = cp(a, std::string(dev), std::string(ip), std::string("bblp"), std::string(code), true);
    std::fprintf(stderr, "connect_printer rc=%d\n", rc);
    for (int i = 0; i < 40; ++i) usleep(100000);

    int sr = smp(a, std::string(dev), cmd, 1, 0);
    std::fprintf(stderr, "send_message_to_printer rc=%d\n", sr);
    usleep(800000);
    if (dp) dp(a);
    usleep(300000);
    // The plugin spawns worker threads; skip its global destructors (they can
    // throw during teardown) -- the tap has already flushed the capture.
    std::fflush(nullptr);
    _exit(sr == 0 ? 0 : 1);
}
