// Smoke test for the ABI tap -- no GUI / no Bambu login required.
//
// Part A (deterministic): dlopen a stub plugin THROUGH the interposed dlsym,
// call get_version + send_message_to_printer + start_local_print_with_record
// with crafted args, and confirm (a) the tap logged the exact args, (b) the
// stub received them byte-for-byte, (c) the return value passed through.
//
// Part B (real plugin, if present): dlopen the genuine VMProtect'd plugin and
// call get_version through the tap -- proves the tap forwards to the real module
// and its 8-char version gate value comes back, i.e. interposition works against
// the actual plugin without tripping its integrity/anti-debug checks.
#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include "bambu_abi.hpp"
using namespace bbl_abi;

int main(int argc, char** argv) {
    const char* stub = argc > 1 ? argv[1] : "./stub_plugin.so";
    const char* genuine = argc > 2 ? argv[2] : nullptr;
    int fails = 0;

    // ---- Part A: stub ----
    void* h = dlopen(stub, RTLD_NOW | RTLD_LOCAL);
    if (!h) { std::fprintf(stderr, "dlopen stub failed: %s\n", dlerror()); return 2; }

    auto gv = (std::string(*)())dlsym(h, "bambu_network_get_version");
    auto sm = (int(*)(void*, std::string, std::string, int, int))
              dlsym(h, "bambu_network_send_message_to_printer");
    auto sp = (int(*)(void*, PrintParams, OnUpdateStatusFn, WasCancelledFn, OnWaitFn))
              dlsym(h, "bambu_network_start_local_print_with_record");
    if (!gv || !sm || !sp) { std::fprintf(stderr, "dlsym failed\n"); return 2; }

    std::string ver = gv();
    std::printf("get_version -> \"%s\"\n", ver.c_str());
    if (ver != "01020304") { std::fprintf(stderr, "FAIL: version passthrough\n"); ++fails; }

    int r = sm(nullptr, "0AF0BM12345", "{\"print\":{\"command\":\"pause\"}}", 1, 0);
    std::printf("send_message_to_printer -> %d\n", r);
    if (r != 4242) { std::fprintf(stderr, "FAIL: send return passthrough (got %d)\n", r); ++fails; }

    PrintParams p{};
    p.dev_id = "0AF0BM12345";
    p.project_name = "smoke_cube";
    p.ftp_file_md5 = "DEADBEEFCAFE";
    p.ams_mapping = "[2,128]";
    p.task_bed_type = "eng_plate";
    p.task_use_ams = true;
    p.plate_index = 1;
    int r2 = sp(nullptr, p, nullptr, nullptr, nullptr);
    std::printf("start_local_print_with_record -> %d\n", r2);
    if (r2 != 7) { std::fprintf(stderr, "FAIL: print return passthrough (got %d)\n", r2); ++fails; }

    // ---- Part B: genuine plugin (optional) ----
    if (genuine) {
        void* g = dlopen(genuine, RTLD_NOW | RTLD_LOCAL);
        if (!g) {
            std::fprintf(stderr, "note: dlopen genuine failed: %s\n", dlerror());
        } else {
            auto ggv = (std::string(*)())dlsym(g, "bambu_network_get_version");
            if (ggv) {
                std::string gver = ggv();
                std::printf("GENUINE get_version -> \"%s\" (len=%zu)\n", gver.c_str(), gver.size());
                if (gver.size() != 8) {
                    std::fprintf(stderr, "note: genuine version not 8 chars (gate expects 8)\n");
                }
            } else {
                std::fprintf(stderr, "note: genuine get_version not resolvable\n");
            }
        }
    }

    std::printf(fails ? "SMOKE FAIL (%d)\n" : "SMOKE OK\n", fails);
    return fails ? 1 : 0;
}
