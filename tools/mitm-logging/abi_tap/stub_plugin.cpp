// Minimal stand-in for the genuine plugin, used by the smoke test to prove the
// tap logs args AND forwards them faithfully (return value + args passed through)
// deterministically, without depending on the VMProtect'd plugin's behaviour.
// It exports the same bambu_network_* symbols the tap wraps and records what it
// received so the test can assert the tap forwarded byte-for-byte.
#include <string>
#include <fstream>
#include <cstdlib>
#include "bambu_abi.hpp"
using namespace bbl_abi;

static void rec(const std::string& line) {
    const char* p = getenv("STUB_RECORD");
    std::ofstream f(p && p[0] ? p : "stub_record.txt", std::ios::app);
    f << line << "\n";
}

extern "C" {

std::string bambu_network_get_version() { return "01020304"; }  // 8-char gate value

int bambu_network_send_message_to_printer(void*, std::string dev_id, std::string json_str,
                                          int qos, int flag) {
    rec("send_message_to_printer|" + dev_id + "|" + json_str + "|" +
        std::to_string(qos) + "|" + std::to_string(flag));
    return 4242;   // distinctive return to prove passthrough
}

int bambu_network_start_local_print_with_record(void*, PrintParams p, OnUpdateStatusFn,
                                                WasCancelledFn, OnWaitFn) {
    rec("start_local_print_with_record|" + p.dev_id + "|" + p.project_name + "|" +
        p.ftp_file_md5 + "|" + p.ams_mapping + "|bed=" + p.task_bed_type +
        "|ams=" + (p.task_use_ams ? "1" : "0"));
    return 7;
}

// Inbound report path: the host registers a callback; whatever the stub stores
// here is the WRAPPER the tap handed it (not the host's real callback). A later
// stub_push_report() call simulates the plugin's MQTT thread delivering a report.
static OnMessageFn g_stored_cb;
int bambu_network_set_on_message_fn(void*, OnMessageFn fn) {
    g_stored_cb = fn;
    rec("set_on_message_fn|stored");
    return 0;
}
void stub_push_report(std::string dev_id, std::string msg) {
    if (g_stored_cb) g_stored_cb(dev_id, msg);
}

} // extern "C"
