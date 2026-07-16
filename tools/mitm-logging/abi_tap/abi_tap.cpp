// ABI input-tap for the GENUINE Bambu network plugin (tamper-safe design).
//
// BambuStudio's NetworkAgent dlopen()s the genuine libbambu_networking.so and
// resolves each bambu_network_* entry point with dlsym(). This shim is
// LD_PRELOADed into BambuStudio and interposes dlsym ONLY: when the host asks
// for a wrapped input-bearing symbol, we return a wrapper that
//   1. logs the call's arguments (NDJSON), then
//   2. tail-calls the REAL genuine symbol and returns its value unchanged.
//
// The genuine .so file is never modified and never ptraced, so the plugin's
// VMProtect anti-debug and BambuStudio's module-cert/version/debug gates all
// operate on the untouched genuine module and pass. The only observable
// difference is that a wrapped call's return address is inside this tap.
//
// Captured inputs are the ground-truth `driver` block for the OBN wire
// fixtures (import_flow.py merges an abi log with the wire log). Args may carry
// tokens / passwords / access codes: they are scrubbed here before logging, and
// import_flow.py anonymizes again on export.
//
// Build: tools/mitm-logging/abi_tap/build_tap.sh
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <regex>
#include <string>
#include "bambu_abi.hpp"

using namespace bbl_abi;

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------
namespace {
std::mutex g_mu;
FILE* g_fp = nullptr;

FILE* logfp() {
    if (!g_fp) {
        const char* p = getenv("ABI_TAP_LOG");
        g_fp = fopen(p && p[0] ? p : "abi_tap.jsonl", "a");
        if (g_fp) setvbuf(g_fp, nullptr, _IOLBF, 0);
    }
    return g_fp;
}

std::string jesc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += (char)c;
        }
    }
    return o;
}

// Redact obvious secrets from a value string (JSON commands / login blobs).
std::string scrub(const std::string& v) {
    static const std::regex kv(
        "(\"(?:access[_]?token|refresh[_]?token|token|password|passwd|"
        "access[_]?code|secret|auth|bearer|uid|user[_]?id)\"\\s*:\\s*\")[^\"]*(\")",
        std::regex::icase);
    std::string out = std::regex_replace(v, kv, "$1<redacted>$2");
    // bare "Bearer <token>" occurrences
    static const std::regex bearer("Bearer\\s+[A-Za-z0-9._\\-]+", std::regex::icase);
    out = std::regex_replace(out, bearer, "Bearer <redacted>");
    return out;
}

struct Field { const char* k; std::string v; bool quoted; };

void emit(const char* fn, std::initializer_list<Field> fields) {
    FILE* f = logfp();
    if (!f) return;
    std::string line = "{\"proto\":\"abi\",\"fn\":\"";
    line += fn;
    line += "\",\"ts\":";
    line += std::to_string((long long)time(nullptr));
    line += ",\"args\":{";
    bool first = true;
    for (const auto& fd : fields) {
        if (!first) line += ",";
        first = false;
        line += "\"";
        line += fd.k;
        line += "\":";
        if (fd.quoted) { line += "\""; line += jesc(fd.v); line += "\""; }
        else line += fd.v;
    }
    line += "}}\n";
    std::lock_guard<std::mutex> lk(g_mu);
    fputs(line.c_str(), f);
}

Field S(const char* k, const std::string& v) { return {k, v, true}; }
Field Sr(const char* k, const std::string& v) { return {k, scrub(v), true}; }
Field I(const char* k, long long v) { return {k, std::to_string(v), false}; }
Field B(const char* k, bool v) { return {k, v ? "true" : "false", false}; }

// Serialize the whole PrintParams struct as one JSON object value.
std::string pp_json(const PrintParams& p) {
    std::string o = "{";
    auto add = [&](const char* k, const std::string& v, bool q, bool& first) {
        if (!first) o += ",";
        first = false;
        o += "\""; o += k; o += "\":";
        if (q) { o += "\""; o += jesc(v); o += "\""; } else o += v;
    };
    bool f = true;
    add("dev_id", p.dev_id, true, f);
    add("task_name", p.task_name, true, f);
    add("project_name", p.project_name, true, f);
    add("preset_name", p.preset_name, true, f);
    add("filename", p.filename, true, f);
    add("config_filename", p.config_filename, true, f);
    add("plate_index", std::to_string(p.plate_index), false, f);
    add("ftp_folder", p.ftp_folder, true, f);
    add("ftp_file", p.ftp_file, true, f);
    add("ftp_file_md5", p.ftp_file_md5, true, f);
    add("nozzle_mapping", p.nozzle_mapping, true, f);
    add("ams_mapping", p.ams_mapping, true, f);
    add("ams_mapping2", p.ams_mapping2, true, f);
    add("ams_mapping_info", p.ams_mapping_info, true, f);
    add("nozzles_info", p.nozzles_info, true, f);
    add("connection_type", p.connection_type, true, f);
    add("comments", p.comments, true, f);
    add("origin_profile_id", std::to_string(p.origin_profile_id), false, f);
    add("stl_design_id", std::to_string(p.stl_design_id), false, f);
    add("origin_model_id", p.origin_model_id, true, f);
    add("print_type", p.print_type, true, f);
    add("dst_file", p.dst_file, true, f);
    add("dev_name", p.dev_name, true, f);
    add("dev_ip", p.dev_ip, true, f);
    add("use_ssl_for_ftp", p.use_ssl_for_ftp ? "true" : "false", false, f);
    add("use_ssl_for_mqtt", p.use_ssl_for_mqtt ? "true" : "false", false, f);
    add("username", p.username, true, f);
    add("password", "<redacted>", true, f);
    add("task_bed_leveling", p.task_bed_leveling ? "true" : "false", false, f);
    add("task_flow_cali", p.task_flow_cali ? "true" : "false", false, f);
    add("task_vibration_cali", p.task_vibration_cali ? "true" : "false", false, f);
    add("task_layer_inspect", p.task_layer_inspect ? "true" : "false", false, f);
    add("task_record_timelapse", p.task_record_timelapse ? "true" : "false", false, f);
    add("task_timelapse_use_internal", p.task_timelapse_use_internal ? "true" : "false", false, f);
    add("task_use_ams", p.task_use_ams ? "true" : "false", false, f);
    add("task_bed_type", p.task_bed_type, true, f);
    add("extra_options", p.extra_options, true, f);
    add("auto_bed_leveling", std::to_string(p.auto_bed_leveling), false, f);
    add("auto_flow_cali", std::to_string(p.auto_flow_cali), false, f);
    add("auto_offset_cali", std::to_string(p.auto_offset_cali), false, f);
    add("extruder_cali_manual_mode", std::to_string(p.extruder_cali_manual_mode), false, f);
    add("task_ext_change_assist", p.task_ext_change_assist ? "true" : "false", false, f);
    add("try_emmc_print", p.try_emmc_print ? "true" : "false", false, f);
    add("svc_context", p.svc_context, true, f);
    o += "}";
    return o;
}

// ---------------------------------------------------------------------------
// real symbol pointers (set the first time the host dlsym()s each name)
// ---------------------------------------------------------------------------
std::string (*r_get_version)() = nullptr;
void*       (*r_create_agent)(std::string) = nullptr;
int         (*r_set_config_dir)(void*, std::string) = nullptr;
int         (*r_change_user)(void*, std::string) = nullptr;
int         (*r_connect_printer)(void*, std::string, std::string, std::string, std::string, bool) = nullptr;
int         (*r_send_message)(void*, std::string, std::string, int, int) = nullptr;
int         (*r_send_message_to_printer)(void*, std::string, std::string, int, int) = nullptr;
int         (*r_start_print)(void*, PrintParams, OnUpdateStatusFn, WasCancelledFn, OnWaitFn) = nullptr;
int         (*r_start_local_print_with_record)(void*, PrintParams, OnUpdateStatusFn, WasCancelledFn, OnWaitFn) = nullptr;
int         (*r_start_local_print)(void*, PrintParams, OnUpdateStatusFn, WasCancelledFn) = nullptr;
int         (*r_bind)(void*, std::string, std::string, std::string, std::string, bool, OnUpdateStatusFn) = nullptr;
} // namespace

// ---------------------------------------------------------------------------
// wrappers -- identical ABI to the genuine symbol; log then tail-call
// ---------------------------------------------------------------------------
extern "C" {

std::string w_get_version() {
    emit("get_version", {});
    return r_get_version();
}
void* w_create_agent(std::string log_dir) {
    emit("create_agent", { S("log_dir", log_dir) });
    return r_create_agent(log_dir);
}
int w_set_config_dir(void* a, std::string config_dir) {
    emit("set_config_dir", { S("config_dir", config_dir) });
    return r_set_config_dir(a, config_dir);
}
int w_change_user(void* a, std::string user_info) {
    emit("change_user", { Sr("user_info", user_info) });
    return r_change_user(a, user_info);
}
int w_connect_printer(void* a, std::string dev_id, std::string dev_ip,
                      std::string user, std::string pass, bool ssl) {
    emit("connect_printer", { S("dev_id", dev_id), S("dev_ip", dev_ip),
                              S("username", user), S("password", "<redacted>"),
                              B("use_ssl", ssl) });
    return r_connect_printer(a, dev_id, dev_ip, user, pass, ssl);
}
int w_send_message(void* a, std::string dev_id, std::string json_str, int qos, int flag) {
    emit("send_message", { S("dev_id", dev_id), Sr("json", json_str),
                           I("qos", qos), I("flag", flag) });
    return r_send_message(a, dev_id, json_str, qos, flag);
}
int w_send_message_to_printer(void* a, std::string dev_id, std::string json_str, int qos, int flag) {
    emit("send_message_to_printer", { S("dev_id", dev_id), Sr("json", json_str),
                                      I("qos", qos), I("flag", flag) });
    return r_send_message_to_printer(a, dev_id, json_str, qos, flag);
}
int w_start_print(void* a, PrintParams p, OnUpdateStatusFn u, WasCancelledFn c, OnWaitFn w) {
    emit("start_print", { {"params", pp_json(p), false} });
    return r_start_print(a, p, u, c, w);
}
int w_start_local_print_with_record(void* a, PrintParams p, OnUpdateStatusFn u, WasCancelledFn c, OnWaitFn w) {
    emit("start_local_print_with_record", { {"params", pp_json(p), false} });
    return r_start_local_print_with_record(a, p, u, c, w);
}
int w_start_local_print(void* a, PrintParams p, OnUpdateStatusFn u, WasCancelledFn c) {
    emit("start_local_print", { {"params", pp_json(p), false} });
    return r_start_local_print(a, p, u, c);
}
int w_bind(void* a, std::string dev_ip, std::string dev_id, std::string sec_link,
           std::string tz, bool improved, OnUpdateStatusFn u) {
    emit("bind", { S("dev_ip", dev_ip), S("dev_id", dev_id),
                   S("sec_link", sec_link), S("timezone", tz), B("improved", improved) });
    return r_bind(a, dev_ip, dev_id, sec_link, tz, improved, u);
}

} // extern "C"

// ---------------------------------------------------------------------------
// interposed dlsym
// ---------------------------------------------------------------------------
static void* real_dlsym(void* handle, const char* name) {
    static void* (*rp)(void*, const char*) = nullptr;
    if (!rp) {
        rp = (void* (*)(void*, const char*))dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
        if (!rp) rp = (void* (*)(void*, const char*))dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    }
    return rp ? rp(handle, name) : nullptr;
}

extern "C" void* dlsym(void* handle, const char* name) {
    void* real = real_dlsym(handle, name);
    if (!real || !name) return real;

#define WRAP(sym, slot, wrap) \
    if (std::strcmp(name, sym) == 0) { slot = (decltype(slot))real; return (void*)&wrap; }

    WRAP("bambu_network_get_version", r_get_version, w_get_version)
    WRAP("bambu_network_create_agent", r_create_agent, w_create_agent)
    WRAP("bambu_network_set_config_dir", r_set_config_dir, w_set_config_dir)
    WRAP("bambu_network_change_user", r_change_user, w_change_user)
    WRAP("bambu_network_connect_printer", r_connect_printer, w_connect_printer)
    WRAP("bambu_network_send_message", r_send_message, w_send_message)
    WRAP("bambu_network_send_message_to_printer", r_send_message_to_printer, w_send_message_to_printer)
    WRAP("bambu_network_start_print", r_start_print, w_start_print)
    WRAP("bambu_network_start_local_print_with_record", r_start_local_print_with_record, w_start_local_print_with_record)
    WRAP("bambu_network_start_local_print", r_start_local_print, w_start_local_print)
    WRAP("bambu_network_bind", r_bind, w_bind)
#undef WRAP

    return real;   // untapped symbols pass straight through
}
