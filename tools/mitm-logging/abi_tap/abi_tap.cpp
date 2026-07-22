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
#include <atomic>
#include <functional>
#include "bambu_abi.hpp"
#include "bambu_camera_abi.hpp"

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

// Emit an INBOUND report record. Same NDJSON schema as emit() plus a top-level
// "dir":"report" so import_flow.py can tell plugin->Studio reports from the
// outbound command records. dev_id + the report JSON are logged (scrubbed).
void emit_report(const char* fn, const std::string& dev_id, const std::string& msg) {
    FILE* f = logfp();
    if (!f) return;
    std::string line = "{\"proto\":\"abi\",\"dir\":\"report\",\"fn\":\"";
    line += fn;
    line += "\",\"ts\":";
    line += std::to_string((long long)time(nullptr));
    line += ",\"args\":{\"dev_id\":\"";
    line += jesc(dev_id);
    line += "\",\"msg\":\"";
    line += jesc(scrub(msg));
    line += "\"}}\n";
    std::lock_guard<std::mutex> lk(g_mu);
    fputs(line.c_str(), f);
}

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
int         (*r_set_on_message_fn)(void*, OnMessageFn) = nullptr;
int         (*r_set_on_local_message_fn)(void*, OnMessageFn) = nullptr;
int         (*r_set_on_user_message_fn)(void*, OnMessageFn) = nullptr;

// The host's REAL inbound callbacks, captured at registration; the tap wrappers
// log the report then forward to these so Studio behaves normally.
OnMessageFn g_real_on_message;
OnMessageFn g_real_on_local_message;
OnMessageFn g_real_on_user_message;

// --- camera path: plugin get_camera_url + libBambuSource Bambu_* ABI ---------
using CamUrlCb = std::function<void(std::string)>;
int (*r_get_camera_url)(void*, std::string, CamUrlCb) = nullptr;
int (*r_get_camera_url_for_golive)(void*, std::string, std::string, CamUrlCb) = nullptr;

int  (*r_Bambu_Create)(bbl_cam::Bambu_Tunnel*, char const*) = nullptr;
void (*r_Bambu_SetLogger)(bbl_cam::Bambu_Tunnel, bbl_cam::Logger, void*) = nullptr;
int  (*r_Bambu_Open)(bbl_cam::Bambu_Tunnel) = nullptr;
int  (*r_Bambu_StartStream)(bbl_cam::Bambu_Tunnel, bool) = nullptr;
int  (*r_Bambu_StartStreamEx)(bbl_cam::Bambu_Tunnel, int) = nullptr;
int  (*r_Bambu_GetStreamCount)(bbl_cam::Bambu_Tunnel) = nullptr;
int  (*r_Bambu_GetStreamInfo)(bbl_cam::Bambu_Tunnel, int, bbl_cam::Bambu_StreamInfo*) = nullptr;
int  (*r_Bambu_ReadSample)(bbl_cam::Bambu_Tunnel, bbl_cam::Bambu_Sample*) = nullptr;
int  (*r_Bambu_SendMessage)(bbl_cam::Bambu_Tunnel, int, char const*, int) = nullptr;
void (*r_Bambu_Close)(bbl_cam::Bambu_Tunnel) = nullptr;
void (*r_Bambu_Destroy)(bbl_cam::Bambu_Tunnel) = nullptr;

// The host's REAL logger, captured at Bambu_SetLogger so the tap can surface the
// genuine BambuSource's internal log lines (its RTSP/TUTK/Agora dialing chatter)
// then forward to Studio unchanged.
std::atomic<bbl_cam::Logger> g_real_source_logger{nullptr};

// Per-tunnel ReadSample frame counter (opaque tunnel ptr -> count). A small
// fixed table avoids locking/allocating on the streaming thread hot path.
std::atomic<unsigned long long> g_frame_seq{0};

// Short hex of the first `n` bytes of a frame buffer + a 64-bit FNV-1a hash of
// the whole buffer. Lets us fingerprint each demuxed sample (JPEG FFD8 / H.264
// Annex-B 00000001<nal> / SPS-PPS) without dumping the video itself.
std::string frame_prefix_hex(const unsigned char* b, int size, int n) {
    if (!b || size <= 0) return "";
    int m = size < n ? size : n;
    static const char* hx = "0123456789abcdef";
    std::string o;
    o.reserve(m * 2);
    for (int i = 0; i < m; ++i) { o += hx[b[i] >> 4]; o += hx[b[i] & 0xf]; }
    return o;
}
std::string frame_hash_hex(const unsigned char* b, int size) {
    if (!b || size <= 0) return "0";
    uint64_t h = 1469598103934665603ull;
    for (int i = 0; i < size; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    char buf[20];
    std::snprintf(buf, sizeof buf, "%016llx", (unsigned long long)h);
    return buf;
}
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

// --- inbound report path ---------------------------------------------------
// The plugin invokes these (from its MQTT thread) to hand a status report up to
// Studio. Each logs the report, then forwards to the host's real callback so
// Studio's device state / UI update exactly as normal.
void tap_on_message(std::string dev_id, std::string msg) {
    emit_report("on_message", dev_id, msg);
    if (g_real_on_message) g_real_on_message(dev_id, msg);
}
void tap_on_local_message(std::string dev_id, std::string msg) {
    emit_report("on_local_message", dev_id, msg);
    if (g_real_on_local_message) g_real_on_local_message(dev_id, msg);
}
void tap_on_user_message(std::string dev_id, std::string msg) {
    emit_report("on_user_message", dev_id, msg);
    if (g_real_on_user_message) g_real_on_user_message(dev_id, msg);
}

// Setter wrappers: store the host's real callback, register the tap wrapper with
// the genuine plugin instead. Signature matches the genuine ABI exactly
// (int(void*, OnMessageFn), std::function passed by value).
int w_set_on_message_fn(void* a, OnMessageFn fn) {
    g_real_on_message = std::move(fn);
    emit("set_on_message_fn", { B("wrapped", true) });
    return r_set_on_message_fn(a, OnMessageFn(tap_on_message));
}
int w_set_on_local_message_fn(void* a, OnMessageFn fn) {
    g_real_on_local_message = std::move(fn);
    emit("set_on_local_message_fn", { B("wrapped", true) });
    return r_set_on_local_message_fn(a, OnMessageFn(tap_on_local_message));
}
int w_set_on_user_message_fn(void* a, OnMessageFn fn) {
    g_real_on_user_message = std::move(fn);
    emit("set_on_user_message_fn", { B("wrapped", true) });
    return r_set_on_user_message_fn(a, OnMessageFn(tap_on_user_message));
}

// --- camera URL (plugin) ---------------------------------------------------
// Studio asks the plugin for a camera URL and the plugin hands it back through a
// callback. We wrap the callback so we log the EXACT URL the genuine plugin
// chose (LAN bambu:///local, rtsp(s), or a cloud URL) -- this is the single most
// important datum for "which transport" and it is scrubbed for user/passwd.
int w_get_camera_url(void* a, std::string dev_id, CamUrlCb cb) {
    emit("get_camera_url", { S("dev_id", dev_id) });
    CamUrlCb real = std::move(cb);
    CamUrlCb wrap = [real, dev_id](std::string url) {
        emit_report("get_camera_url_result", dev_id, url);
        if (real) real(std::move(url));
    };
    return r_get_camera_url(a, dev_id, std::move(wrap));
}
int w_get_camera_url_for_golive(void* a, std::string dev_id, std::string sdev_id, CamUrlCb cb) {
    emit("get_camera_url_for_golive", { S("dev_id", dev_id), S("sdev_id", sdev_id) });
    CamUrlCb real = std::move(cb);
    CamUrlCb wrap = [real, dev_id](std::string url) {
        emit_report("get_camera_url_for_golive_result", dev_id, url);
        if (real) real(std::move(url));
    };
    return r_get_camera_url_for_golive(a, dev_id, sdev_id, std::move(wrap));
}

// --- libBambuSource Bambu_* camera ABI -------------------------------------
// The genuine BambuSource logs its own progress through Studio's Logger. We tap
// that so its RTSP/TUTK/Agora dialing and handshake chatter lands in our NDJSON.
void tap_source_logger(void* ctx, int level, bbl_cam::tchar const* msg) {
    if (msg) emit("source_log", { I("level", level), Sr("msg", std::string(msg)) });
    bbl_cam::Logger real = g_real_source_logger.load();
    if (real) real(ctx, level, msg);
}

int w_Bambu_Create(bbl_cam::Bambu_Tunnel* tunnel, char const* path) {
    // path is the camera URL Studio built from get_camera_url; scrub user/passwd.
    emit("Bambu_Create", { {"tunnel_out", std::to_string((long long)(intptr_t)tunnel), false},
                           Sr("url", path ? std::string(path) : std::string()) });
    return r_Bambu_Create(tunnel, path);
}
void w_Bambu_SetLogger(bbl_cam::Bambu_Tunnel t, bbl_cam::Logger logger, void* ctx) {
    g_real_source_logger.store(logger);
    emit("Bambu_SetLogger", { {"tunnel", std::to_string((long long)(intptr_t)t), false},
                              B("wrapped", true) });
    return r_Bambu_SetLogger(t, tap_source_logger, ctx);
}
int w_Bambu_Open(bbl_cam::Bambu_Tunnel t) {
    emit("Bambu_Open", { {"tunnel", std::to_string((long long)(intptr_t)t), false} });
    int rc = r_Bambu_Open(t);
    emit("Bambu_Open_ret", { {"tunnel", std::to_string((long long)(intptr_t)t), false}, I("rc", rc) });
    return rc;
}
int w_Bambu_StartStream(bbl_cam::Bambu_Tunnel t, bool video) {
    emit("Bambu_StartStream", { {"tunnel", std::to_string((long long)(intptr_t)t), false}, B("video", video) });
    int rc = r_Bambu_StartStream(t, video);
    emit("Bambu_StartStream_ret", { I("rc", rc) });
    return rc;
}
int w_Bambu_StartStreamEx(bbl_cam::Bambu_Tunnel t, int type) {
    {
        char hx[16]; std::snprintf(hx, sizeof hx, "0x%x", type);
        emit("Bambu_StartStreamEx", { {"tunnel", std::to_string((long long)(intptr_t)t), false},
                                      {"type", std::to_string(type), false}, S("type_hex", hx) });
    }
    int rc = r_Bambu_StartStreamEx(t, type);
    emit("Bambu_StartStreamEx_ret", { I("rc", rc) });
    return rc;
}
int w_Bambu_GetStreamCount(bbl_cam::Bambu_Tunnel t) {
    int rc = r_Bambu_GetStreamCount(t);
    emit("Bambu_GetStreamCount", { I("count", rc) });
    return rc;
}
int w_Bambu_GetStreamInfo(bbl_cam::Bambu_Tunnel t, int index, bbl_cam::Bambu_StreamInfo* info) {
    int rc = r_Bambu_GetStreamInfo(t, index, info);
    if (rc == bbl_cam::Bambu_success && info) {
        emit("Bambu_GetStreamInfo", { I("index", index), I("type", info->type),
              I("sub_type", info->sub_type), I("format_type", info->format_type),
              I("width", info->format.video.width), I("height", info->format.video.height),
              I("frame_rate", info->format.video.frame_rate),
              I("format_size", info->format_size), I("max_frame_size", info->max_frame_size) });
    } else {
        emit("Bambu_GetStreamInfo", { I("index", index), I("rc", rc) });
    }
    return rc;
}
int w_Bambu_SendMessage(bbl_cam::Bambu_Tunnel t, int ctrl, char const* data, int len) {
    // Handshake / CTRL JSON pushed to the source. Log ctrl + (scrubbed) body.
    std::string body = (data && len > 0) ? std::string(data, (size_t)len) : std::string();
    emit("Bambu_SendMessage", { {"ctrl", std::to_string(ctrl), false}, I("len", len),
                                Sr("data", body) });
    return r_Bambu_SendMessage(t, ctrl, data, len);
}
int w_Bambu_ReadSample(bbl_cam::Bambu_Tunnel t, bbl_cam::Bambu_Sample* sample) {
    int rc = r_Bambu_ReadSample(t, sample);
    // Only log real samples (skip the would_block polls that gst spins on).
    if (rc == bbl_cam::Bambu_success && sample) {
        unsigned long long seq = ++g_frame_seq;
        FILE* f = logfp();
        if (f) {
            std::string pfx = frame_prefix_hex(sample->buffer, sample->size, 16);
            std::string hsh = frame_hash_hex(sample->buffer, sample->size);
            char line[512];
            std::snprintf(line, sizeof line,
                "{\"proto\":\"abi\",\"fn\":\"Bambu_ReadSample\",\"ts\":%lld,"
                "\"args\":{\"seq\":%llu,\"itrack\":%d,\"size\":%d,\"flags\":%d,"
                "\"sync\":%s,\"decode_time\":%llu,\"prefix\":\"%s\",\"fnv\":\"%s\"}}\n",
                (long long)time(nullptr), seq, sample->itrack, sample->size, sample->flags,
                (sample->flags & bbl_cam::f_sync) ? "true" : "false",
                sample->decode_time, pfx.c_str(), hsh.c_str());
            std::lock_guard<std::mutex> lk(g_mu);
            fputs(line, f);
        }
    }
    return rc;
}
void w_Bambu_Close(bbl_cam::Bambu_Tunnel t) {
    emit("Bambu_Close", { {"tunnel", std::to_string((long long)(intptr_t)t), false},
                          {"frames_total", std::to_string(g_frame_seq.load()), false} });
    return r_Bambu_Close(t);
}
void w_Bambu_Destroy(bbl_cam::Bambu_Tunnel t) {
    emit("Bambu_Destroy", { {"tunnel", std::to_string((long long)(intptr_t)t), false} });
    return r_Bambu_Destroy(t);
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

    // The libBambuSource Bambu_* camera ABI lives in a separate module with no
    // anti-hook self-check, so it is always safe to wrap. The bambu_network_*
    // plugin symbols, by contrast, sit behind the plugin's init-time integrity
    // check (some versions exit(0) if a call returns into an interposer frame):
    // ABI_TAP_SKIP_NETWORK=1 leaves every plugin symbol untouched (returned
    // real, byte-identical to no hook) so a video session can be captured on
    // those versions purely from the BambuSource side.
    static const bool skip_net = [] {
        const char* e = getenv("ABI_TAP_SKIP_NETWORK");
        return e && e[0] == '1';
    }();
    if (skip_net) goto camera_abi;

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
    WRAP("bambu_network_set_on_message_fn", r_set_on_message_fn, w_set_on_message_fn)
    WRAP("bambu_network_set_on_local_message_fn", r_set_on_local_message_fn, w_set_on_local_message_fn)
    WRAP("bambu_network_set_on_user_message_fn", r_set_on_user_message_fn, w_set_on_user_message_fn)

    // camera URL (network plugin)
    WRAP("bambu_network_get_camera_url", r_get_camera_url, w_get_camera_url)
    WRAP("bambu_network_get_camera_url_for_golive", r_get_camera_url_for_golive, w_get_camera_url_for_golive)

camera_abi:
    // libBambuSource camera transport ABI (dlsym'd from the BambuSource module)
    WRAP("Bambu_Create", r_Bambu_Create, w_Bambu_Create)
    WRAP("Bambu_SetLogger", r_Bambu_SetLogger, w_Bambu_SetLogger)
    WRAP("Bambu_Open", r_Bambu_Open, w_Bambu_Open)
    WRAP("Bambu_StartStream", r_Bambu_StartStream, w_Bambu_StartStream)
    WRAP("Bambu_StartStreamEx", r_Bambu_StartStreamEx, w_Bambu_StartStreamEx)
    WRAP("Bambu_GetStreamCount", r_Bambu_GetStreamCount, w_Bambu_GetStreamCount)
    WRAP("Bambu_GetStreamInfo", r_Bambu_GetStreamInfo, w_Bambu_GetStreamInfo)
    WRAP("Bambu_ReadSample", r_Bambu_ReadSample, w_Bambu_ReadSample)
    WRAP("Bambu_SendMessage", r_Bambu_SendMessage, w_Bambu_SendMessage)
    WRAP("Bambu_Close", r_Bambu_Close, w_Bambu_Close)
    WRAP("Bambu_Destroy", r_Bambu_Destroy, w_Bambu_Destroy)
#undef WRAP

    return real;   // untapped symbols pass straight through
}

// ---------------------------------------------------------------------------
// Optional LAN transport redirect (same lib, so no inter-preload dlsym clash).
// When LAN_IP + REDIRECT_990/REDIRECT_8883 are set, steer that printer's FTPS
// (:990) / MQTT (:8883) connections to local relays (forward + log). Scoped to
// LAN_IP so the cloud broker connections are untouched. Not linked against a
// second OpenSSL (that hangs BambuStudio's static-OpenSSL startup) -- this is
// connect()-only. This is what lets a full GUI print capture record the FTPS
// STOR + MQTT project_file alongside the tap's PrintParams.
// ---------------------------------------------------------------------------
#include <netinet/in.h>
#include <arpa/inet.h>
extern "C" int connect(int fd, const struct sockaddr* a, socklen_t l) {
    static int (*rc)(int, const struct sockaddr*, socklen_t) = nullptr;
    if (!rc) rc = (int (*)(int, const struct sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect");
    if (a && a->sa_family == AF_INET) {
        const struct sockaddr_in* s = (const struct sockaddr_in*)a;
        unsigned short p = ntohs(s->sin_port);
        const char* lanip = getenv("LAN_IP");
        char ipbuf[64] = {0};
        inet_ntop(AF_INET, &s->sin_addr, ipbuf, sizeof ipbuf);
        bool match = lanip && lanip[0] && std::strcmp(ipbuf, lanip) == 0;
        const char* rd = (match && p == 990) ? getenv("REDIRECT_990")
                       : (match && p == 8883) ? getenv("REDIRECT_8883") : nullptr;
        if (rd && rd[0]) {
            struct sockaddr_in b;
            std::memcpy(&b, s, sizeof b);
            b.sin_addr.s_addr = htonl(0x7f000001u);
            b.sin_port = htons((unsigned short)atoi(rd));
            return rc(fd, (const struct sockaddr*)&b, l);
        }
    }
    return rc(fd, a, l);
}
