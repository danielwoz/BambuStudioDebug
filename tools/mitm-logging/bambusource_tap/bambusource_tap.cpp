// libBambuSource replacement shim — captures the GENUINE camera transport ABI.
//
// Bambu Studio loads the camera source library by PATH:
//   NetworkAgent::get_bambu_source_entry() -> dlopen("<data_dir>/plugins/
//   libBambuSource.so", RTLD_LAZY), then PrinterFileSystem::StaticBambuLib::get
//   dlsym()s each Bambu_* entry point out of that module handle. There is no
//   integrity/cert check on this file (unlike the network plugin), and the
//   network plugin is not involved in any Bambu_* call.
//
// So we drop in as libBambuSource.so, forward every Bambu_* to the REAL library
// (renamed libBambuSource.real.so, or BAMBU_SOURCE_REAL), and log the camera
// session at the ABI boundary: the URL handed to Bambu_Create (where Bambu_Open
// then dials), the StartStream/StartStreamEx handshake, each Bambu_SendMessage,
// every demuxed Bambu_ReadSample (itrack/size/flags/decode_time + prefix+hash),
// and the real library's own internal log lines (its RTSP/TUTK/Agora chatter,
// captured by wrapping the Logger it is handed).
//
// Because this shim never interposes dlsym/connect and never touches the network
// plugin, the plugin's VMProtect anti-tamper sees a pristine process.
//
// Build: bambusource_tap/build.sh
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <string>
#include <atomic>

#define EXPORT extern "C" __attribute__((visibility("default")))

// ---- ABI types mirrored from BambuStudio src/slic3r/GUI/Printer/BambuTunnel.h.
typedef void* Bambu_Tunnel;
using tchar = char;
typedef void (*Logger)(void* context, int level, tchar const* msg);

struct Bambu_StreamInfo {
    int type;      // 0=VIDE 1=AUDI
    int sub_type;  // 0=AVC1 1=MJPG
    union {
        struct { int width; int height; int frame_rate; } video;
        struct { int sample_rate; int channel_count; int sample_size; } audio;
    } format;
    int                  format_type;   // 0=avc_packet 1=avc_byte_stream 2=jpeg ...
    int                  format_size;
    int                  max_frame_size;
    unsigned char const* format_buffer;
};
struct Bambu_Sample {
    int                  itrack;
    int                  size;
    int                  flags;         // bit0 = f_sync (keyframe)
    unsigned char const* buffer;
    unsigned long long   decode_time;   // 100ns units
};

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------
namespace {
std::mutex g_mu;
FILE* g_fp = nullptr;
std::atomic<unsigned long long> g_frame_seq{0};
std::atomic<Logger> g_real_logger{nullptr};

FILE* logfp() {
    if (!g_fp) {
        const char* p = getenv("BAMBUSRC_TAP_LOG");
        g_fp = fopen(p && p[0] ? p : "bambusource_tap.jsonl", "a");
        if (g_fp) setvbuf(g_fp, nullptr, _IOLBF, 0);
    }
    return g_fp;
}
std::string jesc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
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
// Redact user/passwd embedded in camera URLs and any token-ish CTRL JSON.
std::string scrub_url(const std::string& s) {
    std::string o = s;
    auto redact_after = [&](const char* key) {
        size_t k = 0;
        while ((k = o.find(key, k)) != std::string::npos) {
            size_t v = k + std::strlen(key);
            size_t e = v;
            while (e < o.size() && o[e] != '&' && o[e] != '@' && o[e] != ':' &&
                   o[e] != '/' && o[e] != '"' && o[e] != ' ') ++e;
            o.replace(v, e - v, "<redacted>");
            k = v + 10;
        }
    };
    redact_after("passwd=");
    redact_after("password=");
    redact_after("authkey=");
    redact_after("&user=");
    return o;
}
void logline(const std::string& s) {
    FILE* f = logfp();
    if (!f) return;
    std::lock_guard<std::mutex> lk(g_mu);
    fputs(s.c_str(), f);
    fputc('\n', f);
}
void ev(const std::string& fn, const std::string& extra_json) {
    std::string s = "{\"proto\":\"bambusrc\",\"fn\":\"";
    s += fn; s += "\",\"ts\":"; s += std::to_string((long long)time(nullptr));
    if (!extra_json.empty()) { s += ","; s += extra_json; }
    s += "}";
    logline(s);
}
std::string prefix_hex(const unsigned char* b, int size, int n) {
    if (!b || size <= 0) return "";
    int m = size < n ? size : n;
    static const char* hx = "0123456789abcdef";
    std::string o; o.reserve(m * 2);
    for (int i = 0; i < m; ++i) { o += hx[b[i] >> 4]; o += hx[b[i] & 0xf]; }
    return o;
}
std::string fnv_hex(const unsigned char* b, int size) {
    if (!b || size <= 0) return "0";
    uint64_t h = 1469598103934665603ull;
    for (int i = 0; i < size; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    char buf[20]; std::snprintf(buf, sizeof buf, "%016llx", (unsigned long long)h);
    return buf;
}

// ---- real library resolution ---------------------------------------------
void* real_handle() {
    static void* h = nullptr;
    static std::once_flag once;
    std::call_once(once, [] {
        const char* p = getenv("BAMBU_SOURCE_REAL");
        std::string path = (p && p[0]) ? p
            : (std::string(getenv("HOME") ? getenv("HOME") : "") +
               "/.config/BambuStudio/plugins/libBambuSource.real.so");
        h = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        ev("shim_load", std::string("\"real\":\"") + jesc(path) + "\",\"ok\":" +
                        (h ? "true" : "false") +
                        (h ? std::string() : std::string(",\"dlerror\":\"") + jesc(dlerror() ? dlerror() : "") + "\""));
    });
    return h;
}
template <class T>
T rsym(const char* name) {
    void* h = real_handle();
    return h ? reinterpret_cast<T>(dlsym(h, name)) : nullptr;
}

// The real library's Logger sink -- we forward through this so the shim surfaces
// the genuine source's internal progress chatter.
void tap_logger(void* ctx, int level, tchar const* msg) {
    if (msg) ev("source_log", std::string("\"level\":") + std::to_string(level) +
                              ",\"msg\":\"" + jesc(msg) + "\"");
    Logger real = g_real_logger.load();
    if (real) real(ctx, level, msg);
}
}  // namespace

// ---------------------------------------------------------------------------
// forwarded Bambu_* exports (logged where interesting)
// ---------------------------------------------------------------------------
EXPORT int Bambu_Init() {
    auto r = rsym<int(*)()>("Bambu_Init");
    int rc = r ? r() : 0;
    ev("Bambu_Init", std::string("\"rc\":") + std::to_string(rc));
    return rc;
}
EXPORT void Bambu_Deinit() {
    auto r = rsym<void(*)()>("Bambu_Deinit");
    if (r) r();
}
EXPORT int Bambu_Create(Bambu_Tunnel* tunnel, char const* path) {
    auto r = rsym<int(*)(Bambu_Tunnel*, char const*)>("Bambu_Create");
    int rc = r ? r(tunnel, path) : -1;
    ev("Bambu_Create", std::string("\"url\":\"") +
       jesc(scrub_url(path ? path : "")) + "\",\"tunnel\":" +
       std::to_string((long long)(intptr_t)(tunnel ? *tunnel : nullptr)) +
       ",\"rc\":" + std::to_string(rc));
    return rc;
}
EXPORT void Bambu_SetLogger(Bambu_Tunnel tunnel, Logger logger, void* ctx) {
    g_real_logger.store(logger);
    ev("Bambu_SetLogger", std::string("\"tunnel\":") + std::to_string((long long)(intptr_t)tunnel));
    auto r = rsym<void(*)(Bambu_Tunnel, Logger, void*)>("Bambu_SetLogger");
    if (r) r(tunnel, tap_logger, ctx);
}
EXPORT int Bambu_Open(Bambu_Tunnel tunnel) {
    ev("Bambu_Open", std::string("\"tunnel\":") + std::to_string((long long)(intptr_t)tunnel));
    auto r = rsym<int(*)(Bambu_Tunnel)>("Bambu_Open");
    int rc = r ? r(tunnel) : -1;
    ev("Bambu_Open_ret", std::string("\"tunnel\":") + std::to_string((long long)(intptr_t)tunnel) +
                         ",\"rc\":" + std::to_string(rc));
    return rc;
}
EXPORT int Bambu_StartStream(Bambu_Tunnel tunnel, bool video) {
    ev("Bambu_StartStream", std::string("\"video\":") + (video ? "true" : "false"));
    auto r = rsym<int(*)(Bambu_Tunnel, bool)>("Bambu_StartStream");
    int rc = r ? r(tunnel, video) : -1;
    ev("Bambu_StartStream_ret", std::string("\"rc\":") + std::to_string(rc));
    return rc;
}
EXPORT int Bambu_StartStreamEx(Bambu_Tunnel tunnel, int type) {
    char hx[16]; std::snprintf(hx, sizeof hx, "0x%x", type);
    ev("Bambu_StartStreamEx", std::string("\"type\":") + std::to_string(type) +
                              ",\"type_hex\":\"" + hx + "\"");
    auto r = rsym<int(*)(Bambu_Tunnel, int)>("Bambu_StartStreamEx");
    int rc = r ? r(tunnel, type) : -1;
    ev("Bambu_StartStreamEx_ret", std::string("\"rc\":") + std::to_string(rc));
    return rc;
}
EXPORT int Bambu_GetStreamCount(Bambu_Tunnel tunnel) {
    auto r = rsym<int(*)(Bambu_Tunnel)>("Bambu_GetStreamCount");
    int rc = r ? r(tunnel) : 0;
    ev("Bambu_GetStreamCount", std::string("\"count\":") + std::to_string(rc));
    return rc;
}
EXPORT int Bambu_GetStreamInfo(Bambu_Tunnel tunnel, int index, Bambu_StreamInfo* info) {
    auto r = rsym<int(*)(Bambu_Tunnel, int, Bambu_StreamInfo*)>("Bambu_GetStreamInfo");
    int rc = r ? r(tunnel, index, info) : -1;
    if (rc == 0 && info) {
        char buf[256];
        std::snprintf(buf, sizeof buf,
            "\"index\":%d,\"type\":%d,\"sub_type\":%d,\"format_type\":%d,"
            "\"width\":%d,\"height\":%d,\"frame_rate\":%d,\"format_size\":%d,"
            "\"max_frame_size\":%d",
            index, info->type, info->sub_type, info->format_type,
            info->format.video.width, info->format.video.height,
            info->format.video.frame_rate, info->format_size, info->max_frame_size);
        ev("Bambu_GetStreamInfo", buf);
        // Dump the codec init blob (SPS/PPS for H.264) if the source advertises one.
        if (info->format_buffer && info->format_size > 0)
            ev("Bambu_GetStreamInfo_fmt",
               std::string("\"format_size\":") + std::to_string(info->format_size) +
               ",\"prefix\":\"" + prefix_hex(info->format_buffer, info->format_size, 40) + "\"");
    } else {
        ev("Bambu_GetStreamInfo", std::string("\"index\":") + std::to_string(index) +
                                  ",\"rc\":" + std::to_string(rc));
    }
    return rc;
}
EXPORT unsigned long Bambu_GetDuration(Bambu_Tunnel tunnel) {
    auto r = rsym<unsigned long(*)(Bambu_Tunnel)>("Bambu_GetDuration");
    return r ? r(tunnel) : 0;
}
EXPORT int Bambu_Seek(Bambu_Tunnel tunnel, unsigned long t) {
    auto r = rsym<int(*)(Bambu_Tunnel, unsigned long)>("Bambu_Seek");
    return r ? r(tunnel, t) : 0;
}
EXPORT int Bambu_ReadSample(Bambu_Tunnel tunnel, Bambu_Sample* sample) {
    auto r = rsym<int(*)(Bambu_Tunnel, Bambu_Sample*)>("Bambu_ReadSample");
    int rc = r ? r(tunnel, sample) : -1;
    // rc==0 is Bambu_success; skip the would_block(2) polls gst spins on.
    if (rc == 0 && sample) {
        unsigned long long seq = ++g_frame_seq;
        char head[256];
        std::snprintf(head, sizeof head,
            "\"seq\":%llu,\"itrack\":%d,\"size\":%d,\"flags\":%d,\"sync\":%s,"
            "\"decode_time\":%llu",
            seq, sample->itrack, sample->size, sample->flags,
            (sample->flags & 1) ? "true" : "false", sample->decode_time);
        std::string extra = head;
        extra += ",\"prefix\":\"" + prefix_hex(sample->buffer, sample->size, 16) + "\"";
        extra += ",\"fnv\":\"" + fnv_hex(sample->buffer, sample->size) + "\"";
        ev("Bambu_ReadSample", extra);
    }
    return rc;
}
EXPORT int Bambu_SendMessage(Bambu_Tunnel tunnel, int ctrl, char const* data, int len) {
    std::string body = (data && len > 0) ? std::string(data, (size_t)len) : std::string();
    char hx[16]; std::snprintf(hx, sizeof hx, "0x%x", ctrl);
    ev("Bambu_SendMessage", std::string("\"ctrl\":\"") + hx + "\",\"len\":" +
       std::to_string(len) + ",\"data\":\"" + jesc(scrub_url(body)) + "\"");
    auto r = rsym<int(*)(Bambu_Tunnel, int, char const*, int)>("Bambu_SendMessage");
    return r ? r(tunnel, ctrl, data, len) : -1;
}
EXPORT int Bambu_RecvMessage(Bambu_Tunnel tunnel, int* ctrl, char* data, int* len) {
    auto r = rsym<int(*)(Bambu_Tunnel, int*, char*, int*)>("Bambu_RecvMessage");
    return r ? r(tunnel, ctrl, data, len) : 2;
}
EXPORT void Bambu_Close(Bambu_Tunnel tunnel) {
    ev("Bambu_Close", std::string("\"tunnel\":") + std::to_string((long long)(intptr_t)tunnel) +
                      ",\"frames_total\":" + std::to_string(g_frame_seq.load()));
    auto r = rsym<void(*)(Bambu_Tunnel)>("Bambu_Close");
    if (r) r(tunnel);
}
EXPORT void Bambu_Destroy(Bambu_Tunnel tunnel) {
    ev("Bambu_Destroy", std::string("\"tunnel\":") + std::to_string((long long)(intptr_t)tunnel));
    auto r = rsym<void(*)(Bambu_Tunnel)>("Bambu_Destroy");
    if (r) r(tunnel);
}
EXPORT char const* Bambu_GetLastErrorMsg() {
    auto r = rsym<char const*(*)()>("Bambu_GetLastErrorMsg");
    return r ? r() : "";
}
EXPORT void Bambu_FreeLogMsg(tchar const* msg) {
    auto r = rsym<void(*)(tchar const*)>("Bambu_FreeLogMsg");
    if (r) r(msg);
}
