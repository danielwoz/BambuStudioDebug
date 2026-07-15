#include "wire_recorder.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>

namespace bbl::mitm {

namespace {

struct State {
    std::mutex   mu;
    std::FILE*   fp   = nullptr;
    bool         init = false;
    bool         on   = false;
    std::atomic<uint64_t> seq{0};
};

State& state()
{
    static State s;
    return s;
}

// Minimal JSON string escaping — enough for headers, paths, bodies and raw
// datagrams. Non-printable bytes are emitted as \uXXXX so the stream stays
// valid UTF-8-clean NDJSON.
void json_escape(std::string& out, const std::string& in)
{
    static const char* const HEX = "0123456789abcdef";
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += HEX[(c >> 4) & 0xF];
                    out += HEX[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
}

void field(std::string& out, const char* key, const std::string& val, bool first = false)
{
    if (!first) out += ',';
    out += '"';
    out += key;
    out += "\":\"";
    json_escape(out, val);
    out += '"';
}

void field_raw(std::string& out, const char* key, const std::string& raw_val)
{
    out += ',';
    out += '"';
    out += key;
    out += "\":";
    out += raw_val;
}

std::string now_iso_utc()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt  = system_clock::to_time_t(now);
    auto us  = duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000;
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%06lldZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long long>(us));
    return buf;
}

const char* env_or(const char* name, const char* dflt)
{
    const char* v = std::getenv(name);
    return (v && *v) ? v : dflt;
}

// Open the session file lazily on first record. Must hold s.mu.
void ensure_open_locked(State& s)
{
    if (s.init) return;
    s.init = true;

    const char* dir = std::getenv("BBL_MITM_CAPTURE_DIR");
    // OBN_WIRE_RECORD gates the obn-side call sites, but a capture dir is what
    // the sink needs; accept either signal but require a directory.
    if (!dir || !*dir) { s.on = false; return; }

    std::string path(dir);
    char last = path.empty() ? '/' : path.back();
    if (last != '/' && last != '\\') path += '/';
    path += "session-";
    // Timestamp with ':' stripped for filesystem friendliness.
    std::string ts = now_iso_utc();
    for (char& c : ts) if (c == ':') c = '-';
    path += ts;
    path += '-';
    path += env_or("BBL_MITM_FLOW", "unknown");
    path += ".ndjson";

    s.fp = std::fopen(path.c_str(), "a");
    s.on = (s.fp != nullptr);
    if (s.on) std::setvbuf(s.fp, nullptr, _IONBF, 0);
}

// Write one NDJSON line built by the caller (already begins after the opening
// brace's common prefix). Prepends common envelope fields.
void emit_locked(State& s, const char* boundary, const std::string& body)
{
    if (!s.on || !s.fp) return;
    std::string line;
    line.reserve(body.size() + 96);
    line += '{';
    field(line, "seq", std::to_string(s.seq.fetch_add(1)), /*first=*/true);
    field(line, "ts", now_iso_utc());
    field(line, "boundary", boundary);
    line += body; // body starts with ',' for each of its fields
    line += "}\n";
    std::fwrite(line.data(), 1, line.size(), s.fp);
}

} // namespace

bool enabled()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    return s.on;
}

void begin_session(const std::string& slicer_client_version,
                   const std::string& network_plugin_version)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    if (!s.on) return;
    static bool done = false;
    if (done) return;
    done = true;

    std::string b;
    field(b, "os",
#if defined(_WIN32)
          "windows"
#elif defined(__APPLE__)
          "macos"
#else
          "linux"
#endif
    );
    field(b, "slicer_client_version", slicer_client_version);
    field(b, "network_plugin_version", network_plugin_version);
    field(b, "channel", env_or("BBL_MITM_CHANNEL", "unknown"));
    field(b, "printer_model", env_or("BBL_MITM_MODEL", "unknown"));
    field(b, "flow", env_or("BBL_MITM_FLOW", "unknown"));
    emit_locked(s, "meta", b);
}

void record_http(const std::string& method,
                 const std::string& url,
                 const Headers&     headers,
                 const std::string& req_body,
                 long               status,
                 const std::string& resp_content_type,
                 const std::string& resp_body)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    if (!s.on) return;

    std::string b;
    field(b, "method", method);
    field(b, "url", url);
    // Ordered header array — order preserved exactly as passed.
    std::string hdr = "[";
    for (size_t i = 0; i < headers.size(); ++i) {
        if (i) hdr += ',';
        hdr += "{\"name\":\"";
        json_escape(hdr, headers[i].first);
        hdr += "\",\"value\":\"";
        json_escape(hdr, headers[i].second);
        hdr += "\"}";
    }
    hdr += "]";
    field_raw(b, "req_headers", hdr);
    field(b, "req_body", req_body);
    field_raw(b, "status", std::to_string(status));
    field(b, "resp_content_type", resp_content_type);
    field(b, "resp_body", resp_body);
    emit_locked(s, "http", b);
}

void record_mqtt(Direction dir, const std::string& topic,
                 const std::string& payload, int qos, bool retain)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    if (!s.on) return;

    std::string b;
    field(b, "dir", dir == Direction::Out ? "out" : "in");
    field(b, "topic", topic);
    field(b, "payload", payload);
    field_raw(b, "qos", std::to_string(qos));
    field_raw(b, "retain", retain ? "true" : "false");
    emit_locked(s, "mqtt", b);
}

void record_ftps(const std::string& op, const std::string& path,
                 uint64_t size, const std::string& md5)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    if (!s.on) return;

    std::string b;
    field(b, "op", op);
    field(b, "path", path);
    field_raw(b, "size", std::to_string(size));
    field(b, "md5", md5);
    emit_locked(s, "ftps", b);
}

void record_ssdp(Direction dir, const std::string& raw)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    if (!s.on) return;

    std::string b;
    field(b, "dir", dir == Direction::Out ? "out" : "in");
    field(b, "raw", raw);
    emit_locked(s, "ssdp", b);
}

void record_ctrl(Direction dir, int cmdtype, const std::string& json)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    ensure_open_locked(s);
    if (!s.on) return;

    std::string b;
    field(b, "dir", dir == Direction::Out ? "out" : "in");
    field_raw(b, "cmdtype", std::to_string(cmdtype));
    field(b, "json", json);
    emit_locked(s, "ctrl", b);
}

} // namespace bbl::mitm
