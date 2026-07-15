// MITM wire recorder — shared, dependency-free NDJSON event sink.
//
// Included at the network choke points of the OSS `obn` plugin (and,
// optionally, at a NetworkAgent-level tap in the slicer) to record every
// network interaction in a machine-readable stream. A post-processing step
// (export_fixtures.py) folds a session's events into obn-wire-flow/v1
// fixtures and anonymises them.
//
// The sink is inert unless BBL_MITM_CAPTURE_DIR (or OBN_WIRE_RECORD together
// with a capture dir) is set in the environment, so linking it in has no
// runtime effect on a normal build.
//
// Never record raw signing keys. For signed print commands, record only the
// already-computed sign_string / cert_id (verifiable public artefacts), never
// the private key `d`.

#ifndef BBL_MITM_WIRE_RECORDER_HPP
#define BBL_MITM_WIRE_RECORDER_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace bbl::mitm {

// Ordered header list — order is load-bearing (Cloudflare JA4H fingerprint).
using Headers = std::vector<std::pair<std::string, std::string>>;

enum class Direction { Out, In };

// True when a capture dir is configured; call sites may skip expensive
// argument assembly when this is false.
bool enabled();

// One-time session header. `flow`, `model`, `channel` come from the launcher
// env (BBL_MITM_FLOW / BBL_MITM_MODEL / BBL_MITM_CHANNEL); the rest are
// discovered by the recorder. Safe to call repeatedly (first wins).
void begin_session(const std::string& slicer_client_version,
                   const std::string& network_plugin_version);

// Cloud REST / S3. `headers` MUST be in the exact wire order. `status` is the
// HTTP response code (0 if the request failed before a response).
void record_http(const std::string& method,
                 const std::string& url,
                 const Headers&     headers,
                 const std::string& req_body,
                 long               status,
                 const std::string& resp_content_type,
                 const std::string& resp_body);

// LAN MQTT publish / inbound message.
void record_mqtt(Direction          dir,
                 const std::string& topic,
                 const std::string& payload,
                 int                qos,
                 bool               retain);

// FTPS. `op` is "STOR" | "LIST" | "RETR"; `md5` is the file md5 for STOR
// (empty otherwise).
void record_ftps(const std::string& op,
                 const std::string& path,
                 uint64_t           size,
                 const std::string& md5);

// SSDP NOTIFY / M-SEARCH raw datagram.
void record_ssdp(Direction dir, const std::string& raw);

// libBambuSource CTRL channel cmdtype envelope.
void record_ctrl(Direction dir, int cmdtype, const std::string& json);

} // namespace bbl::mitm

#endif // BBL_MITM_WIRE_RECORDER_HPP
