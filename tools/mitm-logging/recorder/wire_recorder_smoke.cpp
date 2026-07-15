// Standalone smoke test for the MITM wire recorder. Points the sink at a temp
// capture dir, drives every entry point, and checks a non-empty session file
// with the expected boundaries was written. No external dependencies.

#include "wire_recorder.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace mitm = bbl::mitm;

int main()
{
    char tmpl[] = "/tmp/bbl_mitm_smoke_XXXXXX";
    const char* dir = mkdtemp(tmpl);
    if (!dir) { std::fprintf(stderr, "mkdtemp failed\n"); return 2; }

    setenv("BBL_MITM_CAPTURE_DIR", dir, 1);
    setenv("BBL_MITM_FLOW", "start_print", 1);
    setenv("BBL_MITM_MODEL", "h2s", 1);
    setenv("BBL_MITM_CHANNEL", "cloud_lan", 1);

    if (!mitm::enabled()) { std::fprintf(stderr, "recorder not enabled\n"); return 2; }

    mitm::begin_session("02.07.00.55", "02.07.00.50");

    mitm::Headers h = {
        {"Host", "api.bambulab.com"},
        {"User-Agent", "bambu_network_agent/02.07.00.50"},
        {"Authorization", "Bearer TESTTOKEN"},
        {"Content-Type", "application/json"},
    };
    mitm::record_http("POST", "https://api.bambulab.com/v1/user-service/my/task",
                      h, "{\"name\":\"box\"}", 200, "application/json", "{\"id\":42}");
    mitm::record_mqtt(mitm::Direction::Out, "device/0940000/request",
                      "{\"print\":{}}", 1, false);
    mitm::record_ftps("STOR", "/model.gcode.3mf", 12345, "d41d8cd98f00b204e9800998ecf8427e");
    mitm::record_ssdp(mitm::Direction::In, "NOTIFY * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n\r\n");
    mitm::record_ctrl(mitm::Direction::Out, 1, "{\"cmdtype\":1,\"req\":{\"type\":\"model\"}}");

    // Locate the produced session file.
    std::string cmd = "ls " + std::string(dir) + "/session-*.ndjson >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) {
        std::fprintf(stderr, "no session file written\n");
        return 1;
    }

    // Count lines: meta + 5 events == 6.
    std::string find = "cat " + std::string(dir) + "/session-*.ndjson";
    FILE* p = popen(find.c_str(), "r");
    if (!p) { std::fprintf(stderr, "popen failed\n"); return 2; }
    int lines = 0; int c; bool nonempty_last = false;
    while ((c = std::fgetc(p)) != EOF) {
        nonempty_last = (c != '\n');
        if (c == '\n') ++lines;
    }
    pclose(p);
    if (nonempty_last) ++lines;

    if (lines != 6) {
        std::fprintf(stderr, "expected 6 NDJSON lines, got %d\n", lines);
        return 1;
    }

    std::printf("wire_recorder_smoke OK: 6 events in %s\n", dir);
    return 0;
}
