// libBambuSource camera ABI, mirrored from BambuStudio's
// src/slic3r/GUI/Printer/BambuTunnel.h (the C ABI Studio resolves out of
// libBambuSource.so via dlsym). Studio loads the module with
// NetworkAgent::get_bambu_source_entry() then dlsym()s each Bambu_* symbol
// (PrinterFileSystem.cpp StaticBambuLib::get), so the abi_tap dlsym interposer
// catches these exactly like the bambu_network_* plugin symbols.
//
// Linux tchar is char; all Bambu_* entry points are plain extern "C" (no
// hidden-pointer C++ ABI), so the wrappers are straightforward.
#pragma once
#include <cstdint>

namespace bbl_cam {

typedef void* Bambu_Tunnel;
using tchar = char;
typedef void (*Logger)(void* context, int level, tchar const* msg);

enum Bambu_StreamType { VIDE = 0, AUDI = 1 };
enum Bambu_VideoSubType { AVC1 = 0, MJPG = 1 };
enum Bambu_FormatType {
    video_avc_packet = 0,
    video_avc_byte_stream,
    video_jpeg,
    audio_raw,
    audio_adts,
};
enum Bambu_SampleFlag { f_sync = 1 };
enum Bambu_Error { Bambu_success = 0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit };

struct Bambu_StreamInfo {
    int type;      // Bambu_StreamType
    int sub_type;  // Bambu_VideoSubType
    union {
        struct { int width; int height; int frame_rate; } video;
        struct { int sample_rate; int channel_count; int sample_size; } audio;
    } format;
    int                  format_type;   // Bambu_FormatType
    int                  format_size;
    int                  max_frame_size;
    unsigned char const* format_buffer;
};

struct Bambu_Sample {
    int                  itrack;
    int                  size;
    int                  flags;
    unsigned char const* buffer;
    unsigned long long   decode_time; // 100ns units
};

}  // namespace bbl_cam
