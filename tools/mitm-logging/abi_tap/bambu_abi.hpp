// Genuine Bambu network plugin ABI (input-bearing subset), mirrored from the
// OBN abi_snapshot for v02.07.01 (SOURCE_TAG v02.07.01.57 -- matches the
// installed 02.07.01.51 plugin's minor ABI). The struct layout and the
// std::function callback types must match the genuine plugin exactly so the tap
// wrappers share its calling convention (PrintParams and the callbacks are
// passed BY VALUE => hidden-pointer in the SysV C++ ABI).
//
// If you tap a DIFFERENT plugin version whose PrintParams layout changed,
// regenerate this struct from that version's abi_snapshot before building.
#pragma once
#include <string>
#include <vector>
#include <functional>

namespace bbl_abi {

struct PrintParams {
    /* basic info */
    std::string dev_id;
    std::string task_name;
    std::string project_name;
    std::string preset_name;
    std::string filename;
    std::string config_filename;
    int         plate_index;
    std::string ftp_folder;
    std::string ftp_file;
    std::string ftp_file_md5;
    std::string nozzle_mapping;
    std::string ams_mapping;
    std::string ams_mapping2;
    std::string ams_mapping_info;
    std::string nozzles_info;
    std::string connection_type;
    std::string comments;
    int         origin_profile_id = 0;
    int         stl_design_id = 0;
    std::string origin_model_id;
    std::string print_type;
    std::string dst_file;
    std::string dev_name;

    /* access options */
    std::string dev_ip;
    bool        use_ssl_for_ftp;
    bool        use_ssl_for_mqtt;
    std::string username;
    std::string password;

    /* user options */
    bool        task_bed_leveling;
    bool        task_flow_cali;
    bool        task_vibration_cali;
    bool        task_layer_inspect;
    bool        task_record_timelapse;
    bool        task_timelapse_use_internal;
    bool        task_use_ams;
    std::string task_bed_type;
    std::string extra_options;
    int         auto_bed_leveling{ 0 };
    int         auto_flow_cali{ 0 };
    int         auto_offset_cali{ 0 };
    int         extruder_cali_manual_mode{ -1 };
    bool        task_ext_change_assist;
    bool        try_emmc_print;
    std::string svc_context;
};

// Callback types the print entry points carry (forwarded opaquely by the tap).
typedef std::function<void(int status, int code, std::string msg)> OnUpdateStatusFn;
typedef std::function<bool()>                                      WasCancelledFn;
typedef std::function<bool(int status, std::string job_info)>      OnWaitFn;

// Inbound message callback the plugin invokes to deliver MQTT reports UP to
// Studio. Registered via bambu_network_set_on_{message,local_message,
// user_message}_fn(void* agent, OnMessageFn fn) -> int. Signature must match the
// genuine plugin exactly (std::function passed BY VALUE) so the tap can store
// the host's real callback and hand the plugin a wrapper in its place.
typedef std::function<void(std::string dev_id, std::string msg)>   OnMessageFn;

}  // namespace bbl_abi
