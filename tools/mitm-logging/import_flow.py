#!/usr/bin/env python3
"""Import a BambuStudioDebug MITM wire log into an anonymized obn-wire-flow/v1
fixture for the open-bamboo-networking (OBN) wire-compliance harness.

The input is the NDJSON produced by capture.sh / wire_addon.py -- one line per
api.bambulab.com request the GENUINE plugin emitted:

    {"method","path","query","headers":[[name,value],...],"blen","body","status"}

The output is a `flow.json` in the schema documented in the OBN repo's
tests/wire-fixtures/FORMAT.md: meta, the ordered X-BBL identity_block, vars, and
ordered steps (header-presence flags + body_json + captures). Drop the result
into the OBN `tests/wire-fixtures/<os>/<ver>/<channel>/<model>/<flow>/flow.json`
tree and `ctest` it to see where OBN diverges from genuine.

Everything is ANONYMIZED on export: IPs->192.168.1.2, access codes->1234abcd,
serials keep the model-family prefix then zeros, cloud uid->1234567890,
email->bob@test.com, bearer tokens/device-id become <dynamic:*> markers. No real
secret is ever written.

Usage:
  import_flow.py LOG.jsonl --flow login [--model account] [--channel cloud]
                 [--os linux] [-o OUT/flow.json]

  # generic best-effort for a flow without a named recognizer:
  import_flow.py LOG.jsonl --flow my_flow --match /v1/iot-service --model h2s
"""
import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl

# ---------------------------------------------------------------------------
# identity block
# ---------------------------------------------------------------------------

def is_identity_header(name):
    n = name.lower()
    return (n in ("host", "user-agent", "accept", "authorization", "content-type")
            or n.startswith("x-bbl-"))

# headers that are transport/auto and never part of the identity contract
DROP_HEADERS = {"content-length", "connection", "accept-encoding", "expect"}

DYNAMIC_VALUE = {
    "x-bbl-device-id": "<dynamic:install-uuid>",
    "x-bbl-client-id": "<dynamic:slicer:{user_id}:{hex4}>",
}


def header_dict(rec):
    return {k: v for k, v in rec["headers"]}


def has_header(rec, name):
    name = name.lower()
    return any(k.lower() == name for k, v in rec["headers"])


def get_header(rec, name):
    name = name.lower()
    for k, v in rec["headers"]:
        if k.lower() == name:
            return v
    return None


def is_client_id_header(name):
    n = name.lower()
    return n in ("client-id", "x-bbl-client-id", "x-client-id")


# ---------------------------------------------------------------------------
# anonymization
# ---------------------------------------------------------------------------

# Real dotted-quad IPs only: octets 0-255 with no leading zeros, so version
# strings like 02.07.00.50 (leading-zero octets) are not mistaken for IPs.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IP_RE = re.compile(r"\b" + _OCTET + r"(?:\." + _OCTET + r"){3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BEARER_RE = re.compile(r"Bearer\s+\S+", re.I)
# Bambu serials: model-family digits then a long alnum tail (e.g. 094...).
SERIAL_RE = re.compile(r"\b0[0-9A-Fa-f]{2}[0-9A-Za-z]{9,}\b")
UID_KEYS = {"uid", "uidstr", "user_id", "userid"}


def anon_str(s):
    if not isinstance(s, str):
        return s
    if BEARER_RE.fullmatch(s.strip()) or s.strip() in ("Bearer <tok>", "<tok>"):
        return "Bearer <dynamic:access_token>"
    s = BEARER_RE.sub("Bearer <dynamic:access_token>", s)
    s = EMAIL_RE.sub("bob@test.com", s)
    s = IP_RE.sub("192.168.1.2", s)
    s = SERIAL_RE.sub(lambda m: m.group(0)[:3] + "0" * (len(m.group(0)) - 3), s)
    # 8-hex LAN access code appearing standalone
    if re.fullmatch(r"[0-9a-fA-F]{8}", s):
        s = "1234abcd"
    return s


def anon(obj):
    if isinstance(obj, str):
        return anon_str(obj)
    if isinstance(obj, list):
        return [anon(x) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in UID_KEYS and isinstance(v, (str, int)):
                out[k] = "1234567890"
            else:
                out[k] = anon(v)
        return out
    return obj


# ---------------------------------------------------------------------------
# step building
# ---------------------------------------------------------------------------

def query_obj(rec, path_template):
    q = rec.get("query", "") or ""
    parts = urlsplit(q if q.startswith("/") else "/" + q)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    return {k: anon_str(v) for k, v in pairs}


def build_step(rec, seq, step_id, path_template, body_template=None,
               captures=None, host="api.bambulab.com"):
    flags = {
        "block": has_header(rec, "x-bbl-device-id"),
        "client_id": any(is_client_id_header(k) for k, _ in rec["headers"]),
        "content_type": has_header(rec, "content-type"),
        "authorization": has_header(rec, "authorization"),
    }
    extra = {}
    for k, v in rec["headers"]:
        kl = k.lower()
        if is_identity_header(k) or is_client_id_header(k) or kl in DROP_HEADERS:
            continue
        extra[k] = anon_str(v)
    if extra:
        flags["extra"] = extra

    req = {
        "method": rec["method"],
        "host": host,
        "path": path_template,
        "query": query_obj(rec, path_template),
        "headers": flags,
    }
    # body
    if body_template is not None:
        req["body_json"] = body_template
    elif rec.get("blen", 0) and rec.get("body"):
        try:
            req["body_json"] = anon(json.loads(rec["body"]))
        except (ValueError, TypeError):
            req["body_raw"] = anon_str(rec["body"])

    step = {"seq": seq, "id": step_id, "protocol": "http", "request": req,
            "expect": {"status": rec.get("status", 200) or 200}}
    if captures:
        step["captures"] = captures
    return step


def build_identity_block(recs):
    """Pick the most complete record and use its header order/values."""
    best = None
    best_score = -1
    for r in recs:
        idh = [k for k, _ in r["headers"] if is_identity_header(k)
               and k.lower() not in DROP_HEADERS]
        score = len(idh) + (2 if has_header(r, "authorization") else 0)
        if score > best_score:
            best_score, best = score, r
    order, values = [], {}
    for k, v in best["headers"]:
        if not is_identity_header(k) or k.lower() in DROP_HEADERS:
            continue
        if k in values:
            continue
        order.append(k)
        dv = DYNAMIC_VALUE.get(k.lower())
        if dv:
            values[k] = dv
        elif k.lower() == "authorization":
            values[k] = "<dynamic:Bearer access_token>"
        else:
            values[k] = anon_str(v)
    return {"order": order, "values": values}


# ---------------------------------------------------------------------------
# flow recognizers
# ---------------------------------------------------------------------------

TICKET_RE = re.compile(r"^/v1/user-service/user/ticket/([A-Za-z0-9]+)$")


def recognize_login(recs, args=None):
    """POST /v1/user-service/user/ticket/{ticket} then GET my/profile."""
    recs = [r for r in recs if r.get("_proto") == "http"]
    steps, i = [], None
    for idx, r in enumerate(recs):
        if r["method"] == "POST" and TICKET_RE.match(r["path"]):
            i = idx
            break
    if i is None:
        raise SystemExit("login: no POST /v1/user-service/user/ticket/<t> in log")
    steps.append(build_step(
        recs[i], 1, "exchange_ticket",
        "/v1/user-service/user/ticket/{{login_ticket}}",
        body_template={"ticket": "{{login_ticket}}"},
        captures={"access_token": "$.accessToken",
                  "refresh_token": "$.refreshToken",
                  "expires_in": "$.expiresIn",
                  "refresh_expires_in": "$.refreshExpiresIn"}))
    prof = next((r for r in recs[i + 1:]
                 if r["method"] == "GET" and r["path"] == "/v1/user-service/my/profile"),
                None)
    if prof is None:
        raise SystemExit("login: no GET /v1/user-service/my/profile after ticket")
    steps.append(build_step(
        prof, 2, "get_profile", "/v1/user-service/my/profile",
        captures={"user_id": "$.uidStr"}))

    vars_ = {
        "login_ticket": {"kind": "generated", "example": "AJR7H7"},
        "access_token": {"kind": "from_response", "step": "exchange_ticket",
                         "json": "$.accessToken", "example": "<opaque, ~144 chars>"},
        "refresh_token": {"kind": "from_response", "step": "exchange_ticket",
                          "json": "$.refreshToken", "example": "<opaque, ~144 chars>"},
        "expires_in": {"kind": "from_response", "step": "exchange_ticket",
                       "json": "$.expiresIn", "example": 31536000},
        "user_id": {"kind": "from_response", "step": "get_profile",
                    "json": "$.uidStr", "example": "1234567890"},
    }
    return steps, vars_, {"printer_model": "account", "channel": "cloud"}


def find_rec(recs, method, path_pred, after=0):
    for i in range(after, len(recs)):
        r = recs[i]
        if r["method"] == method and path_pred(r["path"]):
            return i, r
    return -1, None


def flags_from(rec):
    """Header-presence flags for a step, read from the actual record."""
    return {
        "block": has_header(rec, "x-bbl-device-id"),
        "client_id": has_header(rec, "x-bbl-client-id"),
        "content_type": has_header(rec, "content-type"),
        "authorization": has_header(rec, "authorization"),
    }


def recognize_filament_manager(recs, args=None):
    """GET filament/config, GET my/filament/v2 (offset/limit), PUT my/filament/v2."""
    recs = [r for r in recs if r.get("_proto") == "http"]
    _, cfg = find_rec(recs, "GET", lambda p: p.endswith("/design-user-service/filament/config"))
    _, lst = find_rec(recs, "GET", lambda p: p.endswith("/design-user-service/my/filament/v2"))
    _, put = find_rec(recs, "PUT", lambda p: p.endswith("/design-user-service/my/filament/v2"))
    if not (cfg and lst and put):
        raise SystemExit("filament_manager: missing config/list/put filament records")
    steps = [
        {"seq": 1, "id": "get_filament_config", "protocol": "http",
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/design-user-service/filament/config",
                     "headers": flags_from(cfg)},
         "expect": {"status": 200}},
        {"seq": 2, "id": "list_filaments", "protocol": "http",
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/design-user-service/my/filament/v2",
                     "query": {"offset": "{{page_offset}}", "limit": "{{page_limit}}"},
                     "headers": flags_from(lst)},
         "expect": {"status": 200}, "captures": {"filament_ids": "$.filaments[*].id"}},
        {"seq": 3, "id": "edit_filament", "protocol": "http",
         "request": {"method": "PUT", "host": "api.bambulab.com",
                     "path": "/v1/design-user-service/my/filament/v2",
                     "headers": flags_from(put),
                     "body_json": {"color": "{{color}}", "colors": ["{{color}}"],
                                   "filamentName": "{{filament_name}}",
                                   "id": "{{filament_id}}", "note": "{{note}}"}},
         "expect": {"status": 200}},
    ]
    vars_ = {
        "filament_id": {"kind": "from_response", "step": "list_filaments",
                        "json": "$.filaments[*].id", "example": 1000001},
        "filament_name": {"kind": "input", "example": "PETG Basic"},
        "color": {"kind": "input", "example": "#001489"},
        "note": {"kind": "input", "example": "obncap"},
        "page_offset": {"kind": "input", "example": 0},
        "page_limit": {"kind": "input", "example": 20},
    }
    return steps, vars_, {"printer_model": "account", "channel": "cloud"}


def recognize_preset_sync(recs, args=None):
    """GET slicer/setting?version=&public=false, then GET slicer/setting/{id}."""
    recs = [r for r in recs if r.get("_proto") == "http"]
    _, lst = find_rec(recs, "GET", lambda p: p.endswith("/iot-service/api/slicer/setting"))
    _, one = find_rec(recs, "GET", lambda p: "/iot-service/api/slicer/setting/" in p)
    if not lst:
        raise SystemExit("preset_sync: no GET /iot-service/api/slicer/setting")
    steps = [
        {"seq": 1, "id": "list_settings", "protocol": "http",
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/slicer/setting",
                     "query": {"version": "{{bundle_version}}", "public": "false"},
                     "headers": flags_from(lst)},
         "expect": {"status": 200}, "captures": {"setting_ids": "$..setting_id"}},
    ]
    if one:
        steps.append(
            {"seq": 2, "id": "get_setting", "protocol": "http", "repeatable": True,
             "request": {"method": "GET", "host": "api.bambulab.com",
                         "path": "/v1/iot-service/api/slicer/setting/{{setting_id}}",
                         "headers": flags_from(one)},
             "expect": {"status": 200}})
    vars_ = {
        "bundle_version": {"kind": "input", "example": "2.7.0.2"},
        "setting_id": {"kind": "from_response", "step": "list_settings",
                       "json": "$..setting_id", "example": "PPUS00000000000004"},
    }
    return steps, vars_, {"printer_model": "account", "channel": "cloud"}


def recognize_preset_write(recs, args=None):
    """POST slicer/setting (create), PATCH slicer/setting/{id} (update),
    DELETE slicer/setting/{id}."""
    recs = [r for r in recs if r.get("_proto") == "http"]
    _, cre = find_rec(recs, "POST", lambda p: p.endswith("/iot-service/api/slicer/setting"))
    _, upd = find_rec(recs, "PATCH", lambda p: "/iot-service/api/slicer/setting/" in p)
    _, dele = find_rec(recs, "DELETE", lambda p: "/iot-service/api/slicer/setting/" in p)
    if not cre:
        raise SystemExit("preset_write: no POST /iot-service/api/slicer/setting")
    create_body = {
        "base_id": "{{base_id}}", "name": "{{preset_name}}", "public": False,
        "setting": {"inherits": "{{inherits}}",
                    "initial_layer_print_height": "0.24",
                    "print_extruder_id": "1,1,2,2,2",
                    "print_extruder_variant": "<diffed values>",
                    "print_settings_id": "{{preset_name}}", "updated_time": "0"},
        "type": "{{preset_type}}", "version": "{{bundle_version}}"}
    steps = [
        {"seq": 1, "id": "create", "protocol": "http",
         "request": {"method": "POST", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/slicer/setting",
                     "headers": flags_from(cre), "body_json": create_body},
         "expect": {"status": 200}, "captures": {"setting_id": "$.setting_id"}},
    ]
    if upd:
        upd_body = {
            "base_id": "{{base_id}}", "name": "{{preset_name}}",
            "setting": {"inherits": "{{inherits}}",
                        "initial_layer_print_height": "0.28",
                        "print_extruder_id": "1,1,2,2,2",
                        "print_extruder_variant": "<diffed values>",
                        "print_settings_id": "{{preset_name}}",
                        "updated_time": "{{updated_time}}"},
            "version": "{{bundle_version}}"}
        steps.append(
            {"seq": 2, "id": "update", "protocol": "http",
             "request": {"method": "PATCH", "host": "api.bambulab.com",
                         "path": "/v1/iot-service/api/slicer/setting/{{setting_id}}",
                         "headers": flags_from(upd), "body_json": upd_body},
             "expect": {"status": 200}})
    if dele:
        steps.append(
            {"seq": 3, "id": "delete", "protocol": "http",
             "request": {"method": "DELETE", "host": "api.bambulab.com",
                         "path": "/v1/iot-service/api/slicer/setting/{{setting_id}}",
                         "headers": flags_from(dele)},
             "expect": {"status": 200}})
    vars_ = {
        "bundle_version": {"kind": "input", "example": "2.7.0.2"},
        "base_id": {"kind": "input", "example": "GP124"},
        "inherits": {"kind": "input", "example": "0.20mm Standard @BBL H2D"},
        "preset_name": {"kind": "input", "example": "obn_write_test"},
        "preset_type": {"kind": "input", "example": "print"},
        "updated_time": {"kind": "generated", "example": "1784033404"},
        "setting_id": {"kind": "from_response", "step": "create",
                       "json": "$.setting_id", "example": "PPUS00000000000010"},
    }
    return steps, vars_, {"printer_model": "account", "channel": "cloud"}


def _rep_flags(recs, method, sub):
    """Header flags from a representative record for method+path-substring."""
    _, r = find_rec(recs, method, lambda p: sub in p)
    return flags_from(r) if r else {"block": True, "client_id": True,
                                    "content_type": True, "authorization": True}


def reconstruct_task_driver(body, md5, asset_base):
    """Invert build_task_body: a create_task body -> the PrintParams driver
    block the harness feeds test_build_task_body (see cloud_print.cpp)."""
    def dumps(v):
        return json.dumps(v, separators=(",", ":")) if v not in (None, [], "") else ""
    ams2 = [{"ams_id": e.get("amsId", 255), "slot_id": e.get("slotId", 0)}
            for e in body.get("amsMapping2", [])]
    return {
        "project_name": body.get("title", ""),
        "dev_id": serial_anon(body.get("deviceId", "090000000000000")),
        "plate_index": body.get("plateIndex", 1),
        "task_bed_type": body.get("bedType", "auto"),
        "task_use_ams": body.get("useAms", False),
        "task_record_timelapse": body.get("timelapse", False),
        "task_layer_inspect": body.get("layerInspect", False),
        "task_bed_leveling": body.get("bedLeveling", False),
        "task_flow_cali": body.get("flowCali", False),
        "task_vibration_cali": body.get("vibrationCali", False),
        "auto_bed_leveling": body.get("autoBedLeveling", 2),
        "auto_flow_cali": body.get("extrudeCaliFlag", 2),
        "auto_offset_cali": body.get("nozzleOffsetCali", 2),
        "extruder_cali_manual_mode": body.get("extrudeCaliManualMode", 0),
        "ftp_file_md5": md5 or "",
        "ams_mapping": dumps(body.get("amsMapping", [])),
        "ams_mapping2": dumps(ams2),
        "ams_mapping_info": dumps(body.get("amsDetailMapping", [])),
        "nozzles_info": dumps(body.get("nozzleInfos", [])),
        "asset": "assets/%s.gcode.3mf" % asset_base,
        "config_asset": "assets/%s_config.3mf" % asset_base,
    }


def _task_step_body(body):
    """create_task step body_json: the captured body with only the serial
    anonymized and the per-run fields templated (colors/filament ids are not
    secrets and must stay literal so test_build_task_body matches)."""
    b = json.loads(json.dumps(body))   # deep copy
    b["deviceId"] = serial_anon(body.get("deviceId", "090000000000000"))
    b["modelId"] = "{{model_id}}"
    b["profileId"] = "{{profile_id}}"
    b["sequence_id"] = "{{seq}}"
    if "oriProfileId" in b:
        b["oriProfileId"] = 0
    return b


def _cloud_print_steps(recs, task_rec, patch_md5, lan):
    """Canonical start_print HTTP pipeline. channel_only steps are emitted for
    both channels; the harness applies them only when meta.channel matches."""
    tf = flags_from(task_rec)
    proj_f = _rep_flags(recs, "POST", "/iot-service/api/user/project")
    notif_f = _rep_flags(recs, "PUT", "/iot-service/api/user/notification")
    poll_f = _rep_flags(recs, "GET", "/iot-service/api/user/notification")
    patch_f = _rep_flags(recs, "PATCH", "/iot-service/api/user/project")
    upl_f = _rep_flags(recs, "GET", "/iot-service/api/user/upload")
    body = json.loads(task_rec["body"])
    title = body.get("title", "print")
    steps = [
        {"seq": 1, "id": "create_project", "protocol": "http",
         "request": {"method": "POST", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/user/project",
                     "headers": proj_f, "body_json": {"name": title}},
         "expect": {"status": 200},
         "captures": {"project_id": "$.project_id", "profile_id": "$.profile_id",
                      "model_id": "$.model_id", "upload_url": "$.upload_url",
                      "upload_ticket": "$.upload_ticket"}},
        {"seq": 2, "id": "upload_config_3mf", "protocol": "http",
         "request": {"method": "PUT", "host": "<presigned>", "path": "{{upload_url}}",
                     "headers": {"block": False, "content_type_removed": True,
                                 "expect_removed": True},
                     "body_raw": "<config .3mf bytes>"}, "expect": {"status": 200}},
        {"seq": 3, "id": "notify_upload", "protocol": "http",
         "request": {"method": "PUT", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/user/notification", "headers": notif_f,
                     "body_json": {"upload": {"origin_file_name": "{{config_file_name}}",
                                              "ticket": "{{upload_ticket}}"}}},
         "expect": {"status": 200}},
        {"seq": 4, "id": "poll_upload", "protocol": "http", "repeatable": True,
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/user/notification",
                     "query": {"action": "upload", "ticket": "{{upload_ticket}}"},
                     "headers": poll_f}, "expect": {"status": 200}},
        {"seq": 5, "id": "patch_project_placeholder", "protocol": "http",
         "channel_only": "cloud_lan",
         "request": {"method": "PATCH", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/user/project/{{project_id}}",
                     "headers": patch_f,
                     "body_json": {"profile_id": "{{profile_id}}",
                                   "profile_print_3mf": [{"md5": "{{gcode_md5}}",
                                       "plate_idx": "{{plate_index}}",
                                       "url": "ftp://%s.gcode.3mf" % title}]}},
         "expect": {"status": 200}},
        {"seq": 6, "id": "get_my_setting", "protocol": "http", "channel_only": "cloud_lan",
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/user-service/my/setting",
                     "headers": _rep_flags(recs, "GET", "/user-service/my/setting")},
         "expect": {"status": 200}},
        {"seq": 7, "id": "get_upload_url", "protocol": "http",
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/user/upload",
                     "query": {"models": "{{model_id}}_{{profile_id}}_{{plate_index}}.3mf"},
                     "headers": upl_f}, "expect": {"status": 200},
         "captures": {"main_upload_url": "$.urls[0].url"}},
        {"seq": 8, "id": "upload_main_3mf", "protocol": "http",
         "request": {"method": "PUT", "host": "<presigned>", "path": "{{main_upload_url}}",
                     "headers": {"block": False, "content_type_removed": True,
                                 "expect_removed": True},
                     "body_raw": "<print-ready .3mf (with gcode) bytes>"},
         "expect": {"status": 200}},
        {"seq": 9, "id": "patch_project_real", "protocol": "http",
         "request": {"method": "PATCH", "host": "api.bambulab.com",
                     "path": "/v1/iot-service/api/user/project/{{project_id}}",
                     "headers": patch_f,
                     "body_json": {"profile_id": "{{profile_id}}",
                                   "profile_print_3mf": [{"md5": "{{gcode_md5}}",
                                       "plate_idx": "{{plate_index}}",
                                       "url": "{{main_upload_url}}"}]}},
         "expect": {"status": 200}},
        {"seq": 10, "id": "create_task", "protocol": "http", "body_builder": True,
         "request": {"method": "POST", "host": "api.bambulab.com",
                     "path": "/v1/user-service/my/task", "headers": tf,
                     "body_json": _task_step_body(body)},
         "expect": {"status": 200}, "captures": {"task_id": "$.id"}},
        {"seq": 11, "id": "poll_task", "protocol": "http", "repeatable": True,
         "request": {"method": "GET", "host": "api.bambulab.com",
                     "path": "/v1/user-service/my/task/{{task_id}}",
                     "headers": _rep_flags(recs, "GET", "/user-service/my/task/")},
         "expect": {"status": 200}},
        {"seq": 12, "id": "mqtt_publish_project_file", "protocol": "mqtt",
         "channel_only": "cloud_lan",
         "request": {"topic": "device/{{device_id}}/request",
                     "payload_hint": "print.project_file (lan channel)"}, "expect": {}},
    ]
    return steps


CLOUD_PRINT_VARS = {
    "job_name": {"kind": "input", "example": "box20"},
    "plate_index": {"kind": "input", "example": 1},
    "device_id": {"kind": "session", "example": "090000000000001"},
    "user_id": {"kind": "session", "example": "1234567890"},
    "project_id": {"kind": "from_response", "step": "create_project", "json": "$.project_id", "example": "899112871"},
    "profile_id": {"kind": "from_response", "step": "create_project", "json": "$.profile_id", "example": "874668027"},
    "model_id": {"kind": "from_response", "step": "create_project", "json": "$.model_id", "example": "US00000000000001"},
    "upload_url": {"kind": "from_response", "step": "create_project", "json": "$.upload_url", "example": "<presigned S3 url>"},
    "upload_ticket": {"kind": "from_response", "step": "create_project", "json": "$.upload_ticket", "example": "uploader_..."},
    "config_file_name": {"kind": "generated", "example": ".1_config.3mf"},
    "gcode_md5": {"kind": "input", "example": "C243A8A7648BDB3ECF89978D795105B7"},
    "main_upload_url": {"kind": "from_response", "step": "get_upload_url", "json": "$.urls[0].url", "example": "<presigned S3 url>"},
    "seq": {"kind": "generated", "example": "20001"},
    "task_id": {"kind": "from_response", "step": "create_task", "json": "$.id", "example": "1090332016"},
}


def _find_create_task(recs, mode, dev=None, title=None):
    for i, r in enumerate(recs):
        if r["method"] == "POST" and r["path"] == "/v1/user-service/my/task" and r.get("body"):
            try:
                b = json.loads(r["body"])
            except ValueError:
                continue
            if b.get("mode") == mode and (dev is None or b.get("deviceId") == dev) \
               and (title is None or b.get("title") == title):
                return i, r
    return -1, None


def _patch_md5(recs):
    for r in recs:
        if r["method"] == "PATCH" and "/iot-service/api/user/project" in r["path"] and r.get("body"):
            try:
                arr = json.loads(r["body"]).get("profile_print_3mf", [])
                if arr and arr[0].get("md5"):
                    return arr[0]["md5"]
            except ValueError:
                pass
    return ""


def recognize_cloud_print(recs, args=None):
    recs = [r for r in recs if r.get("_proto") == "http"]
    channel = (args.channel if args and args.channel and args.channel != "unknown"
               else "cloud")
    mode = "lan_file" if channel == "cloud_lan" else "cloud_file"
    dev = getattr(args, "dev", None) if args else None
    title = getattr(args, "print_title", None) if args else None
    _, task = _find_create_task(recs, mode, dev, title)
    if not task:
        raise SystemExit(f"cloud_print: no POST /my/task with mode={mode}"
                         + (f" dev={dev}" if dev else "")
                         + (f" title={title}" if title else ""))
    body = json.loads(task["body"])
    md5 = _patch_md5(recs)
    asset_base = body.get("title", "print").replace(" ", "_")
    lan = channel == "cloud_lan"
    steps = _cloud_print_steps(recs, task, md5, lan)
    driver = reconstruct_task_driver(body, md5, asset_base)
    if lan:
        driver["access_code"] = "1234abcd"
    model = args.model if args and args.model and args.model != "unknown" else "h2s"
    defaults = {"printer_model": model, "channel": channel,
                "flow": "start_print", "_driver": driver}
    return steps, dict(CLOUD_PRINT_VARS), defaults


NUM_SEG_RE = re.compile(r"/(\d{5,})(?=/|$)")


def recognize_generic(recs, flow, match):
    """Best-effort: turn each matching request into a step, templatizing long
    numeric path segments (task/design ids) into vars."""
    sel = [r for r in recs if (match in r["path"] if match else True)]
    if not sel:
        raise SystemExit(f"{flow}: no records matched (match={match!r})")
    # de-dupe consecutive identical (method,path,query) polls
    seen, uniq = set(), []
    for r in sel:
        key = (r["method"], r["path"], r.get("query"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    steps, vars_ = [], {}
    for seq, r in enumerate(uniq, 1):
        tpl = r["path"]
        for m in NUM_SEG_RE.finditer(r["path"]):
            name = "id_%d" % seq
            vars_[name] = {"kind": "input", "example": m.group(1)}
            tpl = tpl.replace(m.group(1), "{{%s}}" % name, 1)
        sid = re.sub(r"[^a-z0-9]+", "_", r["path"].strip("/").lower())[:40] or "step"
        steps.append(build_step(r, seq, "%s_%d" % (sid, seq), tpl))
    return steps, vars_, {}


# ---------------------------------------------------------------------------
# non-HTTP protocols: SSDP / MQTT / FTPS / CTRL
# ---------------------------------------------------------------------------

# DevModel.bambu.com internal code -> fixture printer_model
MODEL_MAP = {"N2S": "a1", "O1S": "h2s", "O1D": "h2d", "N1": "p1", "C11": "p1",
             "C12": "p1", "C13": "x1", "BL-P001": "x1"}


def serial_anon(s):
    """Keep the model-family prefix, zero the rest (no real serial leaks)."""
    if not s or len(s) < 3:
        return s
    return s[:3] + "0" * (len(s) - 3)


def parse_ssdp(packet):
    """Return (ordered [(name,value)], lower->value) preserving case/order."""
    lines = packet.split("\r\n")
    pairs = []
    for ln in lines[1:]:
        if not ln or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        pairs.append((k.strip(), v.strip()))
    low = {k.lower(): v for k, v in pairs}
    return pairs, low


def recognize_ssdp(recs, args):
    ssdp = [r for r in recs if r.get("_proto") == "ssdp"]
    if not ssdp:
        raise SystemExit("ssdp_discovery: no proto=ssdp NOTIFY records in log")
    # select the packet: by --src, else by --model (DevModel/DevName), else first
    chosen = None
    for r in ssdp:
        _, low = parse_ssdp(r["packet"])
        if args.src and r.get("src") == args.src:
            chosen = r
            break
        if args.model and args.model != "unknown":
            dm = MODEL_MAP.get(low.get("devmodel.bambu.com", ""), "")
            if dm == args.model.lower():
                chosen = r
                break
    if chosen is None:
        chosen = ssdp[0]

    packet = chosen["packet"]
    _, low = parse_ssdp(packet)
    # anonymize IN THE RAW PACKET so header set/order/case is preserved exactly
    loc = low.get("location", "")
    usn = low.get("usn", "")
    apacket = packet
    if loc:
        apacket = apacket.replace(loc, "192.168.1.2")
    if usn:
        apacket = apacket.replace(usn, serial_anon(usn))
    _, alow = parse_ssdp(apacket)

    # obn::ssdp::to_device_info_json mapping (dev_signal is always "")
    expect = {
        "dev_name": alow.get("devname.bambu.com", ""),
        "dev_id": alow.get("usn", ""),
        "dev_ip": alow.get("location", ""),
        "dev_type": alow.get("devmodel.bambu.com", ""),
        "dev_signal": "",
        "connect_type": alow.get("devconnect.bambu.com", ""),
        "bind_state": alow.get("devbind.bambu.com", ""),
        "sec_link": alow.get("devseclink.bambu.com", ""),
        "ssdp_version": alow.get("devversion.bambu.com", ""),
        "connection_name": alow.get("devinf.bambu.com", ""),
    }
    model = args.model if args.model and args.model != "unknown" else \
        MODEL_MAP.get(low.get("devmodel.bambu.com", ""), "unknown")
    host_line = apacket.split("\r\n", 2)[1] if "\r\n" in apacket else ""
    host = host_line.split(":", 1)[1].strip() if ":" in host_line else "239.255.255.250:1900"
    meta = base_meta(args, flow="ssdp_discovery", channel="lan", model=model,
                     extra={"command": "ssdp_notify", "protocol": "ssdp"})
    return {
        "schema": "obn-wire-flow/v1", "meta": meta,
        "driver": {"packet": apacket, "expect": expect},
        "steps": [{
            "seq": 1, "id": "ssdp_notify", "protocol": "ssdp",
            "channel_only": "lan",
            "request": {"host": host, "transport": chosen.get("transport", "udp:2021"),
                        "op": "NOTIFY" + ("" if "nts:" in apacket.lower() else " (no NTS line)")},
            "expect": {"device_info":
                       "{dev_name,dev_id,dev_ip,dev_type,dev_signal,connect_type,"
                       "bind_state,sec_link,ssdp_version,connection_name}"},
        }],
    }


TOPIC_REQ_RE = re.compile(r"^device/([^/]+)/request$")


def recognize_device_command(recs, args):
    mq = [r for r in recs if r.get("_proto") == "mqtt"
          and r.get("event") == "publish"
          and TOPIC_REQ_RE.match(r.get("topic", ""))]
    if not mq:
        raise SystemExit("device_command: no MQTT publish to device/<serial>/request")
    rec = mq[0]
    dev = TOPIC_REQ_RE.match(rec["topic"]).group(1)
    dev_a = serial_anon(dev)
    payload = json.loads(rec["payload"])
    signed = "header" in payload and "print" in payload
    if signed:
        logical = {"print": payload["print"]}
    else:
        logical = payload
    # the command name lives one level down (system/print/pushing/... .command)
    command = ""
    for sub in payload.values():
        if isinstance(sub, dict) and isinstance(sub.get("command"), str):
            command = sub["command"]
            break
    payload_json = anon(logical)
    meta = base_meta(args, flow="device_command", channel="cloud_lan",
                     model=args.model if args.model != "unknown" else "h2d",
                     extra={"command": command})
    return {
        "schema": "obn-wire-flow/v1", "meta": meta,
        "driver": {"dev_id": dev_a, "access_code": "1234abcd",
                   "signed": signed, "command_json": json.dumps(anon(logical))},
        "steps": [{
            "seq": 1, "id": "publish", "protocol": "mqtt",
            "channel_only": "cloud_lan",
            "request": {"topic": "device/{{device_id}}/request",
                        "signed": signed, "payload_json": payload_json},
            "expect": {},
        }],
    }


LIST_LINE_RE = re.compile(
    r"^([\-d])\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$")


def parse_listing(listing, models_only=False):
    files = []
    for ln in listing.replace("\r\n", "\n").split("\n"):
        m = LIST_LINE_RE.match(ln)
        if not m:
            continue
        kind, size, name = m.group(1), int(m.group(2)), m.group(3).strip()
        if kind == "d":
            continue
        # The CTRL type=model listing returns only .3mf model files; the FTPS
        # storage listing returns every regular file (incl. media).
        if models_only and not name.lower().endswith(".3mf"):
            continue
        files.append({"name": name, "size": size})
    return files


def _ftps_driver(recs, args, models_only):
    ft = [r for r in recs if r.get("_proto") == "ftps"
          and r.get("event", "").upper() == "LIST" and r.get("listing")]
    if not ft:
        raise SystemExit("no FTPS LIST record with a listing in log")
    rec = ft[0]
    dev = serial_anon(rec.get("dev", "090000000000000"))
    files = parse_listing(rec["listing"], models_only=models_only)
    return dev, rec["listing"], files


def recognize_storage_list(recs, args):
    dev, listing, files = _ftps_driver(recs, args, models_only=False)
    meta = base_meta(args, flow="storage_list", channel="cloud_lan",
                     model=args.model if args.model != "unknown" else "h2s",
                     extra={"command": "list_info"})
    return {
        "schema": "obn-wire-flow/v1", "meta": meta,
        "driver": {"dev_id": dev, "access_code": "1234abcd",
                   "listing": listing, "expect_files": files},
        "steps": [{
            "seq": 1, "id": "ftps_list", "protocol": "ftp",
            "channel_only": "cloud_lan",
            "request": {"host": "{{device_id}}:990", "tls": "implicit-990",
                        "op": "LIST", "path": "/"},
            "expect": {"reply": "226 Directory send OK"},
        }],
    }


def recognize_ctrl_storage_list(recs, args):
    dev, listing, files = _ftps_driver(recs, args, models_only=True)
    meta = base_meta(args, flow="ctrl_storage_list", channel="cloud_lan",
                     model=args.model if args.model != "unknown" else "h2s",
                     extra={"command": "list_info"})
    return {
        "schema": "obn-wire-flow/v1", "meta": meta,
        "driver": {"dev_id": dev, "access_code": "1234abcd",
                   "listing": listing, "expect_files": files},
        "steps": [
            {"seq": 1, "id": "ctrl_open", "protocol": "tls",
             "channel_only": "cloud_lan",
             "request": {"host": "{{device_id}}:6000", "tls": "native-6000",
                         "op": "handshake",
                         "frames": "LOGIN(magic 0x0101013F, user+access_code) -> "
                                   "login-ack(0x0001013F); SETUP(0x0102013F, ctrl json) -> "
                                   "setup-reply(mtype 12291, result 0)"},
             "expect": {"reply": "session Ready (ctrl_mode)"}},
            {"seq": 2, "id": "ctrl_list_info", "protocol": "ftp",
             "channel_only": "cloud_lan",
             "request": {"cmdtype": 1, "sequence": 1,
                         "req": {"type": "model", "storage": ""},
                         "served_over": "FTPS LIST (force_ftps bridge)"},
             "expect": {"reply": "{cmdtype:1,sequence:1,result:0,reply:{file_lists:"
                                 "[{name,path,size,time,date}]}}"}},
        ],
    }


# ---------------------------------------------------------------------------
# composite flows: merge http + ftps + mqtt captures into one fixture
# ---------------------------------------------------------------------------

def _find_ftps_stor(recs):
    for r in recs:
        if r.get("_proto") == "ftps" and r.get("event", "").upper() == "STOR":
            return r
    return None


def _find_mqtt_project_file(recs):
    for r in recs:
        if r.get("_proto") == "mqtt" and r.get("event") == "publish" \
           and TOPIC_REQ_RE.match(r.get("topic", "")):
            try:
                pl = json.loads(r.get("payload", "{}"))
            except ValueError:
                continue
            pr = pl.get("print", {})
            if isinstance(pr, dict) and pr.get("command") == "project_file":
                return r, pr.get("url", "")
    return None, ""


def recognize_hybrid_print(recs, args):
    """cloud_lan (mode=lan_file): the full api pipeline PLUS the LAN legs.
    Merges the HTTP create-task/project sequence with the FTPS STOR (md5 of the
    sliced 3mf) and the MQTT project_file publish."""
    if args.channel in (None, "unknown"):
        args.channel = "cloud_lan"
    steps, vars_, defaults = recognize_cloud_print(recs, args)
    driver = defaults["_driver"]
    stor = _find_ftps_stor(recs)
    if stor:
        driver["ftp_file_md5"] = (stor.get("md5") or driver.get("ftp_file_md5", "")).upper()
        fname = stor.get("filename") or ""
        if fname:
            base = fname[:-len(".gcode.3mf")] if fname.endswith(".gcode.3mf") else \
                   fname.rsplit(".", 1)[0]
            driver["asset"] = "assets/%s.gcode.3mf" % base
            driver["config_asset"] = "assets/%s_config.3mf" % base
    driver.setdefault("access_code", "1234abcd")
    # populate the MQTT project_file step url from the mqtt capture if present
    _, url = _find_mqtt_project_file(recs)
    for s in steps:
        if s.get("id") == "mqtt_publish_project_file" and url:
            s["request"]["url"] = anon_str(url)
    defaults["flow"] = "start_print"
    return steps, vars_, defaults


def recognize_lan_print(recs, args):
    """pure LAN (channel=lan): FTPS STOR + MQTT project_file only, no cloud.
    NOTE: the OBN harness has no `lan` start_print driver yet -- this fixture is
    verified structurally; a harness driver is the remaining obn-repo piece."""
    stor = _find_ftps_stor(recs)
    mrec, url = _find_mqtt_project_file(recs)
    if not stor and not mrec:
        raise SystemExit("lan_print: need an FTPS STOR and/or MQTT project_file record")
    dev = serial_anon((stor or {}).get("dev") or "090000000000000")
    fname = (stor or {}).get("filename") or "print.gcode.3mf"
    base = fname[:-len(".gcode.3mf")] if fname.endswith(".gcode.3mf") else fname.rsplit(".", 1)[0]
    md5 = ((stor or {}).get("md5") or "").upper()
    model = args.model if args.model and args.model != "unknown" else "h2s"
    meta = base_meta(args, flow="start_print", channel="lan", model=model,
                     extra={"command": "start_local_print"})
    driver = {"dev_id": dev, "access_code": "1234abcd",
              "asset": "assets/%s.gcode.3mf" % base, "ftp_file_md5": md5,
              "plate_index": 1}
    steps = [
        {"seq": 1, "id": "ftps_stor", "protocol": "ftp", "channel_only": "lan",
         "request": {"host": "{{device_id}}:990", "tls": "implicit-990",
                     "op": "STOR", "path": "/%s.gcode.3mf" % base,
                     "md5": "{{ftp_file_md5}}"},
         "expect": {"reply": "226 Transfer complete"}},
        {"seq": 2, "id": "mqtt_publish_project_file", "protocol": "mqtt",
         "channel_only": "lan",
         "request": {"topic": "device/{{device_id}}/request",
                     "url": anon_str(url) if url else "ftp://%s.gcode.3mf" % base,
                     "payload_hint": "print.project_file (lan channel, cleartext ftp:// url)"},
         "expect": {}},
    ]
    return {"schema": "obn-wire-flow/v1", "meta": meta, "driver": driver,
            "steps": steps}


# ---------------------------------------------------------------------------
# meta + http fixture builder + main
# ---------------------------------------------------------------------------

def base_meta(args, flow, channel, model, extra=None):
    meta = {
        "os": args.os or "linux",
        "network_plugin_version": args.net_ver or "02.07.00.50",
        "slicer_client_version": args.client_ver or "02.07.00.55",
        "channel": args.channel if args.channel and args.channel != "unknown" else channel,
        "printer_model": model,
        "flow": flow,
        "source": "BambuStudio",
    }
    if extra:
        meta.update(extra)
    return meta


def load_log(path):
    recs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if "method" in d and "path" in d:
                d["_proto"] = "http"
            else:
                d["_proto"] = d.get("proto", "unknown")
            recs.append(d)
    return recs


def build_http_fixture(recs, args, steps, vars_, defaults):
    if args.model is None:
        args.model = defaults.get("printer_model", "unknown")
    if args.channel is None:
        args.channel = defaults.get("channel", "unknown")
    ref = next((r for r in recs if has_header(r, "x-bbl-client-version")), recs[0])
    ua = get_header(ref, "user-agent") or ""
    m = re.search(r"bambu_network_agent/(\S+)", ua)
    net_ver = m.group(1) if m else (get_header(ref, "x-bbl-agent-version") or "unknown")
    meta = {
        "os": args.os or (get_header(ref, "x-bbl-os-type") or "linux").lower(),
        "network_plugin_version": net_ver,
        "slicer_client_version": get_header(ref, "x-bbl-client-version") or "unknown",
        "channel": args.channel, "printer_model": args.model,
        "flow": defaults.get("flow", args.flow), "source": "BambuStudio",
    }
    used = []
    for s in steps:
        if s.get("protocol") != "http":
            continue
        pfx = s["request"]["path"].split("{{")[0]
        for r in recs:
            if r.get("_proto") == "http" and r["method"] == s["request"]["method"] \
               and pfx and r["path"].startswith(pfx):
                used.append(r)
    fixture = {
        "schema": "obn-wire-flow/v1", "meta": meta,
        "identity_block": build_identity_block(used or [r for r in recs if r.get("_proto") == "http"]),
        "vars": vars_, "steps": steps,
    }
    if defaults.get("_driver") is not None:
        fixture["driver"] = defaults["_driver"]
    return fixture


# driver-based recognizers return a complete fixture dict
DRIVER_RECOGNIZERS = {
    "ssdp_discovery": recognize_ssdp,
    "device_command": recognize_device_command,
    "storage_list": recognize_storage_list,
    "ctrl_storage_list": recognize_ctrl_storage_list,
}
HTTP_RECOGNIZERS = {
    "login": recognize_login,
    "filament_manager": recognize_filament_manager,
    "preset_sync": recognize_preset_sync,
    "preset_write": recognize_preset_write,
    "cloud_print": recognize_cloud_print,
    "hybrid_print": recognize_hybrid_print,   # composite (http + ftps + mqtt)
}
# lan_print returns a complete fixture dict (no HTTP identity block)
FULL_RECOGNIZERS = {"lan_print": recognize_lan_print}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="+",
                    help="one or more capture logs, or a session directory "
                         "(*.jsonl merged) for composite flows")
    ap.add_argument("--flow", required=True)
    ap.add_argument("--model", default=None, help="printer model or 'account'")
    ap.add_argument("--channel", default=None, help="cloud | cloud_lan | lan")
    ap.add_argument("--os", default=None)
    ap.add_argument("--src", default=None, help="ssdp: pick the NOTIFY from this source IP")
    ap.add_argument("--dev", default=None, help="cloud/hybrid print: pick the create_task by deviceId")
    ap.add_argument("--print-title", dest="print_title", default=None,
                    help="cloud/hybrid print: pick the create_task by title")
    ap.add_argument("--match", default=None,
                    help="generic http mode: substring a path must contain")
    ap.add_argument("--net-ver", dest="net_ver", default=None,
                    help="override meta.network_plugin_version for non-http flows")
    ap.add_argument("--client-ver", dest="client_ver", default=None,
                    help="override meta.slicer_client_version for non-http flows")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    import os
    paths = []
    for p in args.log:
        if os.path.isdir(p):
            paths += sorted(os.path.join(p, f) for f in os.listdir(p) if f.endswith(".jsonl"))
        else:
            paths.append(p)
    recs = []
    for p in paths:
        recs += load_log(p)
    if not recs:
        raise SystemExit("no records in log(s)")
    if args.model is None:
        args.model = "unknown"

    if args.flow in DRIVER_RECOGNIZERS:
        fixture = DRIVER_RECOGNIZERS[args.flow](recs, args)
        nsteps = len(fixture["steps"])
    elif args.flow in FULL_RECOGNIZERS:
        fixture = FULL_RECOGNIZERS[args.flow](recs, args)
        nsteps = len(fixture["steps"])
    else:
        http = [r for r in recs if r.get("_proto") == "http"]
        if not http:
            raise SystemExit(f"flow '{args.flow}' needs HTTP records; none in log")
        if args.flow in HTTP_RECOGNIZERS:
            steps, vars_, defaults = HTTP_RECOGNIZERS[args.flow](recs, args)
        else:
            steps, vars_, defaults = recognize_generic(http, args.flow, args.match)
        fixture = build_http_fixture(http, args, steps, vars_, defaults)
        nsteps = len(steps)

    out = json.dumps(fixture, indent=2, ensure_ascii=False)
    if args.out:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            f.write(out + "\n")
        sys.stderr.write(f"wrote {args.out} ({nsteps} step(s), flow={args.flow})\n")
    else:
        print(out)


if __name__ == "__main__":
    main()
