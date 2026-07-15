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


def recognize_login(recs):
    """POST /v1/user-service/user/ticket/{ticket} then GET my/profile."""
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


RECOGNIZERS = {"login": recognize_login}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def load_log(path):
    recs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if "method" in d and "path" in d:
                recs.append(d)
    return recs


def infer_meta(recs, args):
    ref = next((r for r in recs if has_header(r, "x-bbl-client-version")), recs[0])
    ua = get_header(ref, "user-agent") or ""
    m = re.search(r"bambu_network_agent/(\S+)", ua)
    net_ver = m.group(1) if m else (get_header(ref, "x-bbl-agent-version") or "unknown")
    return {
        "os": args.os or (get_header(ref, "x-bbl-os-type") or "linux").lower(),
        "network_plugin_version": net_ver,
        "slicer_client_version": get_header(ref, "x-bbl-client-version") or "unknown",
        "channel": args.channel,
        "printer_model": args.model,
        "flow": args.flow,
        "source": "BambuStudio",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--flow", required=True)
    ap.add_argument("--model", default=None, help="printer model or 'account'")
    ap.add_argument("--channel", default=None, help="cloud | cloud_lan | lan")
    ap.add_argument("--os", default=None)
    ap.add_argument("--match", default=None,
                    help="generic mode: substring a path must contain")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    recs = load_log(args.log)
    if not recs:
        raise SystemExit("no request records in log")

    if args.flow in RECOGNIZERS:
        steps, vars_, defaults = RECOGNIZERS[args.flow](recs)
    else:
        steps, vars_, defaults = recognize_generic(recs, args.flow, args.match)

    # recognizer defaults fill unset model/channel
    if args.model is None:
        args.model = defaults.get("printer_model", "unknown")
    if args.channel is None:
        args.channel = defaults.get("channel", "unknown")

    # identity block from the records that back the emitted steps
    used = []
    for s in steps:
        for r in recs:
            if r["method"] == s["request"]["method"] and \
               s["request"]["path"].split("{{")[0] and \
               r["path"].startswith(s["request"]["path"].split("{{")[0]):
                used.append(r)
    identity = build_identity_block(used or recs)

    fixture = {
        "schema": "obn-wire-flow/v1",
        "meta": infer_meta(recs, args),
        "identity_block": identity,
        "vars": vars_,
        "steps": steps,
    }

    out = json.dumps(fixture, indent=2, ensure_ascii=False)
    if args.out:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            f.write(out + "\n")
        sys.stderr.write(f"wrote {args.out} ({len(steps)} steps)\n")
    else:
        print(out)


if __name__ == "__main__":
    main()
