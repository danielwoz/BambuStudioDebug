#!/usr/bin/env python3
"""Fold a raw MITM capture (NDJSON) into an obn-wire-flow/v1 fixture skeleton,
anonymizing all personal identifiers on the way out.

Milestone-1 scope: this produces a *review skeleton*, not a committable
fixture. A human diffs it against the hand-authored fixtures in
obn-cloud-header-order/tests/wire-fixtures before committing. It intentionally
does not auto-commit and does not attempt full identity_block / vars inference
for every flow — that is Phase 3.

Anonymization is applied to every string value:
  IP            -> 192.168.1.2
  access code   -> 1234abcd
  serial        -> model prefix kept, remainder zeroed
  uid           -> 1234567890
  email         -> bob@test.com
  bearer/tokens -> <dynamic:...> markers

Usage:
  export_fixtures.py SESSION.ndjson [--out DIR]
"""
import argparse
import json
import re
import sys
from pathlib import Path

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.I)
# Bambu serials: model-family digits then a long numeric/alnum tail.
SERIAL_RE = re.compile(r"\b0[0-9A-Fa-f]{2}[0-9A-Za-z]{9,}\b")
# 8-hex LAN access codes.
ACCESS_RE = re.compile(r"\b[0-9a-fA-F]{8}\b")


def anon_str(s: str) -> str:
    s = BEARER_RE.sub("Bearer <dynamic:access_token>", s)
    s = EMAIL_RE.sub("bob@test.com", s)
    s = IP_RE.sub("192.168.1.2", s)

    def serial_sub(m):
        v = m.group(0)
        return v[:3] + "0" * (len(v) - 3)

    s = SERIAL_RE.sub(serial_sub, s)
    # Access codes are riskier to blanket-replace (collide with short hashes);
    # only touch values that look like standalone codes.
    if ACCESS_RE.fullmatch(s):
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
            if k in ("uid", "uidStr", "user_id"):
                out[k] = "1234567890"
            else:
                out[k] = anon(v)
        return out
    return obj


def load_events(path: Path):
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def to_step(ev, seq):
    """Map one http/mqtt/ftps/ssdp/ctrl event to a steps[] skeleton entry."""
    boundary = ev.get("boundary")
    if boundary == "http":
        url = ev.get("url", "")
        m = re.match(r"https?://([^/]+)(/[^?]*)?(?:\?(.*))?$", url)
        host = m.group(1) if m else ""
        path = m.group(2) if m and m.group(2) else "/"
        query = m.group(3) if m and m.group(3) else None
        headers = [h.get("name") for h in ev.get("req_headers", [])]
        return {
            "seq": seq,
            "protocol": "http",
            "request": {
                "method": ev.get("method"),
                "host": anon_str(host),
                "path": anon_str(path),
                "query": anon_str(query) if query else None,
                "header_order_observed": headers,
            },
            "expect": {"status": ev.get("status")},
            "_review": "map headers to identity_block flags; body -> body_json",
        }
    if boundary == "mqtt":
        return {"seq": seq, "protocol": "mqtt",
                "topic": anon_str(ev.get("topic", "")),
                "dir": ev.get("dir"),
                "_review": "signed print -> assert sign_string via harness, never key"}
    if boundary == "ftps":
        return {"seq": seq, "protocol": "ftps", "op": ev.get("op"),
                "path": anon_str(ev.get("path", "")), "md5": ev.get("md5")}
    if boundary == "ssdp":
        return {"seq": seq, "protocol": "ssdp", "dir": ev.get("dir"),
                "_review": "parse raw NOTIFY into device-info json"}
    if boundary == "ctrl":
        return {"seq": seq, "protocol": "ctrl", "cmdtype": ev.get("cmdtype"),
                "dir": ev.get("dir")}
    return {"seq": seq, "protocol": boundary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session", type=Path)
    ap.add_argument("--out", type=Path, default=Path("fixture-skeletons"))
    args = ap.parse_args()

    events = load_events(args.session)
    if not events:
        print("no events in session", file=sys.stderr)
        return 1

    meta_ev = next((e for e in events if e.get("boundary") == "meta"), {})
    meta = {
        "os": meta_ev.get("os", "linux"),
        "network_plugin_version": meta_ev.get("network_plugin_version", "unknown"),
        "slicer_client_version": meta_ev.get("slicer_client_version", "unknown"),
        "channel": meta_ev.get("channel", "unknown"),
        "printer_model": meta_ev.get("printer_model", "unknown"),
        "flow": meta_ev.get("flow", "unknown"),
        "source": "BambuStudioDebug MITM capture",
    }

    steps = []
    seq = 1
    for ev in events:
        if ev.get("boundary") == "meta":
            continue
        steps.append(anon(to_step(ev, seq)))
        seq += 1

    fixture = {
        "schema": "obn-wire-flow/v1",
        "meta": meta,
        "_review": "SKELETON from MITM capture — verify identity_block/vars, "
                   "confirm anonymization, diff vs hand-authored fixtures before commit.",
        "steps": steps,
    }

    leaf = args.out / meta["os"] / meta["network_plugin_version"] / \
        meta["channel"] / meta["printer_model"] / meta["flow"]
    leaf.mkdir(parents=True, exist_ok=True)
    out = leaf / "flow.skeleton.json"
    out.write_text(json.dumps(fixture, indent=2))
    print(f"wrote {out} ({len(steps)} steps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
