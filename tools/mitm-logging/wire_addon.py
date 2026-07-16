"""mitmdump addon: record the GENUINE plugin's api.bambulab.com wire traffic.

Each request/response pair is appended as one NDJSON line to $WIRE_LOG
(default: ./http_all.jsonl). One line looks like:

    {"method","path","query","headers":[[name,value],...],"blen","body","status"}

- headers preserve on-wire order (JA4H / Cloudflare fingerprint the SET+ORDER).
- the Authorization bearer token is masked in the log so raw captures are less
  sensitive; import_flow.py anonymizes everything else on export. Raw captures
  still land in a gitignored runtime dir and must never be committed.

Load with: mitmdump -s wire_addon.py
"""
import json
import os

LOG_PATH = os.environ.get("WIRE_LOG", "http_all.jsonl")
# Only these hosts are recorded; the redirect shim already scopes the transport,
# this is a second guard so an accidentally-proxied host is never written.
HOSTS = set(filter(None, os.environ.get("WIRE_HOSTS", "api.bambulab.com").split(",")))

_fh = open(LOG_PATH, "a", buffering=1)


def _mask(name, value):
    if name.lower() == "authorization" and value.lower().startswith("bearer "):
        return "Bearer <tok>"
    return value


def response(flow):
    try:
        host = flow.request.pretty_host
        if HOSTS and host not in HOSTS:
            return
        req = flow.request
        body = req.get_text(strict=False) or ""
        rec = {
            "method": req.method,
            "path": req.path.split("?", 1)[0],
            "query": req.path,
            "headers": [[k, _mask(k, v)] for k, v in req.headers.items(multi=True)],
            "blen": len(req.raw_content or b""),
            "body": body,
            "status": flow.response.status_code if flow.response else 0,
        }
        _fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # never let logging break the proxy
        _fh.write(json.dumps({"error": str(e)}) + "\n")
