#!/usr/bin/env bash
# BambuStudioDebug capture mode: run BambuStudio with the GENUINE closed-source
# Bambu network plugin AND a transport-level MITM of api.bambulab.com, writing
# the plugin's on-wire REST traffic to an NDJSON log for import_flow.py.
#
#   tools/mitm-logging/capture.sh [--studio BIN] [--port 9000]
#                                 [--out DIR] [--log NAME] [-- <studio args>]
#
# What it does:
#   1. builds the LD_PRELOAD redirect shim (mitm_redirect.so);
#   2. starts a mitmdump reverse-proxy for https://api.bambulab.com on 127.0.0.1
#      with wire_addon.py, logging to <out>/<log> (gitignored runtime dir);
#   3. launches BambuStudio with the shim so ONLY api.bambulab.com is steered
#      through the proxy (login webview + every other host stay direct).
#
# Then: log in, reproduce your problem in the GUI, quit. Import the log with
#   tools/mitm-logging/import_flow.py <out>/<log> --flow <flow> ...
# See docs/MITM_LOGGING.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

STUDIO_BIN="${BBL_STUDIO_BIN:-$REPO_ROOT/build/src/bambu-studio}"
PORT="${WIRE_PORT:-9000}"
OUT_DIR="${BBL_MITM_CAPTURE_DIR:-$REPO_ROOT/mitm-captures}"
LOG_NAME="http_all.jsonl"
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --studio) STUDIO_BIN="$2"; shift 2;;
    --port)   PORT="$2"; shift 2;;
    --out)    OUT_DIR="$2"; shift 2;;
    --log)    LOG_NAME="$2"; shift 2;;
    --) shift; EXTRA=("$@"); break;;
    -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT_DIR"
LOG_PATH="$OUT_DIR/$LOG_NAME"

echo "[capture] building redirect shim"
"$HERE/build_redirect.sh" "$HERE/mitm_redirect.so" >/dev/null

echo "[capture] starting mitmdump reverse-proxy for api.bambulab.com on 127.0.0.1:$PORT"
# --ssl-insecure lets mitmproxy reach the real upstream regardless of its own
# trust store; the plugin leg's trust is handled by the redirect shim.
WIRE_LOG="$LOG_PATH" mitmdump \
  --mode "reverse:https://api.bambulab.com" \
  --listen-host 127.0.0.1 --listen-port "$PORT" \
  --ssl-insecure --set stream_large_bodies=10m \
  -s "$HERE/wire_addon.py" &
MITM_PID=$!
trap 'kill "$MITM_PID" 2>/dev/null || true' EXIT
sleep 2

if [[ ! -x "$STUDIO_BIN" ]]; then
  echo "[capture] ERROR: studio binary not found/executable: $STUDIO_BIN" >&2
  echo "          build the fork or pass --studio <path>." >&2
  exit 1
fi

echo "[capture] launching BambuStudio (genuine plugin) -> log: $LOG_PATH"
echo "[capture] log in, reproduce the issue, then quit BambuStudio."
LD_PRELOAD="$HERE/mitm_redirect.so" REDIRECT_443="$PORT" "$STUDIO_BIN" "${EXTRA[@]}" || true

echo "[capture] done. wire log: $LOG_PATH"
echo "[capture] next: tools/mitm-logging/import_flow.py \"$LOG_PATH\" --flow <flow> --model <model> --channel <channel> -o <out>/flow.json"
