#!/usr/bin/env bash
# Capture the genuine Bambu network plugin's TUTK/IOTC camera flow at the
# socket level, for import into OBN's wire-compliance harness.
#
#   tools/mitm-logging/capture_tutk.sh [--studio BIN] [--display :0]
#                                      [--out DIR] [--max BYTES] [-- <studio args>]
#
# Unlike capture.sh (which MITMs api.bambulab.com over HTTPS), this records the
# raw UDP the plugin sends: the REST redirect cannot see the camera path because
# the plugin self-resolves DNS and runs TUTK as raw UDP to the printer.
#
# What it does:
#   1. builds socklog/socklog.so (LD_PRELOAD socket tracer);
#   2. launches BambuStudio with socklog.so + abi_tap.so preloaded on $DISPLAY,
#      writing the socket log to <out>/socklog.txt;
#   3. tells you to open the printer's camera, let a few seconds of video run,
#      then quit.
#
# Then decode + import:
#   tools/mitm-logging/tutk_decode.py --socklog <out>/socklog.txt
#   tools/mitm-logging/import_tutk_flow.py <out>/socklog.txt \
#       -o <obn>/tests/wire-fixtures/linux/<ver>/lan/<model>/tutk_camera/flow.json \
#       --model <model> --version <ver>
#
# See docs/SOCKLOG_LISTENER.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

STUDIO_BIN="${BBL_STUDIO_BIN:-$REPO_ROOT/build/src/bambu-studio}"
DISPLAY_ARG="${DISPLAY:-:0}"
OUT_DIR="${BBL_TUTK_CAPTURE_DIR:-$REPO_ROOT/mitm-captures/tutk}"
MAX_BYTES="2048"
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --studio)  STUDIO_BIN="$2"; shift 2;;
    --display) DISPLAY_ARG="$2"; shift 2;;
    --out)     OUT_DIR="$2"; shift 2;;
    --max)     MAX_BYTES="$2"; shift 2;;
    --) shift; EXTRA=("$@"); break;;
    -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT_DIR"
SOCKLOG_PATH="$OUT_DIR/socklog.txt"

echo "[tutk] building socklog.so"
"$HERE/socklog/build_socklog.sh" "$HERE/socklog/socklog.so" >/dev/null

PRELOAD="$HERE/socklog/socklog.so"
if [[ -f "$HERE/abi_tap/abi_tap.so" ]]; then
  PRELOAD="$PRELOAD:$HERE/abi_tap/abi_tap.so"   # ABI-level camera-frame annotation
fi

if [[ ! -x "$STUDIO_BIN" ]]; then
  echo "[tutk] ERROR: studio binary not found/executable: $STUDIO_BIN" >&2
  echo "        build the fork or pass --studio <path>." >&2
  exit 1
fi

echo "[tutk] launching BambuStudio on $DISPLAY_ARG -> log: $SOCKLOG_PATH"
echo "[tutk] OPEN the printer's camera, let a few seconds of video run, then quit."
DISPLAY="$DISPLAY_ARG" \
  LD_PRELOAD="$PRELOAD" \
  SOCKLOG_OUT="$SOCKLOG_PATH" \
  SOCKLOG_MAX="$MAX_BYTES" \
  "$STUDIO_BIN" "${EXTRA[@]}" || true

echo "[tutk] done. socket log: $SOCKLOG_PATH"
echo "[tutk] decode:  $HERE/tutk_decode.py --socklog \"$SOCKLOG_PATH\""
echo "[tutk] import:  $HERE/import_tutk_flow.py \"$SOCKLOG_PATH\" -o <obn>/tests/wire-fixtures/.../tutk_camera/flow.json"
