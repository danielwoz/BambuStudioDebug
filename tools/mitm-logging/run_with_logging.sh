#!/usr/bin/env bash
# Launch a BambuStudioDebug build with MITM wire-logging enabled.
#
# Prereqs (see docs/MITM_LOGGING.md):
#   * the OSS `obn` plugin built with the wire recorder and installed as the
#     slicer's network plugin (libbambu_networking_<ver>.so);
#   * a built bambu-studio binary from this fork.
#
# This sets the capture env and launches the slicer. Captures land in a
# gitignored dir; drive the UI flow named by --flow, then export + anonymize
# with export_fixtures.py before committing anything.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FLOW="unknown"
MODEL="unknown"
CHANNEL="unknown"
CAPTURE_DIR="${BBL_MITM_CAPTURE_DIR:-$REPO_ROOT/mitm-captures}"
STUDIO_BIN="${BBL_STUDIO_BIN:-$REPO_ROOT/build/src/bambu-studio}"

usage() {
    cat <<EOF
Usage: $0 --flow <flow> [--model <h2s|h2d|a1|account>] [--channel <cloud|cloud_lan|lan>]
          [--capture-dir DIR] [--studio BIN] [-- <extra studio args>]

  --flow      UI flow being captured (start_print, login, preset_sync, ...). Required.
  --model     printer model / 'account' for user flows.
  --channel   delivery channel; may be left 'unknown' and inferred at export.
  --capture-dir  raw NDJSON output dir (default: <repo>/mitm-captures, gitignored).
  --studio    path to the bambu-studio binary (default: <repo>/build/src/bambu-studio).

Env passthrough: also sets OBN_WIRE_RECORD=1 for the obn-side recorder.
EOF
}

EXTRA=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --flow)        FLOW="$2"; shift 2;;
        --model)       MODEL="$2"; shift 2;;
        --channel)     CHANNEL="$2"; shift 2;;
        --capture-dir) CAPTURE_DIR="$2"; shift 2;;
        --studio)      STUDIO_BIN="$2"; shift 2;;
        --) shift; EXTRA=("$@"); break;;
        -h|--help) usage; exit 0;;
        *) echo "unknown arg: $1" >&2; usage; exit 2;;
    esac
done

if [[ "$FLOW" == "unknown" ]]; then
    echo "error: --flow is required" >&2; usage; exit 2
fi
if [[ ! -x "$STUDIO_BIN" ]]; then
    echo "error: studio binary not found/executable: $STUDIO_BIN" >&2
    echo "build the fork first, or pass --studio / BBL_STUDIO_BIN." >&2
    exit 2
fi

mkdir -p "$CAPTURE_DIR"

export BBL_MITM_CAPTURE_DIR="$CAPTURE_DIR"
export BBL_MITM_FLOW="$FLOW"
export BBL_MITM_MODEL="$MODEL"
export BBL_MITM_CHANNEL="$CHANNEL"
export OBN_WIRE_RECORD=1

echo "MITM capture -> $CAPTURE_DIR (flow=$FLOW model=$MODEL channel=$CHANNEL)"
echo "launching: $STUDIO_BIN ${EXTRA[*]:-}"
exec "$STUDIO_BIN" "${EXTRA[@]:-}"
