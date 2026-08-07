#!/usr/bin/env bash
# Capture the genuine Bambu network plugin's cloud HTTPS request/response
# plaintext from the plugin's own heap via the cloud_tap LD_PRELOAD shim.
# Use when the REST MITM cannot see traffic (plugin pins CA + static OpenSSL).
# Output: <out>/cloud_tap.log (gitignored).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
STUDIO_BIN="${BBL_STUDIO_BIN:-$REPO_ROOT/build/src/bambu-studio}"
OUT="${CLOUD_TAP_CAPTURE_DIR:-$REPO_ROOT/mitm-captures/cloud_tap}"
mkdir -p "$OUT"
bash "$HERE/build_cloudtap.sh" "$HERE/cloud_tap.so" >/dev/null
echo "[cloud_tap] launching studio -> $OUT/cloud_tap.log"
CLOUD_TAP_OUT="$OUT/cloud_tap.log" LD_PRELOAD="$HERE/cloud_tap.so" "$STUDIO_BIN" "$@" || true
echo "[cloud_tap] done. plaintext log: $OUT/cloud_tap.log"
