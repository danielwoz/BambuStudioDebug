#!/usr/bin/env bash
# Build the LD_PRELOAD cloud_tap in-process HTTPS-plaintext capture shim.
#   ./build_cloudtap.sh [output.so]
# Default output: cloud_tap.so next to this script.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/cloud_tap.so}"
gcc -shared -fPIC -O2 -Wall -o "$OUT" "$HERE/cloud_tap.c" -ldl -lpthread
echo "[cloud_tap] built $OUT"
