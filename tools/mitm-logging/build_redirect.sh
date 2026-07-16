#!/usr/bin/env bash
# Compile the LD_PRELOAD transport-redirect shim used by capture.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/mitm_redirect.so}"
cc -shared -fPIC -O2 -o "$OUT" "$HERE/mitm_redirect.c" -ldl -lssl -lcrypto
echo "built $OUT"
