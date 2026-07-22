#!/usr/bin/env bash
# Build the LD_PRELOAD socket tracer.
#   ./build_socklog.sh [output.so]
# Default output: socklog.so next to this script.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/socklog.so}"
gcc -shared -fPIC -O2 -Wall -o "$OUT" "$HERE/socklog.c" -ldl -lpthread
echo "[socklog] built $OUT"
