#!/usr/bin/env bash
# Build the ABI input-tap shim (LD_PRELOAD it into BambuStudio).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/abi_tap.so}"
g++ -shared -fPIC -O2 -std=c++17 -o "$OUT" "$HERE/abi_tap.cpp" -ldl
echo "built $OUT"
