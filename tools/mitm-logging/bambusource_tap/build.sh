#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/libBambuSource.so}"
g++ -shared -fPIC -O2 -std=c++17 -fvisibility=hidden -o "$OUT" "$HERE/bambusource_tap.cpp" -ldl -lpthread
echo "built $OUT"
