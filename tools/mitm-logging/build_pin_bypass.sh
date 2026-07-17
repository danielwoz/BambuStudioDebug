#!/usr/bin/env bash
# Build the cloud-TLS interposer + the connection-origin diagnostic.
# Outputs are .so files that are NOT committed (see .gitignore); build locally.
set -euo pipefail
cd "$(dirname "$0")"
gcc -O2 -fPIC -shared -Wall -o pin_bypass.so pin_bypass.c
gcc -O2 -fPIC -shared -rdynamic -o conn_origin_trace.so conn_origin_trace.c -ldl
echo "built: pin_bypass.so conn_origin_trace.so"
