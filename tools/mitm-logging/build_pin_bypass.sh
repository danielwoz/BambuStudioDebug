#!/usr/bin/env bash
# Build the cloud-TLS interposer (BambuSource), the connection-origin diagnostic,
# the TLS fatal-alert localizer, and the runtime pin patcher.
# Outputs are .so files that are NOT committed (see .gitignore); build locally.
set -euo pipefail
cd "$(dirname "$0")"
gcc -O2 -fPIC -shared -Wall -o pin_bypass.so pin_bypass.c
gcc -O2 -fPIC -shared -rdynamic -o conn_origin_trace.so conn_origin_trace.c -ldl
gcc -O2 -fPIC -shared -rdynamic -o alert_trace.so alert_trace.c -ldl
gcc -O2 -fPIC -shared -Wall -o pin_patch.so pin_patch.c -lpthread
echo "built: pin_bypass.so conn_origin_trace.so alert_trace.so pin_patch.so"
