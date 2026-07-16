#!/usr/bin/env bash
# Validate the ABI tap against the REAL genuine plugin without BambuStudio:
# drive a genuine bambu_network_* call and capture it, then import to a fixture.
#
# Default command is a READ-ONLY pushall (safe). See the SAFETY note in
# probe_genuine.cpp. Keep the obn_send_command stop kill-switch handy.
#
# Usage:
#   probe_genuine.sh <dev_id> <ip> <access_code> [genuine.so] [command_json]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV="${1:?dev_id}"; IP="${2:?ip}"; CODE="${3:?access_code}"
SO="${4:-$HOME/.cache/bambu_extract_d/plugins/02.07.01.51/libbambu_networking.so}"
CMD="${5:-{\"pushing\":{\"sequence_id\":\"0\",\"command\":\"pushall\"}}}"

WORK="$(mktemp -d /tmp/abi_probe.XXXXXX)"
LOG="$WORK/abi_capture.jsonl"
g++ -shared -fPIC -O2 -std=c++17 -o "$WORK/abi_tap.so" "$HERE/abi_tap.cpp" -ldl
g++ -O2 -std=c++17 -o "$WORK/probe" "$HERE/probe_genuine.cpp" -ldl
mkdir -p "$WORK/cfg"

echo "[probe] driving GENUINE plugin ($SO) -> printer $IP; command: $CMD"
ABI_TAP_LOG="$LOG" LD_PRELOAD="$WORK/abi_tap.so" \
  timeout 45 "$WORK/probe" "$SO" "$WORK/cfg" "$DEV" "$IP" "$CODE" "$CMD" 2>&1 \
  | grep -viE 'open bamboo' || true

echo "[probe] captured ABI records:"
cat "$LOG"
echo "[probe] log at $LOG"
