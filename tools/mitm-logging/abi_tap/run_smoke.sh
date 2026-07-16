#!/usr/bin/env bash
# Build + run the ABI-tap smoke test (no GUI / no login). Proves interposition,
# arg unpacking, and forwarding. If a genuine plugin path is given (or the known
# cache path exists) it also probes the real module's get_version through the tap.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d /tmp/abi_tap_smoke.XXXXXX)"

GENUINE="${1:-$HOME/.cache/bambu_extract_d/plugins/02.07.01.51/libbambu_networking.so}"

echo "[smoke] building tap, stub, test"
g++ -shared -fPIC -O2 -std=c++17 -o "$WORK/abi_tap.so"     "$HERE/abi_tap.cpp"     -ldl
g++ -shared -fPIC -O2 -std=c++17 -o "$WORK/stub_plugin.so" "$HERE/stub_plugin.cpp"
g++ -O2 -std=c++17 -I"$HERE" -o "$WORK/smoke_test"         "$HERE/smoke_test.cpp"  -ldl

export ABI_TAP_LOG="$WORK/abi_tap.jsonl"
export STUB_RECORD="$WORK/stub_record.txt"
: > "$ABI_TAP_LOG"; : > "$STUB_RECORD"

GEN_ARG=""
[ -f "$GENUINE" ] && GEN_ARG="$GENUINE" && echo "[smoke] genuine plugin: $GENUINE" || echo "[smoke] no genuine plugin (Part B skipped)"

echo "[smoke] running with LD_PRELOAD=abi_tap.so"
LD_PRELOAD="$WORK/abi_tap.so" "$WORK/smoke_test" "$WORK/stub_plugin.so" $GEN_ARG || true

echo
echo "=== tap log ($ABI_TAP_LOG) ==="
cat "$ABI_TAP_LOG"
echo "=== stub received (forwarding fidelity) ==="
cat "$STUB_RECORD"

echo
echo "[smoke] artifacts in $WORK"
