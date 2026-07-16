# ABI input-tap (genuine plugin call arguments)

Captures the **input** side of the genuine Bambu network plugin — the actual
arguments BambuStudio passes into `bambu_network_*` calls (`PrintParams`, JSON
device commands, dev_id, login blob, …). The wire MITM records what the plugin
*emits*; this tap records what the host *hands it*, so the fixture `driver` block
becomes **captured ground-truth** instead of reconstructed from the wire output.

## Design — LD_PRELOAD `dlsym` interposition (tamper-safe)

BambuStudio `dlopen`s the genuine `libbambu_networking.so` and resolves each
entry point with `dlsym`. The tap (`abi_tap.so`, LD_PRELOADed into BambuStudio)
interposes **`dlsym` only**: when the host resolves a wrapped input-bearing
symbol, the tap returns a wrapper that logs the arguments and then tail-calls the
**real genuine symbol**, returning its value unchanged.

The genuine `.so` file is never modified and never ptraced, so:
- the plugin's VMProtect anti-debug (ptrace/DR-register checks) sees no debugger;
- BambuStudio's module-cert / `get_version` / `check_debug_consistent` gates
  validate the untouched genuine module and pass.

The only observable difference is that a wrapped call's return address is inside
the tap. This is the preferred path from the task brief. (A replacement-tap `.so`
that Studio loads *as* the plugin is the documented fallback — simpler but trips
Studio's module-cert check, needing `ignore_module_cert` and forwarding of the
version/debug gates. Not used here.)

## Wrapped entry points (input-bearing)

`get_version` (proof), `create_agent`, `set_config_dir`, `change_user`,
`connect_printer`, `send_message`, `send_message_to_printer`, `start_print`,
`start_local_print`, `start_local_print_with_record`, `bind`. Everything else
passes straight through untouched.

`PrintParams` and the `std::function` callbacks are passed **by value** (=>
hidden-pointer ABI); the wrappers share the exact struct/callback layout from
`bambu_abi.hpp` (mirrored from the OBN abi_snapshot for the plugin's version).
**Version-match `bambu_abi.hpp` to the plugin ABI** before tapping a different
version whose `PrintParams` changed.

## Secrets

Args can carry tokens / passwords / access codes. The tap **redacts** them in the
log (`accessToken`/`refreshToken`/`token`/`password`/`access_code`/`secret`/
`uid`/… → `<redacted>`, `password` field of `PrintParams` → `<redacted>`).
`import_flow.py` anonymizes again on export. The raw `abi_tap.jsonl` lives in the
gitignored session dir and is never committed.

## Use

```
tools/mitm-logging/abi_tap/build_tap.sh                 # -> abi_tap.so
ABI_TAP_LOG=./mitm-captures/abi_tap.jsonl \
  LD_PRELOAD=tools/mitm-logging/abi_tap/abi_tap.so /path/to/bambu-studio
# drive the flow; then merge the abi log with the wire logs:
python3 tools/mitm-logging/import_flow.py http_all.jsonl ftps.jsonl abi_tap.jsonl \
    --flow hybrid_print --channel cloud_lan --model h2s --dev <serial> -o flow.json
# meta.driver_source == "abi-captured" when a tapped input was used.
```

Combine with `capture.sh` by adding `abi_tap.so` to `LD_PRELOAD` alongside the
transport redirect shim.

## Smoke test (no GUI / no login)

```
tools/mitm-logging/abi_tap/run_smoke.sh
```
Part A loads a stub plugin through the tap, calls `get_version`,
`send_message_to_printer`, and `start_local_print_with_record` with crafted args,
and asserts the tap logged the exact args, the stub received them byte-for-byte,
and return values passed through. Part B loads the real VMProtect'd plugin (if
present at `~/.cache/bambu_extract_d/plugins/02.07.01.51/libbambu_networking.so`)
and calls `get_version` through the tap to prove interposition works against the
actual module.
